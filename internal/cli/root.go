// Package cli wires every subsystem into the cloud-posture command.
package cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

// Build metadata. cmd/cloud-posture sets these from its ldflags variables via SetVersion
// (or, for older call sites, by assigning Version directly).
var (
	Version = "0.1.0-dev"
	Commit  = ""
	Date    = ""
)

// SetVersion records the release version, commit and build date for `cloud-posture version`.
func SetVersion(version, commit, date string) {
	if version != "" {
		Version = version
	}
	Commit, Date = commit, date
}

var (
	flagConfig    string
	flagDB        string
	flagQuiet     bool
	flagPython    string
	flagNoNetwork bool
	flagNoPython  bool
)

var root = &cobra.Command{
	Use:   "cloud-posture",
	Short: "Unified multi-cloud security posture manager",
	Long: `cloud-posture aggregates Prowler, ScoutSuite, Checkov, Trivy, Steampipe and its own
agentless collectors into one security graph, finds attack paths, prioritizes by context,
generates IaC fixes (and PRs), answers SQL over your cloud, and ships alerts to Slack/Jira/SIEMs.`,
	SilenceUsage: true,
	// main prints a returned error once ("error: …"); cobra's own "Error: …" line printed every
	// failure twice (r4 N5 / #10).
	SilenceErrors: true,
	// The foreign-database policy (r4 #15): only the commands that write posture — `ingest` and
	// `scan` — may upgrade a database the Python layer built, and they print a notice; every other
	// command refuses it with store.ErrForeignDB and leaves the file untouched. Subcommands must
	// not define their own PersistentPreRun (cobra would run it instead of this one).
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		writes := cmd.Parent() != nil && cmd.Parent().Parent() == nil && (cmd.Name() == "ingest" || cmd.Name() == "scan")
		store.SetForeignPolicy(store.ForeignPolicy{Allow: writes, Notice: cmd.ErrOrStderr()})
		return nil
	},
}

func init() {
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "config file (default cloud-posture.yaml)")
	root.PersistentFlags().StringVar(&flagDB, "db", "", "posture database path (default .cloud-posture/posture.db or $CLOUD_POSTURE_DB)")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress progress output")
	root.PersistentFlags().StringVar(&flagPython, "python", "", "Python interpreter for the intelligence layer (default $CLOUD_POSTURE_PYTHON, config python.executable, python3)")
	root.PersistentFlags().BoolVar(&flagNoPython, "no-python", false, "never start the optional Python layer (ask, fix --ai, html/pdf reports then say so); also config python.enabled: false")
	root.PersistentFlags().BoolVar(&flagNoNetwork, "no-network", false, "never download KEV/EPSS feeds: use the local cache or the embedded snapshot (also CLOUD_POSTURE_NO_NETWORK=1)")
	root.AddCommand(versionCmd, whoCanCmd)
	// Customer path rules (W7-ENGINE r5 #4): the same flag on the commands that build Issues or
	// list paths; config path_rules.dirs applies to every command.
	for _, c := range []*cobra.Command{scanCmd, ingestCmd, pathsCmd} {
		c.Flags().StringArrayVar(&flagRulesDirs, "rules-dir", nil, "also evaluate customer path rules from this directory (repeatable; each rule must pass `cloud-posture risk test` or it is rejected with the reason; config path_rules.dirs applies to every command)")
	}
}

// flagRulesDirs: --rules-dir on scan / ingest / paths.
var flagRulesDirs []string

var customRules struct {
	sync.Mutex
	byKey map[string][]attackpath.PathRule
}

// pathRulesFor is the path-rule set traversal evaluates: the embedded library plus the customer
// rules of config path_rules.dirs and --rules-dir, validated once per process (`risk test`
// semantics). Rejected rules are reported once, with the reason, and never used. nil (the
// library alone) when no directory is configured.
func pathRulesFor(cfg *config.Config) []attackpath.PathRule {
	dirs := append(cfg.PathRuleDirs(), flagRulesDirs...)
	if len(dirs) == 0 {
		return nil
	}
	key := strings.Join(dirs, "\x00")
	customRules.Lock()
	defer customRules.Unlock()
	if rs, ok := customRules.byKey[key]; ok {
		return rs
	}
	lib := attackpath.ProductPathRules()
	custom, rejected := attackpath.LoadCustomPathRules(dirs, lib)
	for _, r := range rejected {
		fmt.Fprintln(root.ErrOrStderr(), "warning: "+r.String())
	}
	if !flagQuiet && len(custom) > 0 {
		fmt.Fprintf(root.ErrOrStderr(), "path rules: %d customer rule(s) loaded next to the %d library rules\n", len(custom), len(lib))
	}
	rs := append(lib, custom...)
	if customRules.byKey == nil {
		customRules.byKey = map[string][]attackpath.PathRule{}
	}
	customRules.byKey[key] = rs
	return rs
}

func Execute() error { return root.Execute() }

var versionCmd = &cobra.Command{Use: "version", Short: "Print version, commit and build date", Run: func(cmd *cobra.Command, args []string) {
	fmt.Printf("cloud-posture %s\n", Version)
	fmt.Printf("  commit: %s\n  built:  %s\n  score:  %s\n", firstNonEmpty(Commit, "unknown (dev build)"), firstNonEmpty(Date, "unknown"), risk.ScoreVersion)
}}

// noNetwork reports whether outbound feed downloads are disabled (--no-network or
// CLOUD_POSTURE_NO_NETWORK=1/true/yes).
func noNetwork() bool {
	if flagNoNetwork {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CLOUD_POSTURE_NO_NETWORK"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// intelHook lets tests point the KEV/EPSS feeds at a local server.
var intelHook func(*intel.Options)

var (
	intelMu   sync.Mutex
	intelFeed *intel.Feed
	intelKey  string
)

// resetIntel drops the per-process feed cache (tests).
func resetIntel() {
	intelMu.Lock()
	intelFeed, intelKey = nil, ""
	intelMu.Unlock()
}

// intelFeedFor loads KEV/EPSS once per process: fresh cache → HTTPS → stale cache → embedded
// snapshot; with --no-network only the cache or the snapshot. The cache lives beside the DB.
func intelFeedFor(ctx context.Context) *intel.Feed {
	o := intel.Options{CacheDir: filepath.Join(filepath.Dir(firstNonEmpty(flagDB, store.DefaultPath())), "intel"), NoNetwork: noNetwork()}
	if intelHook != nil {
		intelHook(&o)
	}
	key := fmt.Sprint(o.CacheDir, "|", o.NoNetwork, "|", o.KEVURL, "|", o.EPSSURL)
	intelMu.Lock()
	defer intelMu.Unlock()
	if intelFeed != nil && intelKey == key {
		return intelFeed
	}
	f := intel.NewEnricher(o).Load(ctx)
	for _, w := range f.Warnings {
		logf("intel: %s", w)
	}
	intelFeed, intelKey = f, key
	return f
}

// riskOptions are the inputs of the one published score (docs/scoring.md): the KEV/EPSS feed
// and the config crown_jewels levels.
func riskOptions(ctx context.Context, cfg *config.Config) risk.Options {
	return risk.Options{Intel: intelFeedFor(ctx), CrownJewel: risk.JewelFromConfig(cfg)}
}

func logf(format string, args ...any) {
	if !flagQuiet {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, err
	}
	if flagDB == "" && cfg.DB != "" {
		flagDB = cfg.DB
	}
	return cfg, nil
}

func openStore() (*store.Store, error) {
	return store.Open(flagDB)
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		logf("interrupted, finishing up…")
		cancel()
	}()
	return ctx, cancel
}

// loadGraph rebuilds the in-memory graph from the store.
func loadGraph(st *store.Store) (*graph.Graph, error) {
	nodes, edges, err := st.LoadGraph()
	if err != nil {
		return nil, err
	}
	g := graph.New()
	for _, n := range nodes {
		var gn graph.Node
		if json.Unmarshal(n.Doc, &gn) == nil {
			g.AddNode(&gn)
		}
	}
	for _, e := range edges {
		var attr map[string]any
		json.Unmarshal(e.Attr, &attr)
		g.AddEdge(e.From, e.To, e.Kind, attr)
	}
	return g, nil
}

func saveGraph(st *store.Store, g *graph.Graph) error {
	var nodes []store.GraphNode
	for _, n := range g.Nodes() {
		doc, _ := json.Marshal(n)
		nodes = append(nodes, store.GraphNode{ID: n.ID, Type: n.Type, Class: n.Class, Name: n.Name, Provider: n.Provider, Account: n.Account, Region: n.Region,
			Sensitive: n.Sensitive, Criticality: n.Criticality, Owner: n.Owner, ModifiedAt: n.ModifiedAt, CVECount: n.CVECount, MonthlyCost: n.MonthlyCost, Weaknesses: n.Weaknesses, Doc: doc})
	}
	var edges []store.GraphEdge
	for _, e := range g.Edges() {
		attr, _ := json.Marshal(e.Attr)
		edges = append(edges, store.GraphEdge{From: e.From, To: e.To, Kind: e.Kind, Attr: attr})
	}
	return st.ReplaceGraph(nodes, edges)
}

// analyze runs rule chains + graph traversal and stores the merged attack paths.
func analyze(st *store.Store, g *graph.Graph, findings []model.Finding, cfg *config.Config, scanID string) ([]model.AttackPath, *attackpath.Analysis, error) {
	var extra []byte
	if cfg != nil && cfg.Scan.AttackRulesFile != "" {
		extra, _ = os.ReadFile(cfg.Scan.AttackRulesFile)
	}
	rules, err := attackpath.LoadRules(extra)
	if err != nil {
		return nil, nil, err
	}
	rulePaths := attackpath.EvaluateWith(findings, rules, evalOptionsFor(cfg, g))
	an := attackpath.Traverse(g, traversalOptionsFor(cfg, g, findings))
	merged := attackpath.Merge(an.Paths, rulePaths)
	an.Paths = merged
	relinkSecurityGroupDeadEnds(an, g)
	if err := st.ReplaceAttackPaths(scanID, merged); err != nil {
		return nil, nil, err
	}
	return merged, an, nil
}

// sgLinkEdges connect a security group to the compute it guards.
var sgLinkEdges = map[string]bool{graph.EdgeAttachedTo: true, graph.EdgeAllowsTrafficTo: true, graph.EdgeMemberOf: true, "member_of_security_group": true}

// isSecurityGroup reports a security-group / NSG / firewall node.
func isSecurityGroup(n *graph.Node) bool {
	t := strings.ToLower(n.Type)
	return strings.Contains(t, "securitygroup") || strings.Contains(t, "security_group") || strings.Contains(n.ID, ":security-group/")
}

// relinkSecurityGroupDeadEnds takes a security group off the dead-end list when an
// instance it is linked to (attached_to / allows_traffic_to / member_of) is on a complete
// path: fixing the SG closes that path. Links made by a bare id (sg-0abc123, from a
// finding's security_groups attribute) are matched to the SG node's ARN by its last
// path segment.
func relinkSecurityGroupDeadEnds(an *attackpath.Analysis, g *graph.Graph) {
	if an == nil || g == nil || len(an.DeadEnds.IDs) == 0 {
		return
	}
	on := map[string]bool{}
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			on[s.Resource] = true
		}
	}
	linked := map[string]bool{} // SG id or bare id linked to an on-path node
	for _, e := range g.Edges() {
		if !sgLinkEdges[e.Kind] {
			continue
		}
		if on[e.From] {
			linked[e.To] = true
		}
		if on[e.To] {
			linked[e.From] = true
		}
	}
	keep := an.DeadEnds.IDs[:0]
	for _, id := range an.DeadEnds.IDs {
		n, ok := g.Node(id)
		short := id[strings.LastIndex(id, "/")+1:]
		if ok && isSecurityGroup(n) && (linked[id] || linked[short]) {
			if an.ReachesCrownJewel != nil {
				an.ReachesCrownJewel[id] = true
			}
			continue
		}
		keep = append(keep, id)
	}
	an.DeadEnds.IDs = keep
	an.DeadEnds.Count = len(keep)
}

// jewelCriticality maps config crown-jewel levels to traversal target tiers.
var jewelCriticality = map[string]int{config.LevelVeryHigh: 4, config.LevelHigh: 3, config.LevelMedium: 2, config.LevelLow: 1}

// traversalOptions are the default traversal limits plus the typed config crown_jewels (the
// same rules risk.JewelFromConfig scores with). Each matching node becomes an exact-ID target
// rule: every byte of the pattern is escaped, so path.Match only matches that ID and the
// substring fallback in attackpath.Criticality cannot match any other node.
func traversalOptions(cfg *config.Config, g *graph.Graph) attackpath.TraversalOptions {
	opts := attackpath.DefaultTraversalOptions()
	opts.TrustedCIDRs = trustedCIDRs(cfg)
	// CVE gate (engine round 2): KEV / EPSS from the live enricher (cache → HTTPS → snapshot;
	// --no-network: cache or snapshot only). NodeCVEs needs the findings: traversalOptionsFor.
	opts.Intel = intelFeedFor(context.Background())
	opts.PathRules = pathRulesFor(cfg)
	jf := risk.JewelFromConfig(cfg)
	if jf == nil || g == nil {
		return opts
	}
	for _, n := range g.Nodes() {
		if level, _, ok := jf(n); ok && jewelCriticality[level] > 0 {
			opts.CrownJewels = append(opts.CrownJewels, attackpath.JewelRule{Pattern: exactPattern(n.ID), Criticality: jewelCriticality[level]})
		}
	}
	return opts
}

// trustedCIDRs is config trusted_cidrs (nil without a config): exposure whose every source
// lies inside them is "trusted", never an attack-path entry (Track B3 item 2).
func trustedCIDRs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.TrustedCIDRs
}

// evalOptions are the rule-engine options from config (trusted exposure).
func evalOptions(cfg *config.Config) attackpath.EvalOptions {
	return attackpath.EvalOptions{TrustedCIDRs: trustedCIDRs(cfg)}
}

// evalOptionsFor adds the security graph the traversal uses, so rule chains read its verdicts
// (SCP-neutralised admin identities, REACH-blocked exposure; engine round 2, S01).
func evalOptionsFor(cfg *config.Config, g *graph.Graph) attackpath.EvalOptions {
	o := evalOptions(cfg)
	o.Graph = g
	return o
}

// traversalOptionsFor is traversalOptions plus the CVE gate's per-node CVE ids from findings.
func traversalOptionsFor(cfg *config.Config, g *graph.Graph, fs []model.Finding) attackpath.TraversalOptions {
	o := traversalOptions(cfg, g)
	o.NodeCVEs = attackpath.CVEIndex(fs)
	return o
}

// storedTraversal is a traversal-options hook over the store's open findings (serve, mcp).
func storedTraversal(cfg *config.Config, st *store.Store) func(g *graph.Graph) attackpath.TraversalOptions {
	return func(g *graph.Graph) attackpath.TraversalOptions {
		fs, _ := st.Findings(store.Filter{Status: "FAIL"})
		return traversalOptionsFor(cfg, g, fs)
	}
}

func exactPattern(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte('\\')
		b.WriteByte(s[i])
	}
	return b.String()
}

// sinksFromConfig builds alert targets from the integrations section.
func sinksFromConfig(cfg *config.Config, only []string) []integrations.Target {
	var out []integrations.Target
	want := map[string]bool{}
	for _, o := range only {
		want[strings.ToLower(strings.TrimSpace(o))] = true
	}
	for name, sc := range cfg.Integrations {
		if sc == nil || (sc.Enabled != nil && !*sc.Enabled) {
			continue
		}
		if len(want) > 0 && !want[name] {
			continue
		}
		var sink integrations.Sink
		switch strings.ToLower(name) {
		case "slack":
			sink = &integrations.Slack{WebhookURL: config.Resolve(sc.URL, firstNonEmpty(sc.URLEnv, "SLACK_WEBHOOK_URL")), Channel: sc.Channel}
		case "teams":
			sink = integrations.NewTeams(config.Resolve(sc.URL, firstNonEmpty(sc.URLEnv, "TEAMS_WEBHOOK_URL")))
		case "pagerduty":
			sink = integrations.NewPagerDuty(config.Resolve(sc.Token, firstNonEmpty(sc.TokenEnv, "PAGERDUTY_ROUTING_KEY")))
		case "github", "github_issues":
			sink = &integrations.GitHubIssues{Repo: sc.Repo, Token: config.Resolve(sc.Token, firstNonEmpty(sc.TokenEnv, "GITHUB_TOKEN")), Labels: sc.Labels}
		case "jira":
			sink = integrations.NewJira(config.Resolve(sc.URL, sc.URLEnv), config.Resolve(sc.Email, firstNonEmpty(sc.EmailEnv, "JIRA_EMAIL")), config.Resolve(sc.Token, firstNonEmpty(sc.TokenEnv, "JIRA_API_TOKEN")), sc.Project, firstNonEmpty(sc.IssueType, "Bug"))
		case "datadog":
			sink = integrations.NewDatadog(config.Resolve(sc.Token, firstNonEmpty(sc.TokenEnv, "DD_API_KEY")), firstNonEmpty(sc.Site, "datadoghq.com"))
		case "sentinel":
			sink = integrations.NewSentinel(sc.WorkspaceID, config.Resolve(sc.Token, firstNonEmpty(sc.KeyEnv, sc.TokenEnv, "SENTINEL_SHARED_KEY")))
		case "siem", "splunk", "elastic", "webhook", "syslog":
			typ := sc.Type
			if typ == "" {
				typ = name
			}
			sink = &integrations.SIEM{Type: typ, URL: config.Resolve(sc.URL, sc.URLEnv), Token: config.Resolve(sc.Token, sc.TokenEnv), Index: sc.Index, Headers: sc.Headers}
		default:
			continue
		}
		rule := integrations.Rule{}
		if sc.MinSeverity != "" {
			rule.MinSeverity = model.ParseSeverity(sc.MinSeverity)
		}
		out = append(out, integrations.Target{Sink: sink, Rule: rule})
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// python returns the interpreter to use for the intelligence layer, or "" when disabled/missing.
// Interpreter: --python, $CLOUD_POSTURE_PYTHON, config python.executable, else python3 on PATH.
func python(cfg *config.Config) string {
	if pythonDisabledBy(cfg) != "" {
		return ""
	}
	exe := firstNonEmpty(flagPython, os.Getenv("CLOUD_POSTURE_PYTHON"))
	if exe == "" && cfg != nil {
		exe = cfg.Python.Executable
	}
	if exe == "" {
		exe = "python3"
	}
	if _, err := exec.LookPath(exe); err != nil {
		return ""
	}
	probe, cleanup, err := pythonCmd(context.Background(), exe, nil, "-c", "import nimbus")
	if err != nil {
		return ""
	}
	defer cleanup()
	if err := probe.Run(); err != nil { // silent: a missing Python layer is not an error
		return ""
	}
	return exe
}

// pythonDir is an explicitly trusted source checkout of the Python package: $NIMBUS_PYTHON_DIR,
// or python/ next to (or one level above) the cloud-posture executable. It is never derived
// from the working directory (inventory defect 12); "" means "use the installed nimbus".
func pythonDir() string {
	if p := os.Getenv("NIMBUS_PYTHON_DIR"); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	for _, c := range []string{filepath.Join(filepath.Dir(exe), "python"), filepath.Join(filepath.Dir(exe), "..", "python")} {
		if st, err := os.Stat(filepath.Join(c, "nimbus")); err == nil && st.IsDir() {
			return filepath.Clean(c)
		}
	}
	return ""
}

// runPython runs the interpreter from an empty private directory, so neither the working
// directory nor a cwd-relative python/ can be imported; a trusted pythonDir() is put on
// PYTHONPATH explicitly. Path arguments must already be absolute.
func runPython(ctx context.Context, exe string, env []string, args ...string) ([]byte, error) {
	cmd, cleanup, err := pythonCmd(ctx, exe, env, args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// runPythonQuiet is runPython with the interpreter's stderr discarded (probes).
func runPythonQuiet(ctx context.Context, exe string, args ...string) ([]byte, error) {
	cmd, cleanup, err := pythonCmd(ctx, exe, nil, args...)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return cmd.Output()
}

func pythonCmd(ctx context.Context, exe string, env []string, args ...string) (*exec.Cmd, func(), error) {
	neutral, err := os.MkdirTemp("", "cloud-posture-py-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(neutral) }
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = neutral
	cmd.Env = append(os.Environ(), "PYTHONSAFEPATH=1") // 3.11+: never prepend cwd/script dir
	if dir := pythonDir(); dir != "" {
		pp := dir
		if cur := os.Getenv("PYTHONPATH"); cur != "" {
			pp += string(os.PathListSeparator) + cur
		}
		cmd.Env = append(cmd.Env, "PYTHONPATH="+pp)
	}
	if !hasEnv(env, "CLOUD_POSTURE_DB") {
		if db, err := filepath.Abs(firstNonEmpty(flagDB, store.DefaultPath())); err == nil {
			cmd.Env = append(cmd.Env, "CLOUD_POSTURE_DB="+db)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	return cmd, cleanup, nil
}

func hasEnv(env []string, key string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, key+"=") {
			return true
		}
	}
	return false
}

// scanClock is the scan-id clock (tests freeze it).
var scanClock = time.Now

// newScanID is ULID-style: a sortable UTC timestamp with millisecond precision plus 64 random
// bits, so two scans started in the same second (or millisecond) never share an id (N3).
func newScanID() string {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		binary.BigEndian.PutUint64(r[:], uint64(time.Now().UnixNano()))
	}
	return scanClock().UTC().Format("20060102T150405.000Z") + "-" + hex.EncodeToString(r[:])
}

func workDir(cfg *config.Config) string {
	if cfg != nil && cfg.Scan.WorkDir != "" {
		return cfg.Scan.WorkDir
	}
	return filepath.Join(stateDir(), "runs")
}

// stateDir is the directory of the posture database: run files, cost signals and the monitor
// checkpoint live beside the database, never in the working directory when --db points
// elsewhere (r4 N8 / #14). The default database is .cloud-posture/posture.db, so the default
// state directory is unchanged.
func stateDir() string {
	return filepath.Dir(firstNonEmpty(flagDB, store.DefaultPath()))
}

// pythonDisabledBy names the setting that turns the Python layer off ("" when none): the
// --no-python flag, or python.enabled: false in the config file (advice names it, r4 #6).
func pythonDisabledBy(cfg *config.Config) string {
	if flagNoPython {
		return "--no-python"
	}
	if cfg != nil && cfg.Python.Enabled != nil && !*cfg.Python.Enabled {
		return "python.enabled: false in " + firstNonEmpty(cfg.Path(), "the config file")
	}
	return ""
}
