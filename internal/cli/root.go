// Package cli wires every subsystem into the cloud-posture command.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var Version = "0.1.0"

var (
	flagConfig string
	flagDB     string
	flagQuiet  bool
)

var root = &cobra.Command{
	Use:   "cloud-posture",
	Short: "Unified multi-cloud security posture manager",
	Long: `cloud-posture aggregates Prowler, ScoutSuite, Checkov, Trivy, Steampipe and its own
agentless collectors into one security graph, finds attack paths, prioritizes by context,
generates IaC fixes (and PRs), answers SQL over your cloud, and ships alerts to Slack/Jira/SIEMs.`,
	SilenceUsage: true,
}

func init() {
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "config file (default cloud-posture.yaml)")
	root.PersistentFlags().StringVar(&flagDB, "db", "", "posture database path (default .cloud-posture/posture.db or $CLOUD_POSTURE_DB)")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "suppress progress output")
	root.AddCommand(versionCmd)
}

func Execute() error { return root.Execute() }

var versionCmd = &cobra.Command{Use: "version", Short: "Print version", Run: func(cmd *cobra.Command, args []string) {
	fmt.Printf("cloud-posture %s\n", Version)
}}

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
	rulePaths := attackpath.Evaluate(findings, rules)
	opts := attackpath.DefaultTraversalOptions()
	opts.CrownJewels = crownJewels(cfg)
	an := attackpath.Traverse(g, opts)
	merged := attackpath.Merge(an.Paths, rulePaths)
	an.Paths = merged
	if err := st.ReplaceAttackPaths(scanID, merged); err != nil {
		return nil, nil, err
	}
	return merged, an, nil
}

func crownJewels(cfg *config.Config) []attackpath.JewelRule {
	if cfg == nil {
		return nil
	}
	// read optional scan.crown_jewels from the raw config file
	data, err := os.ReadFile(cfg.Path())
	if err != nil {
		return nil
	}
	var raw struct {
		Scan struct {
			CrownJewels []attackpath.JewelRule `yaml:"crown_jewels"`
		} `yaml:"scan"`
	}
	_ = yamlUnmarshal(data, &raw)
	return raw.Scan.CrownJewels
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
func python(cfg *config.Config) string {
	if cfg != nil && cfg.Python.Enabled != nil && !*cfg.Python.Enabled {
		return ""
	}
	exe := "python3"
	if cfg != nil && cfg.Python.Executable != "" {
		exe = cfg.Python.Executable
	}
	if _, err := exec.LookPath(exe); err != nil {
		return ""
	}
	cmd := exec.Command(exe, "-c", "import nimbus")
	cmd.Dir = pythonDir()
	if err := cmd.Run(); err != nil {
		return ""
	}
	return exe
}

// pythonDir lets the Go binary find the Python package when run from the repo checkout.
func pythonDir() string {
	if p := os.Getenv("NIMBUS_PYTHON_DIR"); p != "" {
		return p
	}
	for _, c := range []string{"python", filepath.Join("..", "python")} {
		if st, err := os.Stat(filepath.Join(c, "nimbus")); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if exe, err := os.Executable(); err == nil {
		c := filepath.Join(filepath.Dir(exe), "..", "python")
		if st, err := os.Stat(filepath.Join(c, "nimbus")); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

func runPython(ctx context.Context, exe string, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = pythonDir()
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func newScanID() string { return time.Now().UTC().Format("20060102T150405Z") }

func workDir(cfg *config.Config) string {
	if cfg != nil && cfg.Scan.WorkDir != "" {
		return cfg.Scan.WorkDir
	}
	return filepath.Join(".cloud-posture", "runs")
}
