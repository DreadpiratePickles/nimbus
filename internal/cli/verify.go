package cli

// `cloud-posture verify <issue-id>` (plan v3 RM4 / IW2, P2-VERIFY): nothing is "fixed" until a
// targeted re-collect of the Issue's resources, merged over the stored state and re-traversed,
// shows its path (path Issue) or its failing finding (finding Issue) gone — N consecutive reads
// in a row, with backoff, inside an eventual-consistency window. Bar: Orca rescan-on-close,
// Prowler partial scans, XM Cyber remediation confirmation.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/mcp"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

// Test hooks: the clock, the backoff sleep, the process exit and the targeted collector.
var (
	verifyNow   = time.Now
	verifySleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	verifyExit = os.Exit
	// verifyTargeted returns the targeted collector of a provider (core.Targeted).
	verifyTargeted = func(provider string) (core.Targeted, bool) {
		c, ok := collector.ForProvider(provider)
		if !ok {
			return nil, false
		}
		t, ok := c.(core.Targeted)
		return t, ok
	}
)

// verifyMaxReads bounds one run whatever the window (a stuck read loop is a bug, not a wait).
const verifyMaxReads = 50

var verifyFlags struct {
	fromFile string
	attempts int
	interval time.Duration
	wait     time.Duration
	account  string
	json     bool
	noTicket bool
	evidence string
	key      string
	cosign   string
}

var verifyCmd = &cobra.Command{
	Use:   "verify <issue-id>",
	Short: "Verify a fix: re-collect the Issue's resources, re-traverse, and close it as verified-fixed only when its path / finding is gone",
	Long: `verify re-reads only the resources of one Issue (the path's hops, or the finding's resource,
plus their one-hop neighbours) with the provider's targeted collector — or from a findings export
with --from-file — merges the fresh state over the stored one, re-runs the attack-path analysis and
decides:

  path Issue     verified-fixed when no path with the same Issue id (entry → target) survives
  finding Issue  verified-fixed when the targeted re-read shows the failing check PASS on the
                 resource, or the resource confirmed deleted; with --from-file the file must
                 evaluate that check on that resource (a file that omits it is "unverified")

Targeted readers (re-read the resource and its one-hop neighbours): AWS S3 buckets (Block
Public Access, policy status, ACL), EC2 instances, security groups, IAM roles and users (MFA,
access keys, groups and policies), RDS instances, Lambda functions (URL auth type, resource
policy, execution role), EKS clusters (endpoint access), Secrets Manager secrets (resource
policy), KMS keys (rotation, key policy); Azure storage accounts, network security groups,
VMs, SQL servers (firewall rules) and Key Vaults; GCP firewall rules, instances and Cloud
Storage buckets; Kubernetes Pods, Services, ServiceAccounts and ClusterRoleBindings. A denied
read is inconclusive, never a deletion. Other resource types make the read inconclusive: use
--from-file.

A fix is confirmed only by --attempts consecutive confirmations, read with backoff (--interval,
doubling, at most 8×) while the --wait window is open; a stale read resets the count, so an
eventually consistent API cannot close an Issue early. Otherwise the Issue stays open and the
reason names the surviving hop or the still-failing finding. A verified-fixed Issue that is
observed again for --attempts consecutive reads is reopened.

Exit codes: 0 verified-fixed, 2 still open (or reopened), 1 error.`,
	Example: `  cloud-posture verify 441264381acdb155ffe8ab1b9df69485
  cloud-posture verify 4412643 --attempts 3 --interval 10s --wait 2m
  cloud-posture verify 4412643 --from-file estate.findings.json --attempts 1   # offline / lab
  cloud-posture verify --evidence soc2-evidence.zip --key cosign.pub          # evidence package`,
	Args: func(cmd *cobra.Command, args []string) error {
		if verifyFlags.evidence != "" {
			return cobra.NoArgs(cmd, args)
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifyFlags.evidence != "" {
			return runVerifyEvidence(cmd)
		}
		return runVerify(cmd, args)
	},
}

func init() {
	mcp.DefaultFileVerifier = mcpVerifyFile
	compliance.OpenHistory = openEvidenceHistory
	f := verifyCmd.Flags()
	f.StringVar(&verifyFlags.fromFile, "from-file", "", "read the fresh state from a full or partial findings export (any format `ingest` reads) instead of the cloud")
	f.IntVar(&verifyFlags.attempts, "attempts", 3, "consecutive confirmations required before the Issue is verified-fixed")
	f.DurationVar(&verifyFlags.interval, "interval", 10*time.Second, "delay before the second read; doubles each read, at most 8×")
	f.DurationVar(&verifyFlags.wait, "wait", 2*time.Minute, "eventual-consistency window: keep re-reading until it closes (default 0 with --from-file)")
	f.StringVar(&verifyFlags.account, "account", "", "configured account to re-collect with (default: the only account of the Issue's provider, or the one named like the Issue's account)")
	f.BoolVar(&verifyFlags.json, "json", false, "print the outcome as JSON")
	f.BoolVar(&verifyFlags.noTicket, "no-ticket", false, "do not close the Issue's ticket on verified-fixed")
	f.StringVar(&verifyFlags.evidence, "evidence", "", "verify a compliance evidence package (report --evidence-zip) instead of an Issue: every SHA-256 in manifest.json and the cosign signature")
	f.StringVar(&verifyFlags.key, "key", "", "with --evidence: the signer's cosign public key (file or KMS URI)")
	f.StringVar(&verifyFlags.cosign, "cosign", "", "with --evidence: the cosign binary (default: cosign on PATH)")
	root.AddCommand(verifyCmd)
}

// verifyPlan is the stored state one verification runs against.
type verifyPlan struct {
	cfg     *config.Config
	issue   model.Issue
	stored  []model.Finding
	base    *graph.Graph
	targets []string // resource ids to re-read
	// pathIssueID maps a path to the stored (keyed, store/idkey.go) path Issue id.
	pathIssueID func(model.AttackPath) string
}

// freshRead is one re-read of the Issue's resources.
type freshRead struct {
	findings []model.Finding
	fragment *graph.Graph    // targeted collector fragment (nil for --from-file)
	covered  map[string]bool // resources whose stored state the read replaces
	scopes   map[string]bool // source|provider|account the read is authoritative for
	missing  map[string]bool // resources confirmed deleted
	// inconclusive: why this read cannot confirm anything (partial errors, unsupported ids).
	inconclusive string
	// exact (--from-file): only what the file re-observes replaces stored state — a stored
	// finding is gone only when the file carries the same check on the same resource (PASS),
	// never because the file omits it — and a verdict needs positive evidence (V1/C7).
	exact bool
	// checks: per CHECK|resource the file evaluated, its status (FAIL wins over PASS).
	checks map[string]model.Status
	// failOn: resources the file observes a FAIL on.
	failOn map[string]bool
}

// verifyMaxFileBytes caps a --from-file input (Verification 5 V2).
const verifyMaxFileBytes = 64 << 20

// checkVerifyFile refuses a --from-file input that is not a regular file or exceeds the cap,
// before anything reads it (/dev/zero, a FIFO, a multi-GB export).
func checkVerifyFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--from-file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("--from-file %s: not a regular file", path)
	}
	if fi.Size() > verifyMaxFileBytes {
		return fmt.Errorf("--from-file %s: %d bytes exceeds the 64 MiB cap", path, fi.Size())
	}
	return nil
}

func checkKey(canonical, resource string) string { return strings.ToUpper(canonical) + "|" + resource }

type verifyReader func(ctx context.Context) (*freshRead, error)

// verdict is the decision on one read.
type verdict struct {
	fixed        bool
	inconclusive bool
	// unobserved: the read holds no positive evidence either way (--from-file that never
	// mentions the Issue's resource / check): it never confirms, never reopens.
	unobserved bool
	reason     string
	score      float64 // best surviving path score (path Issues)
}

func runVerify(cmd *cobra.Command, args []string) error {
	ctx, cancel := signalContext()
	defer cancel()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if verifyFlags.attempts < 1 {
		return fmt.Errorf("--attempts must be ≥ 1")
	}
	if verifyFlags.interval < 0 || verifyFlags.wait < 0 {
		return fmt.Errorf("--interval and --wait must not be negative")
	}
	wait := verifyFlags.wait
	if verifyFlags.fromFile != "" && !cmd.Flags().Changed("wait") {
		wait = 0 // a file does not converge: no window unless asked for
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	is, err := findIssueByID(st, args[0])
	if err != nil {
		return err
	}
	plan, err := newVerifyPlan(cfg, st, is)
	if err != nil {
		return err
	}
	var read verifyReader
	verifiedBy := "rescan"
	if verifyFlags.fromFile != "" {
		if err := checkVerifyFile(verifyFlags.fromFile); err != nil {
			return err
		}
		read = fileReader(plan, verifyFlags.fromFile)
		verifiedBy = "file:" + filepath.Base(verifyFlags.fromFile)
	} else {
		if read, err = targetedReader(plan, verifyFlags.account); err != nil {
			return err
		}
	}
	if !verifyFlags.json {
		fmt.Printf("Verifying Issue %s (%s) %s — %d resource(s), %s; %d consecutive confirmation(s) required\n",
			is.ID, is.Kind, termSafe(issueLabel(is)), len(plan.targets), termSafe(map[bool]string{true: "from " + verifyFlags.fromFile, false: "targeted re-collect"}[verifyFlags.fromFile != ""]), verifyFlags.attempts)
	}
	out, err := verifyLoop(ctx, plan, read, verifyFlags.attempts, verifyFlags.interval, wait, func(line string) {
		if !verifyFlags.json {
			fmt.Println("  " + termSafe(line))
		}
	})
	if err != nil {
		return err
	}
	out.Verification.VerifiedBy = verifiedBy
	if err := st.RecordVerification(out.Verification); err != nil {
		return err
	}
	ticket := ""
	if !verifyFlags.noTicket {
		ticket = verifyTicket(ctx, cfg, st, is, out.Verification)
	}
	if verifyFlags.json {
		doc := map[string]any{"issue": is.ID, "kind": is.Kind, "title": issueLabel(is), "result": out.Verification.Result,
			"reads": out.Verification.Reads, "confirmations": out.Verification.Confirmations, "required": out.Verification.Required,
			"reason": out.Verification.Reason, "evidence": out.Verification.Evidence, "verified_by": verifiedBy}
		if ticket != "" {
			doc["ticket"] = ticket
		}
		if err := output.JSON(os.Stdout, doc); err != nil {
			return err
		}
	} else {
		// Reasons quote resource names, titles and API error text: cloud-controlled strings
		// (V3) are printed without escape codes or line breaks (JSON output escapes them).
		reason := termSafe(out.Verification.Reason)
		switch out.Verification.Result {
		case store.VerifyFixed:
			fmt.Printf("✓ verified-fixed: Issue %s — %s (%d/%d consecutive confirmations, verified_by=%s)\n", is.ID, reason, out.Verification.Confirmations, out.Verification.Required, verifiedBy)
		case store.VerifyReopened:
			if is.State == model.StateSuppressed {
				// A suppression is an accepted-risk decision with its own expiry: verify never
				// lifts it (store.RecordVerification), so the Issue is not reopened.
				fmt.Printf("✗ observed again: Issue %s stays suppressed (accepted risk) — %s\n", is.ID, reason)
			} else {
				fmt.Printf("✗ reopened: Issue %s — %s\n", is.ID, reason)
			}
		case store.VerifyUnverified:
			fmt.Printf("? unverified: Issue %s — %s (no change; the read holds no evidence about this Issue)\n", is.ID, reason)
		default:
			fmt.Printf("✗ still open: Issue %s — %s\n", is.ID, reason)
		}
		if ticket != "" {
			fmt.Println("  ticket: " + termSafe(ticket))
		}
	}
	if out.Verification.Result != store.VerifyFixed {
		verifyExit(2)
	}
	return nil
}

// termSafe makes a string that may carry cloud-controlled text (resource names, titles, tags,
// API errors) safe to print on a terminal: ANSI / VT escape sequences (CSI, OSC, DCS and other
// ESC forms) are removed, line and paragraph breaks (\r, \n, U+2028/2029, NEL) become a space,
// and every other C0 / C1 control character and DEL is dropped, so a resource name can neither
// recolour the terminal, set its title, nor start a forged verdict line (r4 rough edge V3).
func termSafe(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b || r == 0x9b || r == 0x9d || r == 0x90 || r == 0x9e || r == 0x9f:
			// ESC-introduced or 8-bit C1 sequences.
			kind := r
			if r == 0x1b {
				if i+1 >= len(rs) {
					continue
				}
				i++
				switch rs[i] {
				case '[':
					kind = 0x9b
				case ']':
					kind = 0x9d
				case 'P', 'X', '^', '_':
					kind = 0x90
				default:
					continue // two-character escape (ESC c, ESC 7, ...)
				}
			}
			if kind == 0x9b { // CSI: parameters then one final byte 0x40–0x7e
				for i+1 < len(rs) {
					i++
					if rs[i] >= 0x40 && rs[i] <= 0x7e {
						break
					}
				}
				continue
			}
			// OSC / DCS / SOS / PM / APC: up to BEL or ST (ESC \ or 0x9c)
			for i+1 < len(rs) {
				i++
				if rs[i] == 0x07 || rs[i] == 0x9c {
					break
				}
				if rs[i] == 0x1b && i+1 < len(rs) && rs[i+1] == '\\' {
					i++
					break
				}
			}
		case r == '\n' || r == '\r' || r == '\t' || r == 0x85 || r == 0x2028 || r == 0x2029 || r == '\v' || r == '\f':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			// other control characters: dropped
		case r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			// bidi overrides (could reorder a verdict on screen): dropped
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findIssueByID resolves an exact id or a unique prefix (≥ 6 characters).
func findIssueByID(st *store.Store, arg string) (model.Issue, error) {
	arg = st.ResolveIssueID(arg) // an id from before the keyed-id migration still resolves
	all, err := st.Issues(store.IssueFilter{})
	if err != nil {
		return model.Issue{}, err
	}
	var hits []model.Issue
	for _, is := range all {
		if is.ID == arg {
			return is, nil
		}
		if len(arg) >= 6 && strings.HasPrefix(is.ID, arg) {
			hits = append(hits, is)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return model.Issue{}, fmt.Errorf("%w: %s", store.ErrIssueNotFound, arg)
	}
	return model.Issue{}, fmt.Errorf("issue id prefix %q is ambiguous (%d matches)", arg, len(hits))
}

func issueLabel(is model.Issue) string {
	if is.Title != "" {
		if is.Kind == model.IssuePath {
			return is.Title
		}
		return is.CanonicalID + " on " + is.ResourceID
	}
	return is.CanonicalID + " on " + is.ResourceID
}

// verifyAnalysis is analyze() without persisting: rule chains plus traversal over g.
func verifyAnalysis(cfg *config.Config, g *graph.Graph, fs []model.Finding) (*attackpath.Analysis, error) {
	var extra []byte
	if cfg != nil && cfg.Scan.AttackRulesFile != "" {
		extra, _ = os.ReadFile(cfg.Scan.AttackRulesFile)
	}
	rules, err := attackpath.LoadRules(extra)
	if err != nil {
		return nil, err
	}
	rulePaths := attackpath.EvaluateWith(fs, rules, evalOptionsFor(cfg, g))
	an := attackpath.Traverse(g, traversalOptionsFor(cfg, g, fs))
	an.Paths = attackpath.Merge(an.Paths, rulePaths)
	relinkSecurityGroupDeadEnds(an, g)
	return an, nil
}

// newVerifyPlan loads the stored findings and graph and decides which resources to re-read:
// every hop of every stored path of a path Issue (else its anchor / identity entry), or the
// resource of a finding Issue.
func newVerifyPlan(cfg *config.Config, st *store.Store, is model.Issue) (*verifyPlan, error) {
	g, err := loadGraph(st)
	if err != nil {
		return nil, err
	}
	return newVerifyPlanFrom(cfg, st, g, is)
}

// verifySource is what a verification plan reads: the stored findings and the keyed path Issue
// ids. *store.Store and the MCP server's read-only Reader both provide it.
type verifySource interface {
	Findings(fl store.Filter) ([]model.Finding, error)
	PathIssueIDOf(p model.AttackPath) string
}

func newVerifyPlanFrom(cfg *config.Config, st verifySource, g *graph.Graph, is model.Issue) (*verifyPlan, error) {
	fs, err := st.Findings(store.Filter{})
	if err != nil {
		return nil, err
	}
	if g == nil {
		g = graph.New()
	}
	if g.Len() <= 1 {
		g.AttachFindings(fs)
		attackpath.AnnotateExposure(g, trustedCIDRs(cfg))
	}
	p := &verifyPlan{cfg: cfg, issue: is, stored: fs, base: g, pathIssueID: st.PathIssueIDOf}
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" && id != graph.InternetNodeID && id != model.PathEntryInternet && !seen[id] {
			seen[id] = true
			p.targets = append(p.targets, id)
		}
	}
	if is.Kind == model.IssuePath {
		an, err := verifyAnalysis(cfg, g.Clone(), fs)
		if err != nil {
			return nil, err
		}
		for _, path := range an.Paths {
			if st.PathIssueIDOf(path) != is.ID {
				continue
			}
			for _, s := range path.Steps {
				add(s.Resource)
			}
		}
		add(is.AnchorID)
		add(is.EntryID)
	} else {
		if strings.HasPrefix(is.ResourceID, "file:") || strings.HasPrefix(is.ResourceID, "account:") {
			return nil, fmt.Errorf("issue %s is on %s: verify re-reads cloud resources (re-run scan --iac for code findings)", is.ID, is.ResourceID)
		}
		add(is.ResourceID)
	}
	if len(p.targets) == 0 {
		return nil, fmt.Errorf("issue %s has no resource to re-read", is.ID)
	}
	return p, nil
}

func findingScope(f model.Finding) string {
	return f.Source + "|" + model.NormalizeProvider(f.Provider) + "|" + f.Account
}

// fileReader re-parses the export on every read (through the same adapters as `ingest`). It is
// an exact read (Verification 5 V1/C7): the file covers only the resources it mentions, and a
// stored finding is replaced only by the same check on the same resource in the file — a file
// that omits a resource or a check says nothing about it.
func fileReader(p *verifyPlan, path string) verifyReader {
	return func(ctx context.Context) (*freshRead, error) {
		if err := checkVerifyFile(path); err != nil {
			return nil, err
		}
		quiet := flagQuiet
		flagQuiet = true
		fs, runs := ingestPath(path, "", "", "verify", verifyNow().UTC())
		flagQuiet = quiet
		for _, r := range runs {
			if r.Status != "ok" {
				return nil, fmt.Errorf("--from-file %s: %s", path, r.Message)
			}
		}
		fr := &freshRead{covered: map[string]bool{}, scopes: map[string]bool{}, missing: map[string]bool{}, exact: true,
			checks: map[string]model.Status{}, failOn: map[string]bool{}}
		for _, f := range fs {
			fr.scopes[findingScope(f)] = true
			if f.Resource.ID != "" {
				fr.covered[f.Resource.ID] = true
			}
			k := checkKey(f.CanonicalID, issueResourceKey(f))
			if f.Status == model.Fail {
				fr.checks[k] = model.Fail
				fr.failOn[issueResourceKey(f)] = true
			} else if _, seen := fr.checks[k]; !seen {
				fr.checks[k] = f.Status
			}
		}
		delete(fr.covered, graph.InternetNodeID)
		for _, f := range fs {
			if fr.covered[f.Resource.ID] {
				fr.findings = append(fr.findings, f)
			}
		}
		return fr, nil
	}
}

// verifySpec picks the configured account the targeted collector re-reads with.
func verifySpec(cfg *config.Config, is model.Issue, name string) (core.AccountSpec, error) {
	toSpec := func(a *config.Account) core.AccountSpec {
		return core.AccountSpec{Name: a.Name, Provider: a.Provider, Profile: a.Profile, RoleARN: a.RoleARN, Regions: a.Regions, SubscriptionID: a.SubscriptionID,
			TenantID: a.TenantID, ProjectID: a.ProjectID, KubeContext: a.KubeContext, Org: a.Org, Domain: a.Domain, TokenEnv: a.TokenEnv, TrustedCIDRs: cfg.TrustedCIDRs}
	}
	if name != "" {
		a, ok := cfg.Accounts[name]
		if !ok || a == nil {
			return core.AccountSpec{}, fmt.Errorf("--account %q is not configured", name)
		}
		if a.Name == "" {
			a.Name = name
		}
		return toSpec(a), nil
	}
	var same []*config.Account
	names := make([]string, 0, len(cfg.Accounts))
	for n := range cfg.Accounts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := cfg.Accounts[n]
		if a == nil || model.NormalizeProvider(a.Provider) != model.NormalizeProvider(is.Provider) {
			continue
		}
		if a.Name == "" {
			a.Name = n
		}
		if n == is.Account || strings.Contains(a.RoleARN, ":"+is.Account+":") || (a.SubscriptionID != "" && strings.EqualFold(a.SubscriptionID, is.Account)) {
			return toSpec(a), nil
		}
		same = append(same, a)
	}
	switch len(same) {
	case 1:
		return toSpec(same[0]), nil
	case 0:
		return core.AccountSpec{}, fmt.Errorf("no %s account configured to re-collect Issue %s (account %s); configure one or use --from-file", is.Provider, is.ID, is.Account)
	}
	return core.AccountSpec{}, fmt.Errorf("several %s accounts are configured; pick the one holding account %s with --account", is.Provider, is.Account)
}

// targetedReader re-collects the Issue's resources with the provider's core.Targeted collector.
func targetedReader(p *verifyPlan, account string) (verifyReader, error) {
	tc, ok := verifyTargeted(p.issue.Provider)
	if !ok || tc == nil {
		return nil, fmt.Errorf("provider %q has no targeted collector yet (AWS, Azure, GCP and Kubernetes have one); use --from-file", p.issue.Provider)
	}
	spec, err := verifySpec(p.cfg, p.issue, account)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (*freshRead, error) {
		tr, err := tc.Target(ctx, spec, p.targets)
		if err != nil {
			return nil, err
		}
		fr := &freshRead{findings: tr.Findings, fragment: tr.Graph, covered: map[string]bool{}, missing: map[string]bool{},
			scopes: map[string]bool{core.Source + "|" + model.NormalizeProvider(p.issue.Provider) + "|" + p.issue.Account: true}}
		for _, id := range tr.Observed {
			fr.covered[id] = true
		}
		for _, id := range tr.Missing {
			fr.covered[id], fr.missing[id] = true, true
		}
		if tr.Graph != nil {
			for _, n := range tr.Graph.Nodes() {
				if n.ID != graph.InternetNodeID && n.Class != graph.ClassAccount {
					fr.covered[n.ID] = true
				}
			}
		}
		for _, f := range tr.Findings {
			fr.scopes[findingScope(f)] = true
			if f.Resource.ID != "" {
				fr.covered[f.Resource.ID] = true
			}
		}
		if tr.Inconclusive() {
			var why []string
			for _, e := range tr.Errors {
				why = append(why, e.Error())
			}
			if len(tr.Unsupported) > 0 {
				why = append(why, "cannot target "+strings.Join(tr.Unsupported, ", "))
			}
			fr.inconclusive = strings.Join(why, "; ")
		}
		return fr, nil
	}, nil
}

// merge applies a read over the stored state: the merged findings and the re-built graph.
func (p *verifyPlan) merge(fr *freshRead) ([]model.Finding, *graph.Graph) {
	freshIDs := map[string]bool{}
	for _, f := range fr.findings {
		freshIDs[f.ID] = true
	}
	dropped := map[string]bool{}
	var merged []model.Finding
	for _, f := range p.stored {
		_, reobserved := fr.checks[checkKey(f.CanonicalID, issueResourceKey(f))]
		if freshIDs[f.ID] || (fr.exact && reobserved) || (!fr.exact && fr.covered[f.Resource.ID] && fr.scopes[findingScope(f)]) {
			dropped[f.ID] = true
			continue
		}
		merged = append(merged, f)
	}
	merged = append(merged, fr.findings...)

	g := p.base.Clone()
	for _, e := range g.Edges() {
		fid, _ := e.Attr["finding_id"].(string)
		if (fid != "" && dropped[fid]) || (e.From == graph.InternetNodeID && fr.covered[e.To]) {
			g.RemoveEdge(e.From, e.To, e.Kind)
		}
	}
	hasFresh := map[string]bool{}
	for _, f := range fr.findings {
		if !fr.exact || len(f.Resource.Attributes) > 0 { // an exact read replaces attributes only when it carries them
			hasFresh[f.Resource.ID] = true
		}
	}
	for id := range fr.covered {
		if fr.missing[id] {
			g.RemoveNode(id)
			continue
		}
		if n, ok := g.Node(id); ok {
			n.Weaknesses, n.FindingIDs, n.CVECount = nil, nil, 0
			if hasFresh[id] {
				n.Attributes = map[string]any{}
			}
		}
	}
	if fr.fragment != nil {
		g.Merge(fr.fragment)
	}
	var attach []model.Finding
	for _, f := range merged {
		if fr.covered[f.Resource.ID] {
			attach = append(attach, f)
		}
	}
	g.AttachFindings(attach)
	attackpath.AnnotateExposure(g, trustedCIDRs(p.cfg))
	return merged, g
}

// evaluate decides one read.
func (p *verifyPlan) evaluate(fr *freshRead) (verdict, error) {
	if fr.inconclusive != "" {
		return verdict{inconclusive: true, reason: "inconclusive read: " + fr.inconclusive}, nil
	}
	if v, ok := p.unobserved(fr); ok {
		return v, nil
	}
	merged, g := p.merge(fr)
	is := p.issue
	switch is.Kind {
	case model.IssuePath:
		an, err := verifyAnalysis(p.cfg, g, merged)
		if err != nil {
			return verdict{}, err
		}
		var best *model.AttackPath
		for i := range an.Paths {
			path := &an.Paths[i]
			if len(path.Steps) == 0 || p.pathIssueID(*path) != is.ID {
				continue
			}
			if best == nil || path.Score > best.Score {
				best = path
			}
		}
		if best != nil && fr.exact && !stepsObservedFailing(fr, best) {
			return verdict{unobserved: true, reason: "the path survives only on stored state this file does not re-observe (no FAIL on any of its hops in the file)"}, nil
		}
		if best == nil {
			return verdict{fixed: true, reason: fmt.Sprintf("no surviving path from %s to %s", nodeName(g, p.base, firstNonEmpty(is.EntryID, model.PathEntryInternet)), nodeName(g, p.base, is.AnchorID))}, nil
		}
		reason := fmt.Sprintf("path survives: %s (score %s)", hopLine(g, is, *best), scoreChange(is.Score, is.Band, best.Score))
		var res []string
		for _, s := range best.Steps {
			res = append(res, s.Resource)
		}
		if ev := openIngressEvidence(g, res); len(ev) > 0 {
			reason = strings.Join(ev, "; ") + "; " + reason
		}
		return verdict{reason: reason, score: best.Score}, nil
	case model.IssueCombination:
		weak := map[string]bool{}
		var fids []string
		for _, f := range merged {
			if f.Status == model.Fail && issueResourceKey(f) == is.ResourceID {
				for _, w := range f.Weaknesses {
					weak[w] = true
				}
				fids = append(fids, f.ID)
			}
		}
		if n, ok := g.Node(is.ResourceID); ok && n.Sensitive {
			weak[model.ConditionSensitive] = true
		}
		for _, c := range model.ToxicCombinations {
			if c.ID != is.CanonicalID {
				continue
			}
			var gone []string
			for _, cond := range c.AllOf {
				if !weak[cond] {
					gone = append(gone, cond)
				}
			}
			if len(gone) > 0 {
				return verdict{fixed: true, reason: "combination broken: " + strings.Join(gone, ", ") + " no longer observed"}, nil
			}
			return verdict{reason: fmt.Sprintf("all of %s still observed on %s (findings %s)", strings.Join(c.AllOf, ", "), nodeName(g, p.base, is.ResourceID), strings.Join(fids, ", "))}, nil
		}
		return verdict{}, fmt.Errorf("unknown toxic combination %s", is.CanonicalID)
	default:
		var still []string
		for _, f := range merged {
			if f.Status != model.Fail || !strings.EqualFold(f.CanonicalID, is.CanonicalID) || issueResourceKey(f) != is.ResourceID {
				continue
			}
			line := fmt.Sprintf("finding %s %s still FAIL on %s (%s)", f.ID, f.CanonicalID, nodeName(g, p.base, is.ResourceID), f.Source)
			if !fr.covered[f.Resource.ID] || !fr.scopes[findingScope(f)] {
				line += ", not re-observed by this read"
			}
			still = append(still, line)
		}
		if len(still) == 0 {
			return verdict{fixed: true, reason: fixedReason(is.CanonicalID, nodeName(g, p.base, is.ResourceID), fr.missing[is.ResourceID])}, nil
		}
		if fr.exact && fr.checks[checkKey(is.CanonicalID, is.ResourceID)] != model.Fail {
			return verdict{unobserved: true, reason: "still FAIL only in stored findings this file does not re-observe: " + strings.Join(still, "; ")}, nil
		}
		reason := strings.Join(still, "; ")
		if ev := openIngressEvidence(g, []string{is.ResourceID}); len(ev) > 0 {
			reason += "; " + strings.Join(ev, "; ")
		}
		return verdict{reason: reason}, nil
	}
}

// unobserved is the positive-evidence gate of an exact (--from-file) read: the file must
// evaluate the Issue's own check on its resource (finding Issue), one of the combination's
// failing checks on its resource (combination), or mention a hop of the path (path Issue).
func (p *verifyPlan) unobserved(fr *freshRead) (verdict, bool) {
	if !fr.exact {
		return verdict{}, false
	}
	is := p.issue
	switch is.Kind {
	case model.IssuePath:
		for _, t := range p.targets {
			if fr.covered[t] {
				return verdict{}, false
			}
		}
		return verdict{unobserved: true, reason: fmt.Sprintf("the file mentions none of the path's %d hop resource(s)", len(p.targets))}, true
	case model.IssueCombination:
		for _, f := range p.stored {
			if f.Status == model.Fail && issueResourceKey(f) == is.ResourceID {
				if _, ok := fr.checks[checkKey(f.CanonicalID, is.ResourceID)]; ok {
					return verdict{}, false
				}
			}
		}
		return verdict{unobserved: true, reason: fmt.Sprintf("the file evaluates none of the combination's failing checks on %s", is.ResourceID)}, true
	default:
		if _, ok := fr.checks[checkKey(is.CanonicalID, is.ResourceID)]; ok {
			return verdict{}, false
		}
		if fr.covered[is.ResourceID] {
			return verdict{unobserved: true, reason: fmt.Sprintf("the file mentions %s but never evaluates %s on it", is.ResourceID, is.CanonicalID)}, true
		}
		return verdict{unobserved: true, reason: fmt.Sprintf("the file never mentions %s", is.ResourceID)}, true
	}
}

// stepsObservedFailing: the file observes a FAIL on at least one hop of path.
func stepsObservedFailing(fr *freshRead, path *model.AttackPath) bool {
	for _, s := range path.Steps {
		if fr.failOn[s.Resource] || (s.WeaknessOn != "" && fr.failOn[s.WeaknessOn]) {
			return true
		}
	}
	return false
}

// issueResourceKey is the resource a finding Issue is keyed on (store.RebuildIssues).
func issueResourceKey(f model.Finding) string {
	if f.Resource.ID != "" {
		return f.Resource.ID
	}
	if f.File != "" {
		return "file:" + f.File
	}
	return "account:" + f.Provider + "/" + f.Account
}

func nodeName(g, base *graph.Graph, id string) string {
	if id == model.PathEntryInternet || id == graph.InternetNodeID {
		return "the internet"
	}
	for _, gr := range []*graph.Graph{g, base} {
		if n, ok := gr.Node(id); ok && n.Name != "" {
			return n.Name
		}
	}
	return id
}

func hopLine(g *graph.Graph, is model.Issue, p model.AttackPath) string {
	var parts []string
	if is.EntryID == "" || is.EntryID == model.PathEntryInternet {
		parts = append(parts, "Internet")
	}
	for _, s := range p.Steps {
		name := nodeName(g, g, s.Resource)
		if len(parts) == 0 || parts[len(parts)-1] != name {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, " → ")
}

func bandUpper(score float64, band string) string {
	if band == "" {
		band = model.ScoreBand(score)
	}
	return strings.ToUpper(band)
}

// scoreChange is "7.0 HIGH" or "10.0 CRITICAL → 7.0 HIGH".
func scoreChange(oldScore float64, oldBand string, newScore float64) string {
	now := fmt.Sprintf("%.1f %s", newScore, bandUpper(newScore, ""))
	if oldScore == 0 || fmt.Sprintf("%.1f", oldScore) == fmt.Sprintf("%.1f", newScore) {
		return now
	}
	return fmt.Sprintf("%.1f %s → %s", oldScore, bandUpper(oldScore, oldBand), now)
}

var openSources = map[string]bool{"0.0.0.0/0": true, "::/0": true, "*": true, "internet": true, "any": true}

// openIngressEvidence names every rule open to the whole internet on the security groups /
// NSGs / firewalls among resources and their attached groups: "port 3389 still open from
// 0.0.0.0/0 on web-sg".
func openIngressEvidence(g *graph.Graph, resources []string) []string {
	sgByShort := map[string]string{}
	for _, n := range g.Nodes() {
		if verifyIsFirewall(n) {
			sgByShort[n.ID[strings.LastIndex(n.ID, "/")+1:]] = n.ID
		}
	}
	seen := map[string]bool{}
	var groups []string
	addGroup := func(id string) {
		if n, ok := g.Node(id); ok && verifyIsFirewall(n) {
			if !seen[id] {
				seen[id] = true
				groups = append(groups, id)
			}
			return
		}
		if full, ok := sgByShort[id[strings.LastIndex(id, "/")+1:]]; ok && strings.HasPrefix(id[strings.LastIndex(id, "/")+1:], "sg-") && !seen[full] {
			seen[full] = true
			groups = append(groups, full)
		}
	}
	for _, r := range resources {
		addGroup(r)
		for _, e := range g.Out(r) {
			addGroup(e.To)
		}
		for _, e := range g.In(r) {
			if e.From != graph.InternetNodeID {
				addGroup(e.From)
			}
		}
	}
	var out []string
	dup := map[string]bool{}
	for _, id := range groups {
		n, _ := g.Node(id)
		for _, rule := range ingressRules(n.Attributes) {
			line := fmt.Sprintf("%s still open from %s on %s", rule.ports, rule.source, firstNonEmpty(n.Name, id))
			if !dup[line] {
				dup[line] = true
				out = append(out, line)
			}
		}
	}
	return out
}

func verifyIsFirewall(n *graph.Node) bool {
	t := strings.ToLower(n.Type)
	return isSecurityGroup(n) || strings.Contains(t, "network_security_group") || strings.Contains(t, "firewall")
}

type openRule struct{ ports, source string }

// ingressRules reads the internet-open inbound rules from a group's attributes (collector
// ingress_rules, scanner ingress / rules; cidr, cidrs, source, sources).
func ingressRules(attrs map[string]any) []openRule {
	var raw any
	for _, k := range []string{"ingress_rules", "ingress", "rules", "inbound"} {
		if v, ok := attrs[k]; ok {
			if list, ok := v.([]any); ok && len(list) > 0 {
				if _, isMap := list[0].(map[string]any); isMap {
					raw = v
					break
				}
			}
		}
	}
	list, _ := raw.([]any)
	var out []openRule
	for _, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if a, _ := m["access"].(string); a != "" && !strings.EqualFold(a, "allow") {
			continue
		}
		var srcs []string
		for _, k := range []string{"cidr", "source", "cidr_ipv4", "cidr_ipv6", "source_address_prefix"} {
			if s, _ := m[k].(string); s != "" {
				srcs = append(srcs, s)
			}
		}
		for _, k := range []string{"cidrs", "sources", "cidr_blocks", "ipv6_cidr_blocks", "source_ranges"} {
			if l, ok := m[k].([]any); ok {
				for _, s := range l {
					if str, ok := s.(string); ok {
						srcs = append(srcs, str)
					}
				}
			}
		}
		for _, s := range srcs {
			if openSources[strings.ToLower(s)] {
				out = append(out, openRule{ports: portLabel(m), source: s})
			}
		}
	}
	return out
}

func portLabel(m map[string]any) string {
	num := func(keys ...string) (int, bool) {
		for _, k := range keys {
			switch v := m[k].(type) {
			case float64:
				return int(v), true
			case int:
				return v, true
			case int64:
				return int(v), true
			}
		}
		return 0, false
	}
	proto, _ := m["protocol"].(string)
	if proto == "-1" || strings.EqualFold(proto, "all") {
		return "all ports"
	}
	if p, ok := num("port"); ok {
		return fmt.Sprintf("port %d", p)
	}
	from, okF := num("from_port", "from")
	to, okT := num("to_port", "to")
	switch {
	case !okF && !okT:
		return "all ports"
	case !okT || from == to:
		return fmt.Sprintf("port %d", from)
	case from == 0 && to == 65535:
		return "all ports"
	}
	return fmt.Sprintf("ports %d-%d", from, to)
}

// verifyOutcome is what verifyLoop decided.
type verifyOutcome struct {
	Verification store.Verification
}

// verifyLoop reads until `attempts` consecutive confirmations (verified_fixed), or — for an
// Issue that is not active (resolved / verified_fixed) — `attempts` consecutive observations
// (reopened), or until the next read would start after the window. A stale (still present)
// or inconclusive read resets the confirmation streak; delays double from interval, capped at
// 8× interval.
func verifyLoop(ctx context.Context, p *verifyPlan, read verifyReader, attempts int, interval, wait time.Duration, logLine func(string)) (*verifyOutcome, error) {
	start := verifyNow()
	active := model.IsActive(p.issue.State)
	confirm, present, reads := 0, 0, 0
	// static: the reads come from a file (exact, a fixed snapshot). Re-reading it never needs a
	// backoff, and one positive observation of the problem is final — attempts guard eventually
	// consistent absence, not presence (Verification 6 C8). Targeted cloud reads keep the
	// consecutive-presence rule: a stale replica must not reopen a verified Issue.
	static := false
	reopenAfter := func() int {
		if static {
			return 1
		}
		return attempts
	}
	delay := interval
	var last verdict
	var evidence []string
	for {
		fr, err := read(ctx)
		if err != nil {
			return nil, err
		}
		v, err := p.evaluate(fr)
		if err != nil {
			return nil, err
		}
		static = fr.exact
		reads++
		last = v
		var line string
		switch {
		case v.inconclusive:
			confirm, present = 0, 0
			line = fmt.Sprintf("read %d: %s (no confirmation)", reads, v.reason)
		case v.unobserved:
			confirm, present = 0, 0
			line = fmt.Sprintf("read %d: unverified — %s", reads, v.reason)
		case v.fixed:
			confirm++
			present = 0
			line = fmt.Sprintf("read %d: gone — %s (confirmation %d/%d)", reads, v.reason, confirm, attempts)
		default:
			confirm = 0
			present++
			line = fmt.Sprintf("read %d: still present — %s", reads, v.reason)
		}
		evidence = append(evidence, line)
		logLine(line)
		if confirm >= attempts || (!active && present >= reopenAfter()) || reads >= verifyMaxReads {
			break
		}
		if static && confirm > 0 {
			continue // the confirmation streak re-reads the file at once, without a backoff
		}
		elapsed := verifyNow().Sub(start)
		if confirm == 0 && elapsed+delay > wait {
			break // no streak in progress and the window is closed
		}
		if err := verifySleep(ctx, delay); err != nil {
			return nil, err
		}
		if delay *= 2; interval > 0 && delay > 8*interval {
			delay = 8 * interval
		}
	}
	v := store.Verification{IssueID: p.issue.ID, At: verifyNow().UTC(), Reads: reads, Confirmations: confirm, Required: attempts, Evidence: evidence}
	switch {
	case confirm >= attempts:
		v.Result, v.Reason = store.VerifyFixed, last.reason
	case !active && present >= reopenAfter():
		v.Result, v.Reason = store.VerifyReopened, "observed again in "+fmt.Sprint(present)+" consecutive read(s): "+last.reason
	case last.unobserved:
		v.Result, v.Reason = store.VerifyUnverified, last.reason
	default:
		v.Result, v.Reason = store.VerifyOpen, last.reason
		if confirm > 0 {
			v.Reason = fmt.Sprintf("only %d of %d confirmations before the window closed: %s", confirm, attempts, last.reason)
		}
	}
	return &verifyOutcome{Verification: v}, nil
}

// verifyTicket closes the Issue's one ticket on verified_fixed and reopens a closed one on
// reopened (IW2), through the configured sink that holds it. Nothing is configured: nothing
// is sent, and the line says so.
func verifyTicket(ctx context.Context, cfg *config.Config, st *store.Store, is model.Issue, v store.Verification) string {
	if is.TicketSink == "" || (is.TicketKey == "" && is.TicketURL == "") {
		return ""
	}
	label := firstNonEmpty(is.TicketKey, is.TicketURL) + " (" + is.TicketSink + ")"
	closeIt := v.Result == store.VerifyFixed && is.TicketState != integrations.TicketClosed
	reopen := v.Result == store.VerifyReopened && is.TicketState == integrations.TicketClosed
	if !closeIt && !reopen {
		return ""
	}
	var tk integrations.IssueTicketer
	for _, t := range sinksFromConfig(cfg, nil) {
		if it, ok := t.Sink.(integrations.IssueTicketer); ok && it.Name() == is.TicketSink {
			tk = it
		}
	}
	if tk == nil {
		return fmt.Sprintf("%s left %s: no %s sink configured", label, is.TicketState, is.TicketSink)
	}
	cur := is
	cur.State = v.Result
	ref := integrations.TicketRef{Key: is.TicketKey, URL: is.TicketURL}
	req := integrations.TicketRequest{Issue: cur}
	state, verb := integrations.TicketClosed, "closed"
	var err error
	if closeIt {
		err = tk.CloseTicket(ctx, ref, req)
	} else {
		state, verb = integrations.TicketOpen, "reopened"
		err = tk.ReopenTicket(ctx, ref, req)
	}
	if err != nil {
		return fmt.Sprintf("%s not %s: %v", label, verb, err)
	}
	if err := st.SetIssueTicket(is.ID, store.IssueTicket{Sink: is.TicketSink, Key: is.TicketKey, URL: is.TicketURL, State: state}); err != nil {
		return fmt.Sprintf("%s %s but not recorded: %v", label, verb, err)
	}
	return label + " " + verb
}

// mcpVerifyFile is the MCP verify tool's from_file evaluator (W7-VERIFY r5 #6): the same plan,
// file reader and decision loop as `verify --from-file --attempts 1` (one read, no window), over
// the server's read-only Reader. Nothing is recorded and no ticket is touched.
func mcpVerifyFile(ctx context.Context, rd mcp.Reader, is model.Issue, path string) (map[string]any, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	g, err := rd.LoadGraph()
	if err != nil {
		return nil, err
	}
	plan, err := newVerifyPlanFrom(cfg, rd, g, is)
	if err != nil {
		return nil, err
	}
	out, err := verifyLoop(ctx, plan, fileReader(plan, path), 1, time.Nanosecond, 0, func(string) {})
	if err != nil {
		return nil, err
	}
	v := out.Verification
	return map[string]any{"result": v.Result, "reason": v.Reason, "evidence": v.Evidence, "reads": v.Reads,
		"confirmations": v.Confirmations, "required": v.Required, "verified_by": "file:" + filepath.Base(path),
		"equivalent_command": "cloud-posture verify " + is.ID + " --from-file " + filepath.Base(path) + " --attempts 1"}, nil
}

// fixedReason is a finding Issue's fixed outcome: what the read observed, never "PASS or absent".
func fixedReason(check, resource string, deleted bool) string {
	if deleted {
		return fmt.Sprintf("%s: %s confirmed deleted by the re-read", check, resource)
	}
	return fmt.Sprintf("%s on %s is now PASS (re-read)", check, resource)
}

// evidenceHistory adapts the store to compliance.PeriodHistory (the evidence period, r5 #9).
type evidenceHistory struct{ st *store.Store }

func (h evidenceHistory) ScanTimes(from, to time.Time) ([]time.Time, error) {
	return h.st.ScanTimes(from, to)
}
func (h evidenceHistory) FailIntervals(ids []string) (map[string][]compliance.Interval, error) {
	m, err := h.st.FindingFailIntervals(ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]compliance.Interval, len(m))
	for k, v := range m {
		for _, iv := range v {
			out[k] = append(out[k], compliance.Interval{From: iv.From, To: iv.To})
		}
	}
	return out, nil
}

func openEvidenceHistory(db string) (compliance.PeriodHistory, func(), error) {
	st, err := store.Open(db)
	if err != nil {
		return nil, nil, err
	}
	return evidenceHistory{st}, func() { st.Close() }, nil
}

// runVerifyEvidence checks a compliance evidence package (r5 #9): exit 0 only when every digest
// matches, nothing is missing, unlisted or duplicated, and the signature verifies with --key.
func runVerifyEvidence(cmd *cobra.Command) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	chk, err := compliance.VerifyEvidence(ctx, verifyFlags.evidence, compliance.VerifyOptions{PublicKey: verifyFlags.key, CosignBin: verifyFlags.cosign})
	if err != nil {
		return err
	}
	if verifyFlags.json {
		if err := output.JSON(os.Stdout, chk); err != nil {
			return err
		}
	} else {
		printEvidenceCheck(os.Stdout, filepath.Base(verifyFlags.evidence), chk)
	}
	if !chk.OK() {
		verifyExit(2)
	}
	return nil
}

func printEvidenceCheck(w io.Writer, name string, chk *compliance.EvidenceCheck) {
	m := chk.Manifest
	if chk.OK() {
		fmt.Fprintf(w, "✓ evidence verified: %s — %d file(s) match manifest.json; signature valid (%s)\n", name, chk.Files, m.Signing.KeyRef)
	} else {
		fmt.Fprintf(w, "✗ evidence NOT verified: %s\n", name)
	}
	for _, x := range []struct {
		label string
		names []string
	}{{"changed (digest mismatch)", chk.Mismatched}, {"missing", chk.Missing}, {"not in the manifest", chk.Unlisted}, {"duplicated entries", chk.Duplicates}} {
		if len(x.names) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", x.label, termSafe(strings.Join(x.names, ", ")))
		}
	}
	if !chk.SignatureOK {
		fmt.Fprintf(w, "  signature: %s\n", termSafe(chk.SignatureErr))
	}
	fmt.Fprintf(w, "  %s %s, period %s to %s (%d days, %d scans from %s)\n", m.FrameworkName, m.Version,
		m.Period.From.Format("2006-01-02"), m.Period.To.Format("2006-01-02"), m.Period.Days, m.Period.Scans, m.Period.Source)
	manual, shown := 0, 0
	for _, c := range m.Controls {
		if c.Kind == compliance.KindManual {
			manual++
			continue
		}
		if c.EffectiveDays+c.FailingDays > 0 && shown < 10 {
			fmt.Fprintf(w, "  %-12s %s\n", termSafe(c.ID), termSafe(c.Statement))
			shown++
		}
	}
	fmt.Fprintf(w, "  %d manual control(s): never passed automatically\n", manual)
}
