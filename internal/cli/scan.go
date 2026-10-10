package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/cost"
	"github.com/DreadpiratePickles/nimbus/internal/dashboard"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/scanner"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

type scanFlagSet struct {
	accounts    []string
	tools       []string
	iac         []string
	fromDir     []string
	out         string
	outFile     string
	sarif       string
	failOn      string
	noStore     bool
	changedOnly bool
	alert       bool
	noNative    bool
	limit       int
	timeout     time.Duration
	diff        bool
	diffJSON    string
	// failOnUnscanned: IaC files that could not be parsed block --fail-on at every threshold.
	failOnUnscanned bool
}

var scanFlags scanFlagSet

// noFailUnscanned reports --fail-on-unscanned=false.
func (f *scanFlagSet) noFailUnscanned() bool { return !f.failOnUnscanned }

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan cloud accounts, SaaS tenants and IaC; aggregate every tool into one graph",
	Example: `  cloud-posture scan --accounts aws-prod,azure-dev,gcp-staging --output dashboard
  cloud-posture scan --iac ./infra --output sarif --sarif results.sarif --fail-on HIGH
  cloud-posture scan --from-dir ./prowler-output --output table
  cloud-posture scan --accounts aws:prod-profile --tools native,python-checks`,
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringSliceVar(&scanFlags.accounts, "accounts", nil, "accounts from config (or ad-hoc provider:id, e.g. aws:prod, gcp:my-project, k8s:ctx)")
	f.StringSliceVar(&scanFlags.tools, "tools", nil, "override tools: native,python-checks,prowler,scoutsuite,checkov,trivy,steampipe")
	f.StringSliceVar(&scanFlags.iac, "iac", nil, "IaC directories/files to scan (Terraform native + checkov/trivy when installed)")
	f.StringSliceVar(&scanFlags.fromDir, "from-dir", nil, "ingest existing scanner output files/directories instead of running tools")
	f.StringVarP(&scanFlags.out, "output", "o", "table", "table|json|sarif|ocsf|asff|gitlab|junit|csv|dashboard|markdown|summary")
	f.StringVar(&scanFlags.outFile, "out-file", "", "write the output to a file (dashboard default: cloud-posture-report/index.html)")
	f.StringVar(&scanFlags.sarif, "sarif", "", "also write SARIF to this path")
	f.StringVar(&scanFlags.failOn, "fail-on", "", "exit 2 when open findings at or above this severity exist")
	f.BoolVar(&scanFlags.failOnUnscanned, "fail-on-unscanned", true, "with --fail-on: IaC files that could not be parsed (IAC_PARSE_LIMIT) block the gate at every threshold")
	f.BoolVar(&scanFlags.noStore, "no-store", false, "do not persist to the posture database")
	f.BoolVar(&scanFlags.changedOnly, "changed-only", false, "IaC: only files staged/changed in git")
	f.BoolVar(&scanFlags.alert, "alert", false, "dispatch new findings to configured integrations after the scan")
	f.BoolVar(&scanFlags.noNative, "no-native", false, "skip the built-in SDK collectors")
	f.IntVar(&scanFlags.limit, "limit", 60, "rows for table output (0 = all)")
	f.DurationVar(&scanFlags.timeout, "timeout", 45*time.Minute, "per-tool timeout")
	f.BoolVar(&scanFlags.diff, "diff", false, "print new / resolved / reopened findings compared with earlier scans (needs the posture database)")
	f.StringVar(&scanFlags.diffJSON, "diff-json", "", "write the --diff change set as JSON to this file (\"-\" = stdout)")
	root.AddCommand(scanCmd, ingestCmd, dashboardCmd)
}

type scanResult struct {
	Findings []model.Finding
	Paths    []model.AttackPath
	Analysis *attackpath.Analysis
	Graph    *graph.Graph
	Risk     []risk.Ranked
	Cost     *cost.Report
	Summary  model.ScanSummary
	// Diff is this scan's lifecycle change set (nil with --no-store); DiffFindings holds
	// the stored finding for each id in it, including resolved ones.
	Diff         *store.Diff
	DiffFindings map[string]model.Finding
	// Issues, Coverage and Scans are read from the store for the dashboard payload.
	Issues   []model.Issue
	Coverage []store.CoverageEntry
	Scans    []model.ScanSummary
	// PathIssues is what this scan's path-Issue rebuild changed (scan --diff).
	PathIssues *store.PathIssueResult
	// Headline is the store's Issue headline after this run (nil with --no-store); DBPath is the
	// database it was written to; Verb names the command in the summary ("Scan", "Ingest").
	Headline *store.Headline
	// Trend is this scan's Issue lifecycle counts as the store recorded them (W6-VERIFY), nil
	// when not recorded; --diff prints Trend.Text(), --diff-json carries issue_trend.
	Trend  *store.ScanTrend
	DBPath string
	Verb   string
}

// iacSource is the Source of the native Terraform scanner's findings (iac.ScanTerraform).
const iacSource = "nimbus-iac"

// collectorHook lets tests replace the native collectors (Options.Collectors).
var collectorHook func(*collector.Options)

// collectorOptions carries config scan.parallel, scan.account_timeout and trusted_cidrs (Track C).
func collectorOptions(cfg *config.Config, onAccount func(collector.AccountSpec, collector.Result, error)) collector.Options {
	conc := cfg.Scan.Parallel
	if conc <= 0 {
		conc = collector.DefaultConcurrency // unset: the collector default, not 1
	}
	o := collector.Options{Concurrency: conc, AccountTimeout: cfg.AccountTimeout(), TrustedCIDRs: cfg.TrustedCIDRs, OnAccount: onAccount}
	if collectorHook != nil {
		collectorHook(&o)
	}
	return o
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := signalContext()
	defer cancel()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	scanID := newScanID()
	sum := model.ScanSummary{ScanID: scanID, StartedAt: now}
	var all []model.Finding
	g := graph.New()
	var signals []collector.CostSignal
	work := filepath.Join(workDir(cfg), scanID)
	sopts := scanner.Options{WorkDir: work, Timeout: scanFlags.timeout, Logf: logf, Python: python(cfg), PythonDir: pythonDir()}
	if (scanFlags.diff || scanFlags.diffJSON != "") && scanFlags.noStore {
		return fmt.Errorf("--diff/--diff-json compare with stored scans; they cannot be combined with --no-store")
	}
	sopts2 := scanOptions{NoStore: scanFlags.noStore, ChangedOnly: scanFlags.changedOnly, Providers: map[string]string{}}
	for name, a := range cfg.Accounts {
		if a != nil {
			sopts2.Providers[name] = a.Provider
		}
	}

	// 1. Accounts: native collectors + external tools.
	if len(scanFlags.accounts) > 0 || (len(scanFlags.iac) == 0 && len(scanFlags.fromDir) == 0 && len(cfg.Accounts) > 0) {
		accts, err := cfg.SelectAccounts(scanFlags.accounts)
		if err != nil {
			return err
		}
		var specs []collector.AccountSpec
		for _, a := range accts {
			sum.Accounts = append(sum.Accounts, a.Name)
			tools := a.Tools
			if len(scanFlags.tools) > 0 {
				tools = scanFlags.tools
			}
			if len(tools) == 0 || contains(tools, "native") || contains(tools, "nimbus") {
				if !scanFlags.noNative {
					specs = append(specs, collector.AccountSpec{Name: a.Name, Provider: a.Provider, Profile: a.Profile, RoleARN: a.RoleARN, Regions: a.Regions, SubscriptionID: a.SubscriptionID, TenantID: a.TenantID, ProjectID: a.ProjectID, KubeContext: a.KubeContext, Org: a.Org, Domain: a.Domain, TokenEnv: a.TokenEnv})
				}
			}
		}
		if len(specs) > 0 {
			logf("▶ native collectors: %d account(s)", len(specs))
			cg, res := collector.RunAll(ctx, specs, collectorOptions(cfg, func(spec collector.AccountSpec, r collector.Result, err error) {
				if err != nil {
					logf("  ✗ %s: %v", spec.Label(), err)
				} else {
					logf("  ✓ %s: %d findings", spec.Label(), len(r.Findings))
				}
			}))
			g.Merge(cg)
			for i := range res.Findings {
				res.Findings[i].ScanID = scanID
			}
			adapters.Finalize(res.Findings, adapters.Options{Now: now})
			all = append(all, res.Findings...)
			signals = append(signals, res.Cost...)
			sum.Tools = append(sum.Tools, res.Runs...)
			for _, w := range res.Warnings {
				logf("  ! %s", w)
			}
			// Partial collector errors (denied / throttled / timed-out API calls) are
			// coverage, not failed tool runs: the per-account run already reports them.
			sopts2.CollectErrors = append(sopts2.CollectErrors, res.CollectErrors()...)
			sopts2.Targets = append(sopts2.Targets, nativeTargets(specs, res.Runs)...)
		}
		for _, a := range accts {
			acct := *a
			if len(scanFlags.tools) > 0 {
				acct.Tools = scanFlags.tools
			}
			for _, o := range scanner.RunAccount(ctx, &acct, sopts) {
				all = append(all, ingestOutput(o, acct.Name, acct.Provider, scanID, now, &sum)...)
			}
		}
		for _, p := range cfg.Plugins {
			o := scanner.RunPlugin(ctx, p, sopts)
			all = append(all, ingestOutput(o, p.Account, "", scanID, now, &sum)...)
		}
	}

	// 2. IaC.
	iacPaths := append([]string{}, scanFlags.iac...)
	if len(iacPaths) == 0 && len(scanFlags.accounts) == 0 && len(scanFlags.fromDir) == 0 {
		iacPaths = cfg.Scan.IaCPaths
	}
	for _, p := range iacPaths {
		ires, err := iac.ScanTerraformResult(p, now)
		fs := ires.Findings
		var unscanned *iac.UnscannedError
		if errors.As(err, &unscanned) {
			// Files that did not parse (or exceeded the parser limits) were not observed:
			// their stored findings must not resolve, and their IAC_PARSE_LIMIT findings
			// count toward --fail-on (failOn).
			for _, f := range ires.UnscannedFiles {
				logf("  ✗ iac %s: %s not scanned: %s", p, f, ires.UnscannedReasons[f])
				sopts2.SkipFiles = append(sopts2.SkipFiles, store.FileScope{Root: filepath.Clean(p), File: f})
			}
		} else if err != nil {
			logf("iac %s: %v", p, err)
		}
		if scanFlags.changedOnly {
			fs = filterChanged(fs, p)
		}
		for i := range fs {
			fs[i].ScanID = scanID
			tagRoot(&fs[i], p)
		}
		adapters.Finalize(fs, adapters.Options{Now: now, Account: "iac"})
		all = append(all, fs...)
		run := model.ToolRun{Tool: "nimbus-iac", Account: p, Status: "ok", Findings: len(fs)}
		if err == nil || unscanned != nil {
			// The root was examined; unscanned files are excluded via SkipFiles.
			sopts2.Targets = append(sopts2.Targets, store.Target{Source: iacSource, AccountLabel: "iac", Root: filepath.Clean(p)})
		}
		if unscanned != nil {
			run.Status, run.Message = "partial", unscanned.Error()
		}
		sum.Tools = append(sum.Tools, run)
		inv, _ := iac.Inventory(p)
		kinds := []string{}
		for k, files := range inv {
			kinds = append(kinds, fmt.Sprintf("%s=%d", k, len(files)))
		}
		if len(kinds) > 0 {
			logf("▶ iac %s: %s", p, strings.Join(kinds, " "))
		}
	}
	if len(iacPaths) > 0 {
		for _, o := range scanner.RunIaC(ctx, iacPaths, sopts) {
			fs := ingestOutput(o, "iac", "", scanID, now, &sum)
			for i := range fs {
				tagRoot(&fs[i], o.Root)
				// External tools report root-relative files too: qualify their ids by
				// root, so identical files under two roots never share a finding.
				fs[i].ID = rootScopedID(fs[i].ID, o.Root)
			}
			if scanFlags.changedOnly {
				fs = filterChanged(fs, ".")
			}
			all = append(all, fs...)
		}
	}

	// 3. Existing output files.
	for _, d := range scanFlags.fromDir {
		fs, runs := ingestPath(d, "", "", scanID, now)
		all = append(all, fs...)
		sum.Tools = append(sum.Tools, runs...)
	}

	if len(sum.Tools) == 0 && len(all) == 0 {
		// Delta review 2 #11: nothing was examined, so "0 open findings" would be a false
		// "clean". Exit 2 before anything is stored; --fail-on never passes this.
		nothingScanned("nothing scanned: no accounts configured, no IaC root and no tool ran; run `cloud-posture onboard` or pass --iac <dir>")
	}
	all = dedupe(all)
	res, err := finishScanWith(ctx, cfg, all, g, signals, sum, sopts2)
	if err != nil {
		return err
	}
	if err := emit(res, scanFlags.out, scanFlags.outFile, scanFlags.sarif, scanFlags.limit); err != nil {
		return err
	}
	if scanFlags.diff {
		printDiff(diffWriter(scanFlags.out, scanFlags.outFile), res)
	}
	if err := writeDiffJSON(scanFlags.diffJSON, res); err != nil {
		return err
	}
	if scanFlags.alert && !scanFlags.noStore {
		st, err := openStore()
		if err == nil {
			defer st.Close()
			results := integrations.Dispatch(ctx, st, sinksFromConfig(cfg, nil), res.Findings, res.Paths, integrations.Options{AutoClose: true})
			logf("alerts: %d results", len(results))
		}
	}
	return failOnWith(res.Findings, scanFlags.failOn, !scanFlags.noFailUnscanned())
}

// nothingScanned reports a run that examined nothing and exits 2 (the --fail-on exit code):
// a scan or ingest with no input must never read as a clean result.
func nothingScanned(msg string) {
	fmt.Fprintln(os.Stderr, "✗ "+msg)
	os.Exit(2)
}

// emptyIngestInputs lists the ingest arguments that held nothing: a file that is empty or
// whitespace, a JSON document with no records ([] / {} / null), a file an adapter parsed to
// zero findings, or a directory with no JSON files. Unparseable input is not "empty".
func emptyIngestInputs(args []string, runs []model.ToolRun) []string {
	var out []string
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			continue
		}
		if st.IsDir() {
			n := 0
			filepath.WalkDir(a, func(p string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					switch strings.ToLower(filepath.Ext(p)) {
					case ".json", ".js", ".jsonl":
						n++
					}
				}
				return nil
			})
			if n == 0 {
				out = append(out, a)
			}
			continue
		}
		if st.Size() <= 1<<16 {
			if b, err := os.ReadFile(a); err == nil {
				switch strings.TrimSpace(string(b)) {
				case "", "[]", "{}", "null":
					out = append(out, a)
					continue
				}
			}
		}
		for _, r := range runs {
			if r.Output == a && r.Status == "ok" && r.Findings == 0 {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

func ingestOutput(o scanner.Output, account, provider, scanID string, now time.Time, sum *model.ScanSummary) []model.Finding {
	run := o.Run
	if run.Tool == "" {
		run.Tool = o.Tool
	}
	if run.Account == "" {
		run.Account = account
	}
	if run.Status != "ok" || o.Path == "" {
		sum.Tools = append(sum.Tools, run)
		return nil
	}
	fs, name, err := adapters.ParseFile(o.Path, o.Source, adapters.Options{Account: account, Provider: provider, Now: now})
	if err != nil {
		run.Status, run.Message = "failed", err.Error()
		sum.Tools = append(sum.Tools, run)
		return nil
	}
	for i := range fs {
		fs[i].ScanID = scanID
	}
	run.Findings = len(fs)
	if run.Tool == "" {
		run.Tool = name
	}
	sum.Tools = append(sum.Tools, run)
	return fs
}

// ingestPath parses one file or every recognisable file in a directory.
func ingestPath(path, source, account, scanID string, now time.Time) ([]model.Finding, []model.ToolRun) {
	var all []model.Finding
	var runs []model.ToolRun
	st, err := os.Stat(path)
	if err != nil {
		runs = append(runs, model.ToolRun{Tool: "ingest", Account: path, Status: "failed", Message: err.Error()})
		return nil, runs
	}
	var files []string
	if st.IsDir() {
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				ext := strings.ToLower(filepath.Ext(p))
				if ext == ".json" || ext == ".js" || ext == ".jsonl" {
					files = append(files, p)
				}
			}
			return nil
		})
	} else {
		files = []string{path}
	}
	for _, f := range files {
		fs, name, err := adapters.ParseFile(f, source, adapters.Options{Account: account, Now: now})
		if err != nil {
			if source != "" || !st.IsDir() {
				runs = append(runs, model.ToolRun{Tool: "ingest", Account: f, Status: "failed", Message: err.Error()})
			}
			continue
		}
		for i := range fs {
			fs[i].ScanID = scanID
		}
		logf("  ✓ %s: %d findings (%s)", f, len(fs), name)
		runs = append(runs, model.ToolRun{Tool: name, Account: firstNonEmpty(account, f), Status: "ok", Findings: len(fs), Output: f})
		all = append(all, fs...)
	}
	return all, runs
}

func dedupe(fs []model.Finding) []model.Finding {
	seen := map[string]int{}
	var out []model.Finding
	for _, f := range fs {
		if i, ok := seen[f.ID]; ok {
			if f.Status == model.Fail {
				out[i] = f
			}
			continue
		}
		seen[f.ID] = len(out)
		out = append(out, f)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// filterChanged keeps IaC findings in files that git reports as changed/staged.
func filterChanged(fs []model.Finding, root string) []model.Finding {
	changed := map[string]bool{}
	for _, args := range [][]string{{"diff", "--name-only", "--cached"}, {"diff", "--name-only"}, {"ls-files", "--others", "--exclude-standard"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if out, err := cmd.Output(); err == nil {
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if l != "" {
					changed[filepath.ToSlash(l)] = true
				}
			}
		}
	}
	if len(changed) == 0 {
		return fs
	}
	var out []model.Finding
	for _, f := range fs {
		if changed[filepath.ToSlash(f.File)] || changed[filepath.ToSlash(filepath.Join(root, f.File))] {
			out = append(out, f)
		}
	}
	return out
}

// finishScan persists findings, builds the graph, attack paths, risk ranking and cost report.
func finishScan(ctx context.Context, cfg *config.Config, all []model.Finding, g *graph.Graph, signals []collector.CostSignal, sum model.ScanSummary, noStore bool) (*scanResult, error) {
	return finishScanWith(ctx, cfg, all, g, signals, sum, scanOptions{NoStore: noStore})
}

// scanOptions carries what finishScanWith needs beyond the findings themselves.
type scanOptions struct {
	NoStore bool
	// ChangedOnly scans saw only changed IaC files, so IaC findings are never resolved by absence.
	ChangedOnly bool
	// CollectErrors are the native collectors' partial failures (coverage rows, and
	// their provider's native findings are not resolved by absence this scan).
	CollectErrors []collector.CollectError
	// Providers maps configured account names to providers for coverage rows.
	Providers map[string]string
	// Targets are what the scan declared it examined in full (IaC roots, native
	// accounts that ran clean); their stored findings resolve by absence even when the
	// target produced no findings at all this time.
	Targets []store.Target
	// SkipFiles are IaC files under a declared root that could not be parsed: their
	// stored findings are never resolved by absence.
	SkipFiles []store.FileScope
}

func finishScanWith(ctx context.Context, cfg *config.Config, all []model.Finding, g *graph.Graph, signals []collector.CostSignal, sum model.ScanSummary, opts scanOptions) (*scanResult, error) {
	noStore := opts.NoStore
	g.AttachFindings(all)
	// The accounts this scan itself observed (collector graph + its own findings), before
	// stored findings of other accounts are attached: the path-Issue rebuild is scoped to them.
	observed := graphAccounts(g)
	attackpath.AnnotateExposure(g, trustedCIDRs(cfg))
	res := &scanResult{Findings: all, Graph: g, Summary: sum}
	rules, _ := attackpath.LoadRules(nil)
	if noStore {
		rulePaths := attackpath.EvaluateWith(all, rules, evalOptionsFor(cfg, g))
		an := attackpath.Traverse(g, traversalOptionsFor(cfg, g, all))
		an.Paths = attackpath.Merge(an.Paths, rulePaths)
		relinkSecurityGroupDeadEnds(an, g)
		res.Paths, res.Analysis = an.Paths, an
		res.Risk = prioritizeBest(ctx, cfg, nil, all, g, an, 50)
		governFindingRanked(cfg, res.Risk)
		res.Summary = summarize(res.Summary, all, res.Paths)
		return res, nil
	}
	st, err := openStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	now := time.Now().UTC()
	scopes, err := lifecycleScopes(st, all, opts)
	if err != nil {
		return nil, err
	}
	diff, err := st.ApplyScan(sum.ScanID, all, now, scopes)
	if err != nil {
		return nil, err
	}
	res.Diff = diff
	// Findings from earlier scans still count for the graph and paths.
	stored, err := st.Findings(store.Filter{})
	if err != nil {
		return nil, err
	}
	g.AttachFindings(stored)
	// Label internet edges wide / narrow / trusted against trusted_cidrs before the graph is
	// stored, so every later reader (paths, serve, dashboard) sees the same exposure.
	attackpath.AnnotateExposure(g, trustedCIDRs(cfg))
	if err := saveGraph(st, g); err != nil {
		return nil, err
	}
	paths, an, err := analyze(st, g, stored, cfg, sum.ScanID)
	if err != nil {
		return nil, err
	}
	ranked := rankAll(ctx, cfg, stored, g, paths, an)
	pathRes, err := rebuildIssueViews(st, sum.ScanID, ranked, an, observedScope(observed, g), now)
	if err != nil {
		return nil, err
	}
	// Owners and due dates for every Issue (re-resolved each run), then the ranking reads them.
	governIssueViews(cfg, st, g)
	governStoredRanked(st, ranked)
	res.PathIssues = pathRes
	if err := st.RecordCoverage(sum.ScanID, now, coverageEntries(sum.Tools, opts)); err != nil {
		return nil, err
	}
	res.DiffFindings = map[string]model.Finding{}
	for _, ids := range [][]string{diff.New, diff.Resolved, diff.Reopened} {
		for _, id := range ids {
			if f, err := st.Finding(id); err == nil {
				res.DiffFindings[id] = *f
			}
		}
	}
	// Gates, SARIF/JSON output and --alert act on this scan only (inventory defect 8); the graph,
	// attack paths and risk ranking above still use the full stored history.
	current, err := st.Findings(store.Filter{ScanID: sum.ScanID})
	if err != nil {
		return nil, err
	}
	res.Findings, res.Paths, res.Analysis = current, paths, an
	if err := writeRiskJSON(st, ranked); err != nil {
		logf("risk.json: %v", err)
	}
	res.Risk = topN(ranked, 50)
	if len(signals) > 0 {
		cr := cost.Analyze(signals, g, paths, cost.Options{Findings: stored})
		res.Cost = &cr
		data, _ := json.Marshal(signals)
		os.MkdirAll(stateDir(), 0o755)
		os.WriteFile(filepath.Join(stateDir(), "cost-signals.json"), data, 0o644)
		if cj, err := cr.JSON(); err == nil {
			os.WriteFile(filepath.Join(stateDir(), "cost-report.json"), cj, 0o644)
		}
	}
	res.Summary = summarize(res.Summary, current, paths)
	res.Summary.FinishedAt = time.Now().UTC()
	if err := st.SaveScan(res.Summary); err != nil {
		return nil, err
	}
	if t, err := st.ScanTrendOf(res.Summary.ScanID); err == nil {
		res.Trend = t
	}
	loadLifecycleViews(st, res)
	return res, nil
}

// loadLifecycleViews fills the Issue, coverage and scan-history views of res (dashboard payload).
func loadLifecycleViews(st *store.Store, res *scanResult) {
	if is, err := st.Issues(store.IssueFilter{}); err == nil {
		res.Issues = is
	}
	if h, err := st.Headline(); err == nil {
		res.Headline = h
	}
	res.DBPath = st.Path()
	if cov, err := st.Coverage(""); err == nil {
		res.Coverage = cov
	}
	if sc, err := server.ScanHistory(st, 100); err == nil {
		res.Scans = sc
	}
}

func summarize(sum model.ScanSummary, fs []model.Finding, paths []model.AttackPath) model.ScanSummary {
	sum.Total = len(fs)
	sum.BySeverity = map[model.Severity]int{}
	sum.ByProvider = map[string]int{}
	for _, f := range fs {
		if f.Status != model.Fail {
			continue
		}
		sum.Failed++
		sum.BySeverity[f.Severity]++
		sum.ByProvider[f.Provider]++
	}
	sum.AttackPaths = len(paths)
	if sum.FinishedAt.IsZero() {
		sum.FinishedAt = time.Now().UTC()
	}
	return sum
}

// rankAll is the one published score (internal/risk, docs/scoring.md) over every failing
// finding, with the KEV/EPSS feed and config crown jewels. Python never re-scores: it reads
// the risk.json this writes (writeRiskJSON).
// an is the traversal analysis behind paths (nil = paths alone): its ReachesCrownJewel and
// Exposures feed the off-path cap (risk.Options.Analysis).
func rankAll(ctx context.Context, cfg *config.Config, fs []model.Finding, g *graph.Graph, paths []model.AttackPath, an *attackpath.Analysis) []risk.Ranked {
	o := riskOptions(ctx, cfg)
	o.Analysis = an
	return risk.PrioritizeWith(fs, g, paths, o)
}

// prioritizeBest returns the top ranked findings (0 = all). With a store, owner / SLA / due
// come from the governance assignment of the Issue carrying each finding (one due date).
func prioritizeBest(ctx context.Context, cfg *config.Config, st *store.Store, fs []model.Finding, g *graph.Graph, an *attackpath.Analysis, top int) []risk.Ranked {
	var paths []model.AttackPath
	if an != nil {
		paths = an.Paths
	}
	ranked := topN(rankAll(ctx, cfg, fs, g, paths, an), top)
	governStoredRanked(st, ranked)
	return ranked
}

func topN(r []risk.Ranked, n int) []risk.Ranked {
	if n > 0 && len(r) > n {
		return r[:n]
	}
	return r
}

// riskJSONPath is <db>.risk.json beside the posture database, where python/nimbus/risk.py
// looks: one ranking per database, so two DBs in one directory never share or overwrite it.
func riskJSONPath(st *store.Store) string { return st.Path() + ".risk.json" }

// writeRiskJSON persists the full Go ranking (risk.Ranked JSON with score_version and
// explanation) atomically, so the Python layer and reports show Go's numbers.
func writeRiskJSON(st *store.Store, ranked []risk.Ranked) error {
	if st == nil {
		return nil
	}
	out := make([]risk.Ranked, len(ranked))
	copy(out, ranked)
	for i := range out {
		out[i].Finding.Raw = nil
	}
	if out == nil {
		out = []risk.Ranked{}
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	path := riskJSONPath(st)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".risk-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func emit(res *scanResult, format, outFile, sarifPath string, limit int) error {
	if sarifPath != "" {
		if err := output.WriteFile(sarifPath, output.SARIF(res.Findings)); err != nil {
			return err
		}
		logf("SARIF written to %s", sarifPath)
	}
	w := os.Stdout
	if outFile != "" && format != "dashboard" {
		f, err := os.Create(outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch format {
	case "json":
		doc := map[string]any{"scan": res.Summary, "findings": res.Findings, "attack_paths": res.Paths, "analysis": res.Analysis, "risk": res.Risk, "cost": res.Cost}
		if res.Diff != nil {
			doc["diff"] = res.Diff
		}
		return output.JSON(w, doc)
	case "sarif":
		return output.JSON(w, output.SARIF(res.Findings))
	case "ocsf", "asff", "gitlab", "junit", "csv":
		// The interop formats of internal/output (OCSF 1.6, ASFF, GitLab SAST v15, JUnit,
		// formula-safe CSV); the same renderer as `cloud-posture convert`.
		b, err := output.Render(res.Findings, format)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	case "markdown", "md":
		fmt.Fprint(w, output.PRMarkdown(res.Findings, res.Paths, 30))
		return nil
	case "summary":
		printScanSummary(w, res)
		return nil
	case "dashboard", "html":
		path := outFile
		if path == "" {
			path = filepath.Join("cloud-posture-report", "index.html")
		}
		html, err := renderDashboard(res, "static", "")
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, html, 0o644); err != nil {
			return err
		}
		printScanSummary(os.Stdout, res)
		abs, _ := filepath.Abs(path)
		fmt.Printf("\nView dashboard: file://%s\nLive mode:      cloud-posture serve\n", abs)
		return nil
	case "table", "":
		var fails []model.Finding
		for _, f := range res.Findings {
			if f.Status == model.Fail {
				fails = append(fails, f)
			}
		}
		output.Table(w, fails, limit)
		printScanSummary(w, res)
		if res.Analysis != nil && len(res.Analysis.BreakFixes) > 0 {
			fmt.Fprintln(w, "\nBreak the path (top fixes):")
			for i, fx := range res.Analysis.BreakFixes {
				if i >= 3 {
					break
				}
				fmt.Fprintf(w, "- %s on %s → removes %d path(s): %s\n", strings.ToLower(strings.ReplaceAll(fx.Weakness, "_", " ")), fx.Name, len(fx.Breaks), fx.Command)
			}
		}
		if len(res.Risk) > 0 {
			// A finding's contextual risk score, not an Issue count: say so, and name its severity
			// (the headline counts Issues by severity), so "0 critical" never sits beside an
			// unlabelled "9.8 Critical" (r4 N9).
			r := res.Risk[0]
			fmt.Fprintf(w, "\nTop-ranked finding: %s on %s — risk score %.1f of 10 (severity %s; Issue counts above are by severity; why: %s)\n",
				r.Finding.CanonicalID, firstNonEmpty(r.Finding.Resource.Name, r.Finding.Resource.ID), r.Score, r.Finding.Severity, strings.Join(r.Reasons, "; "))
		}
		if res.Cost != nil {
			fmt.Fprintln(w)
			fmt.Fprint(w, res.Cost.Text())
		}
		return nil
	default:
		return fmt.Errorf("unknown output format %q (table|json|sarif|ocsf|asff|gitlab|junit|csv|dashboard|markdown|summary)", format)
	}
}

func renderDashboard(res *scanResult, mode, copilot string) ([]byte, error) {
	var reports []*compliance.Report
	seen := map[string]bool{}
	for _, f := range res.Findings {
		for fw := range f.Compliance {
			seen[fw] = true
		}
	}
	for fw := range seen {
		if rep, err := compliance.Build(fw, res.Findings, ""); err == nil && rep.Passing+rep.Failing > 0 {
			reports = append(reports, rep)
		}
	}
	var costAny any
	if res.Cost != nil {
		costAny = map[string]any{"text": res.Cost.Text(), "total_monthly_savings": res.Cost.TotalMonthlySavings, "zombies": res.Cost.Zombies, "rightsizing": res.Cost.Rightsizing, "security_cost_wins": res.Cost.SecurityCostWins, "roi": res.Cost.ROI}
	}
	gj := map[string]any{"nodes": []any{}, "edges": []any{}}
	if res.Graph != nil {
		gj = res.Graph.JSON()
	}
	sum := res.Summary
	issues, coverage, scans := res.Issues, res.Coverage, res.Scans
	if issues == nil {
		issues = []model.Issue{}
	}
	if coverage == nil {
		coverage = []store.CoverageEntry{}
	}
	if scans == nil {
		scans = []model.ScanSummary{}
	}
	groups, titles := dashboardPathGroups(res)
	return dashboard.Render(dashboard.Data{Mode: mode, Accounts: sum.Accounts, Findings: res.Findings, Paths: res.Paths, Analysis: res.Analysis, Graph: gj, Risk: res.Risk, Compliance: reports, Cost: costAny, Scan: &sum, CopilotURL: copilot,
		Issues: issues, Coverage: coverage, Scans: scans, IssuePages: dashboardIssuePages(res), Governance: dashboardGovernance(res), Headline: dashHeadline(res),
		PathGroups: groups, PathTitles: titles})
}

// dashboardPathGroups is the paths view's rows under the stored (keyed) Issue ids, so a row links
// to its Issue page (MCP-1: ids are HMAC-keyed per database). nil without a store: Render then
// groups the in-memory paths itself.
func dashboardPathGroups(res *scanResult) ([]dashboard.PathGroupRow, map[string]string) {
	var st *store.Store
	if len(res.Issues) > 0 {
		if s, err := openStore(); err == nil {
			st = s
			defer st.Close()
		}
	}
	// One title and one order with `paths`, `plan`, `issues` and the API (W6-POLISH, r4 #4).
	view := newPathIssueView(st, res.Graph)
	titles := map[string]string{}
	for _, p := range res.Paths {
		titles[p.ID] = view.Row(p)
	}
	if st == nil {
		return nil, titles
	}
	groups := pathGroupsOf(res)
	view.SortGroups(groups)
	rows := dashboard.PathGroupRows(groups)
	for i := range rows {
		rows[i].IssueID = view.IssueID(groups[i].Best)
		rows[i].Name = view.Title(groups[i].Best)
	}
	return rows, titles
}

// dashboardGovernance is the owners panel's metrics (nil without a store or Issues).
func dashboardGovernance(res *scanResult) any {
	if len(res.Issues) == 0 {
		return nil
	}
	st, err := openStore()
	if err != nil {
		return nil
	}
	defer st.Close()
	m, err := server.BuildGovernanceMetrics(st, time.Now().UTC())
	if err != nil {
		logf("dashboard: governance metrics: %v", err)
		return nil
	}
	return m
}

// dashIssuePage is the Issue pane's share of server.IssuePage: everything the payload does not
// already carry (the Issue, its findings and the risk explanation are in the payload).
type dashIssuePage struct {
	Hops        []server.PageHop       `json:"hops"`
	Paths       []server.PagePath      `json:"paths"`
	Score       server.PageScore       `json:"score"`
	Confidence  server.PageConfidence  `json:"confidence"`
	Owner       server.PageOwner       `json:"owner"`
	Linked      []server.LinkedIssue   `json:"linked_issues"`
	Fixes       []server.PageFix       `json:"fixes"`
	Tickets     []server.PageTicket    `json:"tickets"`
	Timeline    []server.TimelineEntry `json:"timeline"`
	Suppression server.PageSuppression `json:"suppression"`
}

// dashboardIssuePages builds the Issue pages of res's Issues from the store (nil without a
// store or without Issues; the pane then falls back to what the payload has).
func dashboardIssuePages(res *scanResult) map[string]dashIssuePage {
	if len(res.Issues) == 0 {
		return nil
	}
	st, err := openStore()
	if err != nil {
		return nil
	}
	defer st.Close()
	cfg, _ := config.Load(flagConfig)
	ctx := context.Background()
	o := server.IssuePageOptions{Graph: res.Graph, Paths: res.Paths, Analysis: res.Analysis, Issues: res.Issues, Risk: riskOptions(ctx, cfg)}
	o.Risk.Analysis = res.Analysis
	if o.Paths == nil {
		o.Paths = []model.AttackPath{}
	}
	pages, err := server.BuildIssuePages(st, o)
	if err != nil {
		logf("dashboard: issue pages: %v", err)
		return nil
	}
	out := make(map[string]dashIssuePage, len(pages))
	for id, pg := range pages {
		sc := pg.Score
		sc.Explanation = nil
		out[id] = dashIssuePage{Hops: pg.Hops, Paths: pg.Paths, Score: sc, Confidence: pg.Confidence, Owner: pg.Owner, Linked: pg.Linked,
			Fixes: pg.Fixes, Tickets: pg.Tickets, Timeline: pg.Timeline, Suppression: pg.Suppression}
	}
	return out
}

func failOn(fs []model.Finding, sev string) error {
	return failOnWith(fs, sev, true)
}

// failOnWith is the --fail-on gate. With unscanned=true (the default; --fail-on-unscanned)
// a scan gap — an IaC file that could not be parsed (IAC_PARSE_LIMIT, ERROR status) — blocks
// the gate at EVERY threshold (output.GateBlocks; main-session decision after V3-cli): whatever
// the file contains was not examined, so `--fail-on critical` must not let a PR hide a public
// bucket behind a parse error. --fail-on-unscanned=false is the explicit opt-out.
func failOnWith(fs []model.Finding, sev string, unscanned bool) error {
	if sev == "" {
		return nil
	}
	n, gaps := gateCounts(fs, sev, unscanned)
	if n+gaps > 0 {
		msg := fmt.Sprintf("✗ %d open finding(s) at or above %s", n, model.ParseSeverity(sev))
		if gaps > 0 {
			msg += fmt.Sprintf(" and %d IaC file(s) not scanned (a scan gap blocks every --fail-on threshold; --fail-on-unscanned=false to ignore)", gaps)
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(2)
	}
	return nil
}

// gateCount is the number of findings that fail the --fail-on gate (output.GateCount
// semantics: failing findings at or above sev plus every scan gap).
func gateCount(fs []model.Finding, sev string) int {
	n, gaps := gateCounts(fs, sev, true)
	return n + gaps
}

// gateCounts splits the gate into failing findings at or above sev and scan gaps; gaps
// count at every threshold when unscanned is set (output.GateBlocks), never otherwise.
func gateCounts(fs []model.Finding, sev string, unscanned bool) (n, gaps int) {
	if sev == "" {
		return 0, 0
	}
	for _, f := range fs {
		switch {
		case isScanGap(f):
			if unscanned {
				gaps++
			}
		case output.GateBlocks(f, sev):
			n++
		}
	}
	return n, gaps
}

// isScanGap reports a finding that marks unexamined input (output.TagScanGap, or an
// IAC_PARSE_LIMIT finding from a DB written before the tag existed).
func isScanGap(f model.Finding) bool {
	return output.IsScanGap(f) || (f.CanonicalID == "IAC_PARSE_LIMIT" && f.Status != model.Pass)
}

// ---------------------------------------------------------------- ingest

var ingestFlags struct {
	source, account string
	out             string
	diff            bool
	diffJSON        string
}

var ingestCmd = &cobra.Command{
	Use:   "ingest <file-or-dir>...",
	Short: "Ingest existing Prowler / ScoutSuite / Checkov / Trivy / Steampipe / native JSON output",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalContext()
		defer cancel()
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		scanID := newScanID()
		sum := model.ScanSummary{ScanID: scanID, StartedAt: now}
		var all []model.Finding
		for _, p := range args {
			fs, runs := ingestPath(p, ingestFlags.source, ingestFlags.account, scanID, now)
			all = append(all, fs...)
			sum.Tools = append(sum.Tools, runs...)
		}
		var dropped int
		all, dropped = dropEmptyRecords(all)
		if len(all) == 0 && dropped > 0 {
			nothingScanned(fmt.Sprintf("nothing to ingest: %s held %d record(s) with no check, resource, file or title (an empty record is not a finding)", strings.Join(args, ", "), dropped))
		}
		if dropped > 0 {
			logf("ingest: skipped %d empty record(s) (no check, resource, file or title)", dropped)
		}
		if len(all) == 0 {
			if empty := emptyIngestInputs(args, sum.Tools); len(empty) > 0 {
				nothingScanned(fmt.Sprintf("nothing to ingest: %s contains no findings (an empty export is not a clean result; check the scanner run that produced it)", strings.Join(empty, ", ")))
			}
			var why []string
			for _, r := range sum.Tools {
				if r.Status == "failed" && r.Message != "" {
					why = append(why, r.Account+": "+r.Message)
				}
			}
			if len(why) > 0 {
				return fmt.Errorf("no findings parsed (use --source to force a format): %s", strings.Join(why, "; "))
			}
			return fmt.Errorf("no findings parsed (use --source to force a format)")
		}
		res, err := finishScan(ctx, cfg, dedupe(all), graph.New(), nil, sum, false)
		if err != nil {
			return err
		}
		res.Verb = "Ingest"
		if err := emit(res, ingestFlags.out, "", "", 40); err != nil {
			return err
		}
		if ingestFlags.diff {
			printDiff(diffWriter(ingestFlags.out, ""), res)
		}
		return writeDiffJSON(ingestFlags.diffJSON, res)
	},
}

func init() {
	ingestCmd.Flags().StringVar(&ingestFlags.source, "source", "", "force adapter: prowler|scoutsuite|checkov|trivy|steampipe|native")
	ingestCmd.Flags().StringVar(&ingestFlags.account, "account", "", "account label to attach")
	ingestCmd.Flags().StringVarP(&ingestFlags.out, "output", "o", "summary", "table|json|summary|dashboard")
	ingestCmd.Flags().BoolVar(&ingestFlags.diff, "diff", false, "print new / resolved / reopened findings compared with earlier scans")
	ingestCmd.Flags().StringVar(&ingestFlags.diffJSON, "diff-json", "", "write the --diff change set as JSON to this file (\"-\" = stdout)")
}

// ---------------------------------------------------------------- dashboard

var dashFlags struct {
	out     string
	copilot string
}

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Render the single-file HTML dashboard from the posture database",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signalContext()
		defer cancel()
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		res, st, err := loadResult(ctx, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		html, err := renderDashboard(res, "static", dashFlags.copilot)
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(dashFlags.out), 0o755)
		if err := os.WriteFile(dashFlags.out, html, 0o644); err != nil {
			return err
		}
		abs, _ := filepath.Abs(dashFlags.out)
		fmt.Printf("file://%s\n", abs)
		return nil
	},
}

func init() {
	dashboardCmd.Flags().StringVar(&dashFlags.out, "out", filepath.Join("cloud-posture-report", "index.html"), "output path")
	dashboardCmd.Flags().StringVar(&dashFlags.copilot, "copilot", "", "URL of the Python intelligence API (nimbus serve) for the copilot panel")
}

// loadResult assembles everything the dashboard/serve need from the store.
func loadResult(ctx context.Context, cfg *config.Config) (*scanResult, *store.Store, error) {
	st, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	fs, err := st.Findings(store.Filter{})
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	g, err := loadGraph(st)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	if g.Len() <= 1 {
		g.AttachFindings(fs)
	}
	paths, _ := st.AttackPaths()
	an := attackpath.Traverse(g, traversalOptionsFor(cfg, g, fs))
	an.Paths = attackpath.Merge(an.Paths, paths)
	relinkSecurityGroupDeadEnds(an, g)
	res := &scanResult{Findings: fs, Graph: g, Paths: an.Paths, Analysis: an}
	res.Risk = prioritizeBest(ctx, cfg, st, fs, g, an, 50)
	if data, err := os.ReadFile(filepath.Join(stateDir(), "cost-signals.json")); err == nil {
		var signals []collector.CostSignal
		if json.Unmarshal(data, &signals) == nil && len(signals) > 0 {
			cr := cost.Analyze(signals, g, an.Paths, cost.Options{Findings: fs})
			res.Cost = &cr
		}
	}
	if last, _ := st.LastScan(); last != nil {
		res.Summary = *last
	}
	res.Summary = summarize(res.Summary, fs, an.Paths)
	loadLifecycleViews(st, res)
	return res, st, nil
}

// dropEmptyRecords removes records that carry nothing a finding needs (no check id, canonical id,
// resource, file or title): a native `{}` / `[{}]` is not a finding (Verification 5 C5).
func dropEmptyRecords(fs []model.Finding) ([]model.Finding, int) {
	out := fs[:0:0]
	n := 0
	for _, f := range fs {
		canonical := f.CanonicalID
		if canonical == strings.ToUpper(f.Source)+":" { // Finalize's placeholder for no check id
			canonical = ""
		}
		if strings.TrimSpace(f.CheckID+canonical+f.Resource.ID+f.Resource.Name+f.File+f.Title) == "" {
			n++
			continue
		}
		out = append(out, f)
	}
	return out, n
}

// printScanSummary is the summary of a scan / ingest (W5-ISSUES item 2, r3 E4–E6): the Issue
// headline (store.Headline, the numbers every surface prints), then the findings as evidence,
// the top path Issue and where the database is. --no-store runs have no Issues: they print the
// path Issue count of the analysis and the findings.
func printScanSummary(w io.Writer, res *scanResult) {
	fails := 0
	byProv := map[string]int{}
	var gaps []string
	for _, f := range res.Findings {
		if output.IsScanGap(f) {
			gaps = append(gaps, firstNonEmpty(f.File, f.Resource.Name))
		}
		if f.Status != model.Fail {
			continue
		}
		fails++
		byProv[f.Provider]++
	}
	verb := firstNonEmpty(res.Verb, "Scan")
	fmt.Fprintf(w, "\n%s complete: %d open findings in %d results (scanner evidence).\n", verb, fails, len(res.Findings))
	if len(gaps) > 0 {
		fmt.Fprintf(w, "⚠ %d file(s) not scanned (they fail --fail-on): %s\n", len(gaps), strings.Join(gaps, ", "))
	}
	if h := res.Headline; h != nil {
		fmt.Fprintln(w, h.Text())
		if c := h.ClosureText(); c != "" {
			fmt.Fprintf(w, "Closed / pending: %s\n", c)
		}
	} else if res.Analysis != nil || len(res.Paths) > 0 {
		groups := pathGroupsOf(res)
		crit := 0
		for _, g := range groups {
			if g.Band == "Critical" {
				crit++
			}
		}
		fmt.Fprintf(w, "%d attack path Issues (%d hop variants), %d critical; finding Issues need the store (results not stored)\n", len(groups), len(res.Paths), crit)
	}
	var provs []string
	for p := range byProv {
		provs = append(provs, p)
	}
	sort.Strings(provs)
	var parts []string
	for _, p := range provs {
		parts = append(parts, fmt.Sprintf("%s=%d", p, byProv[p]))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "Findings by provider: %s\n", strings.Join(parts, "  "))
	}
	if top := topPathIssue(res); top != nil {
		fmt.Fprintf(w, "Attack paths: top Issue %s %.1f %s — %s (cloud-posture issues show %s)\n", top.ID, top.Score, top.Band, top.Title, top.ID)
	} else if len(res.Paths) > 0 {
		fmt.Fprintf(w, "Attack paths: top %s → %s, score %.1f\n", res.Paths[0].Name, res.Paths[0].Impact, res.Paths[0].Score)
	}
	if res.DBPath != "" {
		abs, err := filepath.Abs(res.DBPath)
		if err != nil {
			abs = res.DBPath
		}
		fmt.Fprintf(w, "Database: %s\n", abs)
	}
}

// topPathIssue is the open path Issue with the best score (nil when none is stored).
func topPathIssue(res *scanResult) *model.Issue {
	var best *model.Issue
	for i := range res.Issues {
		is := &res.Issues[i]
		if is.Kind != model.IssuePath || !model.IsActive(is.State) {
			continue
		}
		if best == nil || is.Score > best.Score {
			best = is
		}
	}
	return best
}

// pathGroupsOf is the path Issues of an in-memory analysis (no store).
func pathGroupsOf(res *scanResult) []attackpath.PathGroup {
	if res.Analysis != nil && len(res.Analysis.Paths) > 0 {
		return res.Analysis.Grouped()
	}
	return attackpath.GroupPaths(res.Paths)
}

// dashHeadline is the payload's headline (nil, i.e. JSON null, without a store).
func dashHeadline(res *scanResult) any {
	if res.Headline == nil {
		return nil
	}
	return res.Headline
}
