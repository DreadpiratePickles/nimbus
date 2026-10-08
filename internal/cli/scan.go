package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var scanFlags struct {
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
}

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
	f.StringVarP(&scanFlags.out, "output", "o", "table", "table|json|sarif|dashboard|markdown|summary")
	f.StringVar(&scanFlags.outFile, "out-file", "", "write the output to a file (dashboard default: cloud-posture-report/index.html)")
	f.StringVar(&scanFlags.sarif, "sarif", "", "also write SARIF to this path")
	f.StringVar(&scanFlags.failOn, "fail-on", "", "exit 2 when open findings at or above this severity exist")
	f.BoolVar(&scanFlags.noStore, "no-store", false, "do not persist to the posture database")
	f.BoolVar(&scanFlags.changedOnly, "changed-only", false, "IaC: only files staged/changed in git")
	f.BoolVar(&scanFlags.alert, "alert", false, "dispatch new findings to configured integrations after the scan")
	f.BoolVar(&scanFlags.noNative, "no-native", false, "skip the built-in SDK collectors")
	f.IntVar(&scanFlags.limit, "limit", 60, "rows for table output (0 = all)")
	f.DurationVar(&scanFlags.timeout, "timeout", 45*time.Minute, "per-tool timeout")
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
	sopts := scanner.Options{WorkDir: work, Timeout: scanFlags.timeout, Logf: logf, Python: python(cfg)}

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
			cg, res := collector.RunAll(ctx, specs, collector.Options{Concurrency: max(cfg.Scan.Parallel, 1), OnAccount: func(spec collector.AccountSpec, r collector.Result, err error) {
				if err != nil {
					logf("  ✗ %s: %v", spec.Label(), err)
				} else {
					logf("  ✓ %s: %d findings", spec.Label(), len(r.Findings))
				}
			}})
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
			for _, e := range res.Errors {
				sum.Tools = append(sum.Tools, model.ToolRun{Tool: "native", Status: "failed", Message: e.Error()})
			}
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
		fs, err := iac.ScanTerraform(p, now)
		if err != nil {
			logf("iac %s: %v", p, err)
		}
		if scanFlags.changedOnly {
			fs = filterChanged(fs, p)
		}
		for i := range fs {
			fs[i].ScanID = scanID
		}
		adapters.Finalize(fs, adapters.Options{Now: now, Account: "iac"})
		all = append(all, fs...)
		sum.Tools = append(sum.Tools, model.ToolRun{Tool: "nimbus-iac", Account: p, Status: "ok", Findings: len(fs)})
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

	all = dedupe(all)
	res, err := finishScan(ctx, cfg, all, g, signals, sum, scanFlags.noStore)
	if err != nil {
		return err
	}
	if err := emit(res, scanFlags.out, scanFlags.outFile, scanFlags.sarif, scanFlags.limit); err != nil {
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
	return failOn(res.Findings, scanFlags.failOn)
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
	g.AttachFindings(all)
	res := &scanResult{Findings: all, Graph: g, Summary: sum}
	rules, _ := attackpath.LoadRules(nil)
	if noStore {
		rulePaths := attackpath.Evaluate(all, rules)
		opts := attackpath.DefaultTraversalOptions()
		opts.CrownJewels = crownJewels(cfg)
		an := attackpath.Traverse(g, opts)
		an.Paths = attackpath.Merge(an.Paths, rulePaths)
		res.Paths, res.Analysis = an.Paths, an
		res.Risk = risk.Prioritize(all, g, res.Paths, risk.DefaultWeights, 50, time.Now())
		res.Summary = summarize(res.Summary, all, res.Paths)
		return res, nil
	}
	st, err := openStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := st.UpsertFindings(all); err != nil {
		return nil, err
	}
	// Findings from earlier scans still count for the graph and paths.
	stored, err := st.Findings(store.Filter{})
	if err != nil {
		return nil, err
	}
	g.AttachFindings(stored)
	if err := saveGraph(st, g); err != nil {
		return nil, err
	}
	paths, an, err := analyze(st, g, stored, cfg, sum.ScanID)
	if err != nil {
		return nil, err
	}
	res.Findings, res.Paths, res.Analysis = stored, paths, an
	res.Risk = prioritizeBest(ctx, cfg, st, stored, g, paths, 50)
	if len(signals) > 0 {
		cr := cost.Analyze(signals, g, paths, cost.Options{Findings: stored})
		res.Cost = &cr
		data, _ := json.Marshal(signals)
		os.MkdirAll(".cloud-posture", 0o755)
		os.WriteFile(filepath.Join(".cloud-posture", "cost-signals.json"), data, 0o644)
		if cj, err := cr.JSON(); err == nil {
			os.WriteFile(filepath.Join(".cloud-posture", "cost-report.json"), cj, 0o644)
		}
	}
	res.Summary = summarize(res.Summary, stored, paths)
	res.Summary.FinishedAt = time.Now().UTC()
	if err := st.SaveScan(res.Summary); err != nil {
		return nil, err
	}
	return res, nil
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

// prioritizeBest uses the Python model when available, else the Go formula.
func prioritizeBest(ctx context.Context, cfg *config.Config, st *store.Store, fs []model.Finding, g *graph.Graph, paths []model.AttackPath, top int) []risk.Ranked {
	ranked := risk.Prioritize(fs, g, paths, risk.DefaultWeights, 0, time.Now())
	if exe := python(cfg); exe != "" && st != nil {
		out, err := runPython(ctx, exe, []string{"CLOUD_POSTURE_DB=" + st.Path()}, "-m", "nimbus.risk", "--db", st.Path(), "--top", fmt.Sprint(max(top, 1)), "--json")
		if err == nil {
			var py []struct {
				FindingID string   `json:"finding_id"`
				Score     float64  `json:"risk_score"`
				Reasons   []string `json:"reasons"`
			}
			if json.Unmarshal(out, &py) == nil && len(py) > 0 {
				byID := map[string]risk.Ranked{}
				for _, r := range ranked {
					byID[r.Finding.ID] = r
				}
				var merged []risk.Ranked
				for _, p := range py {
					r, ok := byID[p.FindingID]
					if !ok {
						continue
					}
					r.Score = float64(int(p.Score))/10 // python scores 0-100 → 1-10 band scale
					if r.Score < 1 {
						r.Score = 1
					}
					if len(p.Reasons) > 0 {
						r.Reasons = p.Reasons
					}
					merged = append(merged, r)
				}
				if len(merged) > 0 {
					return merged
				}
			}
		}
	}
	if top > 0 && len(ranked) > top {
		ranked = ranked[:top]
	}
	return ranked
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
		return output.JSON(w, map[string]any{"scan": res.Summary, "findings": res.Findings, "attack_paths": res.Paths, "analysis": res.Analysis, "risk": res.Risk, "cost": res.Cost})
	case "sarif":
		return output.JSON(w, output.SARIF(res.Findings))
	case "markdown", "md":
		fmt.Fprint(w, output.PRMarkdown(res.Findings, res.Paths, 30))
		return nil
	case "summary":
		output.Summary(w, res.Findings, res.Paths)
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
		output.Summary(os.Stdout, res.Findings, res.Paths)
		abs, _ := filepath.Abs(path)
		fmt.Printf("\nView dashboard: file://%s\nLive mode:      cloud-posture serve\n", abs)
		return nil
	default:
		var fails []model.Finding
		for _, f := range res.Findings {
			if f.Status == model.Fail {
				fails = append(fails, f)
			}
		}
		output.Table(w, fails, limit)
		output.Summary(w, res.Findings, res.Paths)
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
			fmt.Fprintf(w, "\nTop risk: %.1f %s — %s on %s (%s)\n", res.Risk[0].Score, res.Risk[0].Band, res.Risk[0].Finding.CanonicalID, res.Risk[0].Finding.Resource.Name, strings.Join(res.Risk[0].Reasons, "; "))
		}
		if res.Cost != nil {
			fmt.Fprintln(w)
			fmt.Fprint(w, res.Cost.Text())
		}
		return nil
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
	return dashboard.Render(dashboard.Data{Mode: mode, Accounts: sum.Accounts, Findings: res.Findings, Paths: res.Paths, Analysis: res.Analysis, Graph: gj, Risk: res.Risk, Compliance: reports, Cost: costAny, Scan: &sum, CopilotURL: copilot})
}

func failOn(fs []model.Finding, sev string) error {
	if sev == "" {
		return nil
	}
	min := model.ParseSeverity(sev)
	n := 0
	for _, f := range fs {
		if f.Status == model.Fail && f.Severity.Rank() >= min.Rank() {
			n++
		}
	}
	if n > 0 {
		fmt.Fprintf(os.Stderr, "✗ %d open finding(s) at or above %s\n", n, min)
		os.Exit(2)
	}
	return nil
}

// ---------------------------------------------------------------- ingest

var ingestFlags struct {
	source, account string
	out             string
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
		if len(all) == 0 {
			return fmt.Errorf("no findings parsed (use --source to force a format)")
		}
		res, err := finishScan(ctx, cfg, dedupe(all), graph.New(), nil, sum, false)
		if err != nil {
			return err
		}
		return emit(res, ingestFlags.out, "", "", 40)
	},
}

func init() {
	ingestCmd.Flags().StringVar(&ingestFlags.source, "source", "", "force adapter: prowler|scoutsuite|checkov|trivy|steampipe|native")
	ingestCmd.Flags().StringVar(&ingestFlags.account, "account", "", "account label to attach")
	ingestCmd.Flags().StringVarP(&ingestFlags.out, "output", "o", "summary", "table|json|summary|dashboard")
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
	opts := attackpath.DefaultTraversalOptions()
	opts.CrownJewels = crownJewels(cfg)
	an := attackpath.Traverse(g, opts)
	an.Paths = attackpath.Merge(an.Paths, paths)
	res := &scanResult{Findings: fs, Graph: g, Paths: an.Paths, Analysis: an}
	res.Risk = prioritizeBest(ctx, cfg, st, fs, g, an.Paths, 50)
	if data, err := os.ReadFile(filepath.Join(".cloud-posture", "cost-signals.json")); err == nil {
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
	return res, st, nil
}
