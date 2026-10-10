package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/integrations"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var reportFlags struct {
	framework, format, out, custom, account, provider, evidence string
	frameworkSet                                                string
}

// defaultFrameworkSet is the curated headline set `report --framework all` walks unless
// --framework-set says otherwise; the CIS benchmark of each provider in scope is added in front.
var defaultFrameworkSet = []string{"nist_800_53", "pci_dss", "soc2", "hipaa", "iso_27001", "gdpr"}

// resolveFrameworkSet turns --framework-set (default | all | comma list of keys/aliases) into
// framework keys. providers are the providers in scope (CIS benchmark selection and the cis alias).
func resolveFrameworkSet(spec string, providers []string, all map[string]*compliance.Framework) ([]string, error) {
	seenProv := map[string]bool{}
	var provs []string
	for _, p := range providers {
		if p != "" && !seenProv[p] {
			seenProv[p] = true
			provs = append(provs, p)
		}
	}
	sort.Strings(provs)
	var keys []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	switch s := strings.ToLower(strings.TrimSpace(spec)); s {
	case "", "default":
		for _, p := range provs {
			if k := compliance.ResolveKey("cis", p); all[k] != nil {
				add(k)
			}
		}
		for _, k := range defaultFrameworkSet {
			if all[k] != nil {
				add(k)
			}
		}
	case "all":
		for k := range all {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	default:
		var unknown []string
		for _, name := range strings.Split(s, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if name == "cis" && len(provs) > 0 { // the CIS benchmark of every provider in scope that has one
				found := false
				for _, p := range provs {
					if k := compliance.ResolveKey(name, p); all[k] != nil {
						add(k)
						found = true
					}
				}
				if !found {
					unknown = append(unknown, name)
				}
				continue
			}
			if k := compliance.ResolveKey(name, ""); all[k] != nil {
				add(k)
			} else {
				unknown = append(unknown, name)
			}
		}
		if len(unknown) > 0 {
			return nil, fmt.Errorf("--framework-set: unknown framework(s) %s (see `cloud-posture report --framework-set all` for every key)", strings.Join(unknown, ", "))
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("--framework-set: no frameworks named")
		}
	}
	return keys, nil
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Compliance-as-code: CIS, NIST 800-53, PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001 or a custom framework",
	Example: `  cloud-posture report --framework cis --provider aws
  cloud-posture report --framework soc2 --format html --out soc2.html      # audit-ready (Python layer)
  cloud-posture report --framework pci_dss --evidence-zip pci-evidence.zip
  cloud-posture report --framework custom --custom acme-baseline.yaml
  cloud-posture report --framework-set all                                 # every imported framework`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		fs, err := st.Findings(store.Filter{Account: reportFlags.account, Provider: reportFlags.provider})
		if err != nil {
			return err
		}
		key := compliance.ResolveKey(reportFlags.framework, reportFlags.provider)
		if reportFlags.custom != "" {
			data, err := os.ReadFile(reportFlags.custom)
			if err != nil {
				return err
			}
			fw, err := compliance.LoadCustom(data, fs)
			if err != nil {
				return err
			}
			key = fw.Key
			compliance.Frameworks()[key] = fw
		}
		multi := reportFlags.framework == "all" || reportFlags.framework == ""
		if reportFlags.frameworkSet != "" && !multi {
			return fmt.Errorf("--framework-set selects several frameworks; use it with --framework all (or omit --framework), not --framework %s", reportFlags.framework)
		}
		if multi {
			providers := []string{reportFlags.provider}
			if reportFlags.provider == "" {
				providers = nil
				for _, f := range fs {
					providers = append(providers, f.Provider)
				}
			}
			all := compliance.Frameworks()
			names, err := resolveFrameworkSet(reportFlags.frameworkSet, providers, all)
			if err != nil {
				return err
			}
			if reportFlags.frameworkSet == "" {
				fmt.Printf("%d of %d frameworks (framework-set default); use --framework-set all for every framework\n", len(names), len(all))
			} else {
				fmt.Printf("%d of %d frameworks (framework-set %s)\n", len(names), len(all), reportFlags.frameworkSet)
			}
			fmt.Println("Frameworks:", strings.Join(names, ", "))
			for _, k := range names {
				rep, _ := compliance.Build(k, fs, "")
				if rep != nil && rep.Passing+rep.Failing > 0 {
					fmt.Printf("  %-14s %5.1f%%  pass %d  fail %d  n/a %d\n", k, rep.ScorePercent, rep.Passing, rep.Failing, rep.NotAssessed)
				}
			}
			return nil
		}
		switch reportFlags.format {
		case "html", "pdf":
			exe := python(cfg)
			if exe == "" {
				return fmt.Errorf("html/pdf audit reports need the Python layer: pip install -e \"python[pdf]\"")
			}
			pyArgs := []string{"-m", "nimbus", "report", "--framework", key, "--format", reportFlags.format}
			if reportFlags.out != "" {
				abs, _ := filepath.Abs(reportFlags.out)
				pyArgs = append(pyArgs, "--out", abs)
			}
			if reportFlags.custom != "" {
				abs, _ := filepath.Abs(reportFlags.custom)
				pyArgs = append(pyArgs, "--custom", abs)
			}
			out, err := runPython(cmd.Context(), exe, []string{"CLOUD_POSTURE_DB=" + st.Path()}, pyArgs...)
			os.Stdout.Write(out)
			return err
		}
		rep, err := compliance.Build(key, fs, strings.TrimSpace(reportFlags.account+" "+reportFlags.provider))
		if err != nil {
			return err
		}
		if reportFlags.evidence != "" {
			last, _ := st.LastScan()
			meta := map[string]any{"scan": last, "db": st.Path()}
			if err := compliance.EvidenceZip(reportFlags.evidence, rep, fs, meta); err != nil {
				return err
			}
			logf("evidence package written to %s", reportFlags.evidence)
		}
		w := os.Stdout
		if reportFlags.out != "" {
			f, err := os.Create(reportFlags.out)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		if reportFlags.format == "json" {
			return output.JSON(w, rep)
		}
		fmt.Fprint(w, rep.Markdown())
		return nil
	},
}

// ---------------------------------------------------------------- alert

var alertFlags struct {
	to          []string
	minSeverity string
	dryRun      bool
	force       bool
	check       bool
	suppress    string
	noAutoClose bool
	onlyPaths   bool
	digest      bool
	since       string
	digestSink  string
}

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Send findings to Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk, Sentinel, ELK, webhooks or syslog",
	Example: `  cloud-posture alert --to slack,github_issues --min-severity HIGH
  cloud-posture alert --to pagerduty --only-attack-paths
  cloud-posture alert --check          # validate credentials (e.g. GitHub token)
  cloud-posture alert --suppress suppressions.json --dry-run
  cloud-posture alert --digest                     # per-owner governance digest (governance.digest.sink)
  cloud-posture alert --digest --digest-sink stdout --since 168h --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if alertFlags.digest {
			return runDigest(cmd.Context(), cfg, os.Stdout)
		}
		targets := sinksFromConfig(cfg, alertFlags.to)
		if len(targets) == 0 {
			return fmt.Errorf("no integrations configured (see cloud-posture.example.yaml)")
		}
		if alertFlags.check {
			for _, t := range targets {
				if gh, ok := t.Sink.(*integrations.GitHubIssues); ok {
					who, err := gh.Whoami(cmd.Context())
					if err != nil {
						fmt.Printf("✗ github: %v\n", err)
					} else {
						fmt.Printf("✓ github: authenticated as %s (repo %s)\n", who, gh.Repo)
					}
					continue
				}
				fmt.Printf("· %s: configured\n", t.Sink.Name())
			}
			return nil
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		fs, err := st.Findings(store.Filter{})
		if err != nil {
			return err
		}
		paths, _ := st.AttackPaths()
		opts := integrations.Options{DryRun: alertFlags.dryRun, Force: alertFlags.force, AutoClose: !alertFlags.noAutoClose}
		if alertFlags.suppress != "" {
			data, err := os.ReadFile(alertFlags.suppress)
			if err != nil {
				return err
			}
			if err := jsonUnmarshal(data, &opts.Suppressions); err != nil {
				return err
			}
		}
		for i := range targets {
			if alertFlags.minSeverity != "" {
				targets[i].Rule.MinSeverity = model.ParseSeverity(alertFlags.minSeverity)
			}
			if alertFlags.onlyPaths {
				targets[i].Rule.OnlyOnAttackPath = true
			}
		}
		// Jira and GitHub Issues hold one ticket per Issue (assignee from the governance owner,
		// due date from due_at); every other sink receives findings.
		var findingTargets []integrations.Target
		var ticketTargets []integrations.IssueTarget
		for _, t := range targets {
			if tk, ok := t.Sink.(integrations.IssueTicketer); ok {
				ticketTargets = append(ticketTargets, integrations.IssueTarget{Ticketer: tk, MinSeverity: t.Rule.MinSeverity})
				continue
			}
			findingTargets = append(findingTargets, t)
		}
		results := integrations.Dispatch(cmd.Context(), st, findingTargets, fs, paths, opts)
		if len(ticketTargets) > 0 {
			issues, err := st.Issues(store.IssueFilter{})
			if err != nil {
				return err
			}
			issues = alertableIssues(issues, paths, alertFlags.onlyPaths)
			results = append(results, integrations.DispatchIssues(cmd.Context(), st, ticketTargets, issues, integrations.IssueDispatchOptions{
				DryRun: alertFlags.dryRun, AutoClose: !alertFlags.noAutoClose,
				Evidence: func(is model.Issue) []model.Finding {
					var ev []model.Finding
					for _, id := range is.FindingIDs {
						if f, err := st.Finding(id); err == nil {
							f.Raw = nil
							ev = append(ev, *f)
						}
					}
					return ev
				},
				FixCommand: issueFixCommand,
			})...)
		}
		return reportDeliveries(os.Stdout, results)
	},
}

// sinkTally is one sink's delivery outcome.
type sinkTally struct{ sent, skipped, failed int }

// reportDeliveries prints each delivery, a per-sink summary and the total; it returns an
// error (non-zero exit) when any delivery failed.
func reportDeliveries(w io.Writer, results []integrations.Result) error {
	bySink := map[string]*sinkTally{}
	var names []string
	var total sinkTally
	for _, r := range results {
		t := bySink[r.Channel]
		if t == nil {
			t = &sinkTally{}
			bySink[r.Channel] = t
			names = append(names, r.Channel)
		}
		id := firstNonEmpty(r.IssueID, r.FindingID)
		if len(id) > 8 {
			id = id[:8]
		}
		switch {
		case r.Err != "":
			t.failed++
			total.failed++
			fmt.Fprintf(w, "✗ %s %s: %s\n", r.Channel, id, r.Err)
		case r.Skipped:
			t.skipped++
			total.skipped++
		default:
			t.sent++
			total.sent++
			fmt.Fprintf(w, "✓ %s %s → %s\n", r.Channel, id, r.Ref)
		}
	}
	sort.Strings(names)
	fmt.Fprintln(w, "per sink:")
	for _, n := range names {
		t := bySink[n]
		fmt.Fprintf(w, "  %s: sent %d · skipped %d · failed %d\n", n, t.sent, t.skipped, t.failed)
	}
	fmt.Fprintf(w, "sent %d · skipped %d (already alerted / suppressed / dry-run) · failed %d\n", total.sent, total.skipped, total.failed)
	if total.failed > 0 && total.sent == 0 {
		return fmt.Errorf("alert: every delivery failed (%d of %d attempted)", total.failed, total.failed)
	}
	// Any failed delivery is a non-zero exit (a dead sink must not hide behind a working one);
	// failed deliveries are retried on the next run.
	var failing []string
	for _, n := range names {
		if t := bySink[n]; t.failed > 0 {
			failing = append(failing, fmt.Sprintf("%s (%d failed, %d sent)", n, t.failed, t.sent))
		}
	}
	if len(failing) > 0 {
		return fmt.Errorf("alert: delivery failed for %s", strings.Join(failing, ", "))
	}
	return nil
}

// ---------------------------------------------------------------- prioritize

var prioritizeFlags struct {
	top     int
	json    bool
	owner   string
	explain bool
}

var prioritizeCmd = &cobra.Command{
	Use:   "prioritize",
	Short: "Context-aware risk ranking: the top findings that actually matter, with reasons, owner and SLA",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		res, st, err := loadResult(ctx, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		all := rankAll(ctx, cfg, res.Findings, res.Graph, res.Paths, res.Analysis)
		// The ranking is the verdict Issue severities derive from; the traversal here covers
		// the full stored graph, so path Issues are rebuilt over every account in it.
		if _, err := rebuildIssueViews(st, "prioritize", all, res.Analysis, observedScope(graphAccounts(res.Graph), res.Graph), time.Now().UTC()); err != nil {
			logf("issues: %v", err)
		}
		governIssueViews(cfg, st, res.Graph)
		governStoredRanked(st, all)
		if err := writeRiskJSON(st, all); err != nil {
			logf("risk.json: %v", err)
		}
		ranked := topN(all, prioritizeFlags.top)
		if prioritizeFlags.owner != "" {
			var f []risk.Ranked
			for _, r := range ranked {
				if strings.EqualFold(r.Owner, prioritizeFlags.owner) {
					f = append(f, r)
				}
			}
			ranked = f
		}
		if prioritizeFlags.json {
			return output.JSON(os.Stdout, ranked)
		}
		fmt.Printf("Top %d findings by risk score (score 0–10, score_version %s; bands Critical ≥9, High ≥7, Medium ≥5, Low <5 — docs/scoring.md; `issues` lists Issues)\n\n", len(ranked), risk.ScoreVersion)
		for i, r := range ranked {
			// Owner and due date are the governance assignment of the finding's Issue.
			due := "no SLA"
			if !r.DueAt.IsZero() {
				due = "due " + r.DueAt.Format("2006-01-02")
				if time.Now().After(r.DueAt) {
					due += " OVERDUE"
				}
			}
			fmt.Printf("%2d. %4.1f %-8s %-28s %s\n      %s · owner: %s · %s · paths: %d\n      why: %s\n", i+1, r.Score, r.Band, r.Finding.CanonicalID, r.Finding.Resource.Name, r.Finding.Provider+"/"+r.Finding.Account, firstNonEmpty(r.Owner, "— (unassigned)"), due, r.AttackPaths, strings.Join(r.Reasons, "; "))
			if prioritizeFlags.explain {
				printExplanation(os.Stdout, risk.Explain(r))
			}
		}
		return nil
	},
}

// printExplanation prints the factor table of one score (risk.Explain): base × Π multipliers = score.
func printExplanation(w io.Writer, e risk.Explanation) {
	fmt.Fprintf(w, "      %-22s %-8s %-11s %s\n", "factor", "×mult", "status", "reason")
	fmt.Fprintf(w, "      %-22s %-8s %-11s %s\n", "base", fmt.Sprintf("%.2f", e.Base), "scored", e.BaseReason)
	for _, f := range e.Factors {
		reason := f.Reason
		if len(f.Evidence) > 0 {
			reason += " [" + strings.Join(f.Evidence, "; ") + "]"
		}
		fmt.Fprintf(w, "      %-22s %-8s %-11s %s\n", f.Name, fmt.Sprintf("×%.2f", f.Multiplier), f.Status, reason)
	}
	fmt.Fprintf(w, "      = %.1f (raw %.2f, score_version %s)\n", e.Score, e.Raw, e.Version)
	for _, p := range e.TopPaths {
		fmt.Fprintf(w, "      path %s %.1f %s\n", p.ID, p.Score, p.Name)
	}
	if len(e.Missing) > 0 {
		fmt.Fprintf(w, "      not scored: %s\n", strings.Join(e.Missing, "; "))
	}
	fmt.Fprintln(w)
}

func init() {
	reportCmd.Flags().StringVar(&reportFlags.framework, "framework", "all", "cis|nist|pci|soc2|hipaa|gdpr|iso|<key>|all|custom")
	reportCmd.Flags().StringVar(&reportFlags.frameworkSet, "framework-set", "", "with --framework all: default (CIS for the providers in scope + NIST 800-53, PCI DSS, SOC 2, HIPAA, ISO 27001, GDPR) | all | comma list of keys")
	reportCmd.Flags().StringVar(&reportFlags.format, "format", "md", "md|json|html|pdf")
	reportCmd.Flags().StringVar(&reportFlags.out, "out", "", "output file")
	reportCmd.Flags().StringVar(&reportFlags.custom, "custom", "", "custom framework YAML")
	reportCmd.Flags().StringVar(&reportFlags.account, "account", "", "limit to an account")
	reportCmd.Flags().StringVar(&reportFlags.provider, "provider", "", "limit to a provider (also selects the CIS benchmark)")
	reportCmd.Flags().StringVar(&reportFlags.evidence, "evidence-zip", "", "write an auditor evidence package (per-control evidence + SHA-256 manifest)")
	alertCmd.Flags().StringSliceVar(&alertFlags.to, "to", nil, "integration names from config (default: all enabled)")
	alertCmd.Flags().StringVar(&alertFlags.minSeverity, "min-severity", "", "override minimum severity")
	alertCmd.Flags().BoolVar(&alertFlags.dryRun, "dry-run", false, "show what would be sent")
	alertCmd.Flags().BoolVar(&alertFlags.force, "force", false, "resend even if already alerted")
	alertCmd.Flags().BoolVar(&alertFlags.check, "check", false, "validate integration credentials")
	alertCmd.Flags().StringVar(&alertFlags.suppress, "suppress", "", "JSON file of suppressions [{canonical_id|finding_id|resource_id, reason, expires_at}]")
	alertCmd.Flags().BoolVar(&alertFlags.noAutoClose, "no-auto-close", false, "do not close tickets for findings that now pass")
	alertCmd.Flags().BoolVar(&alertFlags.onlyPaths, "only-attack-paths", false, "only findings that sit on an attack path")
	alertCmd.Flags().BoolVar(&alertFlags.digest, "digest", false, "send the per-owner governance digest (overdue, open critical/high, resolved this period) instead of alerts")
	alertCmd.Flags().StringVar(&alertFlags.since, "since", "", "digest period start: a duration back from now (168h, 7d) or a date (default: the digest schedule period)")
	alertCmd.Flags().StringVar(&alertFlags.digestSink, "digest-sink", "", "override governance.digest.sink: slack | stdout")
	prioritizeCmd.Flags().IntVar(&prioritizeFlags.top, "top", 50, "how many (0 = all)")
	prioritizeCmd.Flags().BoolVar(&prioritizeFlags.json, "json", false, "JSON output")
	prioritizeCmd.Flags().StringVar(&prioritizeFlags.owner, "owner", "", "filter by governance owner (the owner of the finding's Issue)")
	prioritizeCmd.Flags().BoolVar(&prioritizeFlags.explain, "explain", false, "print each score's factor table (base × multipliers = score)")
	root.AddCommand(reportCmd, alertCmd, prioritizeCmd)
}
