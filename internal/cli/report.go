package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Compliance-as-code: CIS, NIST 800-53, PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001 or a custom framework",
	Example: `  cloud-posture report --framework cis --provider aws
  cloud-posture report --framework soc2 --format html --out soc2.html      # audit-ready (Python layer)
  cloud-posture report --framework pci_dss --evidence-zip pci-evidence.zip
  cloud-posture report --framework custom --custom acme-baseline.yaml`,
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
		if reportFlags.framework == "all" || reportFlags.framework == "" {
			var names []string
			for k := range compliance.Frameworks() {
				names = append(names, k)
			}
			fmt.Println("Frameworks:", strings.Join(names, ", "))
			for _, k := range names {
				rep, _ := compliance.Build(k, fs, "")
				if rep.Passing+rep.Failing > 0 {
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
}

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Send findings to Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk, Sentinel, ELK, webhooks or syslog",
	Example: `  cloud-posture alert --to slack,github_issues --min-severity HIGH
  cloud-posture alert --to pagerduty --only-attack-paths
  cloud-posture alert --check          # validate credentials (e.g. GitHub token)
  cloud-posture alert --suppress suppressions.json --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
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
		results := integrations.Dispatch(cmd.Context(), st, targets, fs, paths, opts)
		sent, skipped, failed := 0, 0, 0
		for _, r := range results {
			switch {
			case r.Err != "":
				failed++
				fmt.Printf("✗ %s %s: %s\n", r.Channel, r.FindingID[:8], r.Err)
			case r.Skipped:
				skipped++
			default:
				sent++
				fmt.Printf("✓ %s %s → %s\n", r.Channel, r.FindingID[:8], r.Ref)
			}
		}
		fmt.Printf("sent %d · skipped %d (already alerted / suppressed / dry-run) · failed %d\n", sent, skipped, failed)
		return nil
	},
}

// ---------------------------------------------------------------- prioritize

var prioritizeFlags struct {
	top   int
	json  bool
	owner string
}

var prioritizeCmd = &cobra.Command{
	Use:   "prioritize",
	Short: "Context-aware risk ranking: the top findings that actually matter, with reasons, owner and SLA",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		res, st, err := loadResult(context.Background(), cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		ranked := res.Risk
		if prioritizeFlags.top > 0 && len(ranked) > prioritizeFlags.top {
			ranked = ranked[:prioritizeFlags.top]
		}
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
		fmt.Printf("Top %d risks (score 1–10; Critical ≥9, High ≥7, Medium ≥4)\n\n", len(ranked))
		for i, r := range ranked {
			due := r.DueAt.Format("2006-01-02")
			overdue := ""
			if time.Now().After(r.DueAt) {
				overdue = " OVERDUE"
			}
			fmt.Printf("%2d. %4.1f %-8s %-28s %s\n      %s · owner: %s · SLA %s%s · paths: %d\n      why: %s\n", i+1, r.Score, r.Band, r.Finding.CanonicalID, r.Finding.Resource.Name, r.Finding.Provider+"/"+r.Finding.Account, firstNonEmpty(r.Owner, "— (orphaned)"), due, overdue, r.AttackPaths, strings.Join(r.Reasons, "; "))
		}
		return nil
	},
}

func init() {
	reportCmd.Flags().StringVar(&reportFlags.framework, "framework", "all", "cis|nist|pci|soc2|hipaa|gdpr|iso|<key>|all|custom")
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
	prioritizeCmd.Flags().IntVar(&prioritizeFlags.top, "top", 50, "how many")
	prioritizeCmd.Flags().BoolVar(&prioritizeFlags.json, "json", false, "JSON output")
	prioritizeCmd.Flags().StringVar(&prioritizeFlags.owner, "owner", "", "filter by owner tag")
	root.AddCommand(reportCmd, alertCmd, prioritizeCmd)
}
