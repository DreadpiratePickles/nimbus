package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/devx"
	"github.com/DreadpiratePickles/nimbus/internal/gitops"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var onboardFlags struct {
	providers   []string
	yes         bool
	scan        bool
	awsOrg      string
	externalID  string
	out         string
	deployRole  bool
	deploy      bool
	trusted     string
	orgOUs      []string
	regions     []string
	profile     string
	manifestDir string
}

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "One-command onboarding: detect AWS/Azure/GCP/Kubernetes/GitHub/Okta/M365 credentials, write config, run the first scan",
	Example: `  cloud-posture onboard
  cloud-posture onboard --aws --azure --gcp --yes --scan
  cloud-posture onboard --aws-org 123456789012 --external-id my-secret   # print the org-wide StackSet template`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if onboardFlags.deployRole || (onboardFlags.awsOrg != "" && onboardFlags.deploy) {
			// Creates cloud resources and records each one in .cloud-posture/onboard-<account>.json
			// so `offboard --rollback` can remove exactly what was created.
			return runOnboardDeploy(cmd.Context())
		}
		if onboardFlags.awsOrg != "" {
			fmt.Print(devx.AWSOrgStackSet(onboardFlags.awsOrg, firstNonEmpty(onboardFlags.externalID, "cloud-posture")))
			fmt.Fprintln(os.Stderr, "\nDeploy: aws cloudformation create-stack-set --stack-set-name cloud-posture --template-body file://stackset.yaml --capabilities CAPABILITY_NAMED_IAM && aws cloudformation create-stack-instances --stack-set-name cloud-posture --deployment-targets OrganizationalUnitIds=<root-ou> --regions us-east-1")
			return nil
		}
		want := map[string]bool{}
		for _, p := range onboardFlags.providers {
			want[strings.ToLower(p)] = true
		}
		fmt.Println("Detecting cloud credentials (read-only, agentless)…")
		found := detectCredentials(context.Background(), want)
		cfg, _ := config.Load(flagConfig)
		added := 0
		for _, d := range found {
			if d.Err != "" {
				fmt.Printf("  ✗ %-10s %s\n", d.Provider, d.Err)
				continue
			}
			fmt.Printf("  ✓ %-10s %s %s\n", d.Provider, d.Detail, d.Identity)
			if !onboardFlags.yes {
				fmt.Printf("    add as %q? [Y/n] ", d.Account.Name)
				line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				if l := strings.ToLower(strings.TrimSpace(line)); l == "n" || l == "no" {
					continue
				}
			}
			a := d.Account
			cfg.Accounts[a.Name] = &a
			added++
		}
		if added == 0 && len(cfg.Accounts) == 0 {
			fmt.Println("\nNothing detected. Log in first (aws sso login / az login / gcloud auth login / kubectl) or set GITHUB_TOKEN, OKTA_ORG_URL+OKTA_API_TOKEN, M365_TENANT_ID.")
			return nil
		}
		out := firstNonEmpty(onboardFlags.out, flagConfig, config.DefaultFile)
		// Ownership out of the box: a starter governance block from owner/team tags already in
		// the posture database (if any) and the repository's CODEOWNERS.
		var gst *store.Store
		if _, err := os.Stat(firstNonEmpty(flagDB, store.DefaultPath())); err == nil {
			if s, err := openStore(); err == nil {
				gst = s
			}
		}
		if onboardGovernance(cfg, ".", gst) {
			fmt.Printf("  + starter governance block (%d rule(s)); refine later with `cloud-posture governance init`\n", len(cfg.Governance.Rules))
		}
		if gst != nil {
			gst.Close()
		}
		if err := cfg.Save(out); err != nil {
			return err
		}
		fmt.Printf("\n✓ wrote %s with %d account(s)\n", out, len(cfg.Accounts))
		avail := scannerAvailable()
		fmt.Printf("  external scanners available: %s\n", strings.Join(avail, ", "))
		if onboardFlags.scan {
			fmt.Println("\nStarting scan… (Ctrl+C to stop)")
			scanFlags.out = "dashboard"
			flagConfig = out
			return runScan(scanCmd, nil)
		}
		fmt.Println("\nNext: cloud-posture scan --output dashboard   # then cloud-posture serve")
		return nil
	},
}

// discoverAWS finds AWS credentials through the SDK default chain (env, shared profiles, SSO
// cache, web identity, container / instance metadata) with one read-only STS call each —
// no `aws` CLI needed (delta r3 #13). A variable so tests use a fake.
var discoverAWS = func(ctx context.Context) []awscol.DiscoveredIdentity {
	return awscol.CredentialDiscovery{}.Discover(ctx)
}

// detectCredentials is onboard's detection: AWS through the SDK chain, the other providers
// through devx.Detect (az / gcloud device-flow logins still need their CLIs).
func detectCredentials(ctx context.Context, want map[string]bool) []devx.Detected {
	var out []devx.Detected
	if noNetwork() {
		// Detection is an STS call per AWS credential source and az / gcloud / kubectl / SaaS
		// token checks: all network (r4 #14 / N7). Say so instead of making them.
		for _, p := range []string{"aws", "azure", "gcp", "kubernetes", "github", "okta", "m365"} {
			if len(want) == 0 || want[p] {
				out = append(out, devx.Detected{Provider: p, Err: "skipped (no-network): detection calls the provider; rerun without --no-network / CLOUD_POSTURE_NO_NETWORK"})
			}
		}
		return out
	}
	if len(want) == 0 || want["aws"] {
		for _, id := range discoverAWS(ctx) {
			out = append(out, awsDetected(id))
		}
	}
	others := map[string]bool{}
	for _, p := range []string{"azure", "gcp", "kubernetes", "github", "okta", "m365"} {
		if len(want) == 0 || want[p] {
			others[p] = true
		}
	}
	if len(others) > 0 {
		out = append(out, devx.Detect(ctx, others)...)
	}
	return out
}

func awsDetected(id awscol.DiscoveredIdentity) devx.Detected {
	d := devx.Detected{Provider: "aws", Account: config.Account{Provider: "aws", Profile: id.Profile, Tools: []string{"native", "python-checks", "prowler", "steampipe"}}}
	prof := ""
	if id.Profile != "" {
		prof = " (profile " + id.Profile + ")"
	}
	if id.Err != "" {
		d.Err = strings.TrimSpace(strings.TrimPrefix(prof, " ") + " " + id.Err)
		return d
	}
	d.Identity = id.Arn
	d.Detail = fmt.Sprintf("account %s via %s%s", id.Account, id.Source, prof)
	d.Account.Name = "aws-" + firstNonEmpty(id.Profile, id.Account)
	return d
}

func scannerAvailable() []string {
	var out []string
	for _, t := range []string{"prowler", "scout", "checkov", "trivy", "steampipe", "powerpipe"} {
		if _, err := lookPath(t); err == nil {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		out = []string{"none (native collectors + python checks only)"}
	}
	return out
}

var learnCmd = &cobra.Command{
	Use:   "learn [lesson]",
	Short: "Interactive tutorial: learn cloud security by fixing real issues in your own accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		fs, _ := st.Findings(store.Filter{Status: "FAIL"})
		picked := devx.Pick(fs)
		if len(args) == 0 {
			if len(picked) == 0 {
				fmt.Println("No open findings yet — run `cloud-posture scan` first. Lessons available:")
				for _, l := range devx.Lessons {
					fmt.Printf("  %-16s %s\n", l.ID, l.Title)
				}
				return nil
			}
			fmt.Println("Lessons that apply to YOUR environment (most severe first):")
			for i, p := range picked {
				fmt.Printf("  %d. %-16s %s — %d finding(s), e.g. %s\n", i+1, p.Lesson.ID, p.Lesson.Title, len(p.Examples), p.Examples[0].Resource.Name)
			}
			fmt.Println("\nStart one: cloud-posture learn <lesson>")
			return nil
		}
		for _, l := range devx.Lessons {
			if l.ID != args[0] {
				continue
			}
			fmt.Printf("# %s\n\n%s\n\n## How attackers use it (%s)\n%s\n", l.Title, l.Explain, l.Mitre, l.Exploit)
			var ex []model.Finding
			for _, p := range picked {
				if p.Lesson.ID == l.ID {
					ex = p.Examples
				}
			}
			if len(ex) > 0 {
				fmt.Printf("\n## In your environment (%d)\n", len(ex))
				for i, f := range ex {
					if i >= 5 {
						break
					}
					fmt.Printf("- [%s] %s — %s/%s\n", f.Severity, f.Resource.Name, f.Provider, f.Account)
				}
				fix, err := remediation.Generate(ex[0], remediation.Terraform)
				if err == nil && !fix.Generic {
					fmt.Printf("\n## Fix for %s (Terraform)\n```hcl\n%s```\n", ex[0].Resource.Name, fix.Content)
				}
			}
			fmt.Printf("\n## Fix\n%s\n\n## Verify\n%s\n", l.Fix, l.Verify)
			return nil
		}
		return fmt.Errorf("unknown lesson %q", args[0])
	},
}

var hookCmd = &cobra.Command{Use: "hook", Short: "Pre-commit hook that blocks risky IaC changes"}
var hookInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install .git/hooks/pre-commit (or print .pre-commit-hooks.yaml with --pre-commit-config)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if pc, _ := cmd.Flags().GetBool("pre-commit-config"); pc {
			fmt.Print(devx.PreCommitHooksYAML)
			return nil
		}
		path, err := devx.InstallGitHook(".")
		if err != nil {
			return err
		}
		fmt.Printf("✓ installed %s\n", path)
		return nil
	},
}

var actionCmd = &cobra.Command{Use: "action", Short: "GitHub Actions integration"}
var actionInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write .github/workflows/cloud-posture.yml (scan on PRs, SARIF upload, sticky PR comment, daily schedule)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path := filepath.Join(".github", "workflows", "cloud-posture.yml")
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(devx.GitHubWorkflow), 0o644); err != nil {
			return err
		}
		fmt.Printf("✓ wrote %s\n", path)
		return nil
	},
}

var prFlags struct {
	results string
	repo    string
	pr      int
	max     int
}

var prCommentCmd = &cobra.Command{
	Use:   "pr-comment",
	Short: "Post (or update) a sticky PR comment with scan results, newly opened attack paths and fix commands",
	Long: `Post (or update) a sticky PR comment.

With --results: the scan's findings and attack paths (cloud-posture scan --output json).
With --plan-json: the plan-time attack-path diff — "this PR opens N / closes M attack paths" —
from ` + "`terraform show -json`" + ` / ` + "`tofu show -json`" + ` of a saved plan, overlaid on the scan DB's live graph
when one exists (confidence inferred) or on the plan alone (confidence hint). See docs/plan-diff.md.`,
	Example: `  terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
  cloud-posture pr-comment --plan-json plan.json                      # print the comment
  cloud-posture pr-comment --plan-json plan.json --repo o/r --pr 12 --sarif paths.sarif --fail-on-opened`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if planCommentFlags.planJSON != "" {
			return runPlanComment(cmd)
		}
		data, err := os.ReadFile(prFlags.results)
		if err != nil {
			return err
		}
		var doc struct {
			Findings    []model.Finding    `json:"findings"`
			AttackPaths []model.AttackPath `json:"attack_paths"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
		body := output.PRMarkdown(doc.Findings, doc.AttackPaths, prFlags.max)
		if prFlags.repo == "" || prFlags.pr == 0 {
			fmt.Print(body)
			return nil
		}
		if err := gitops.PostPRComment(cmd.Context(), prFlags.repo, prFlags.pr, os.Getenv("GITHUB_TOKEN"), body); err != nil {
			return err
		}
		fmt.Printf("✓ commented on %s#%d\n", prFlags.repo, prFlags.pr)
		return nil
	},
}

var catalogCmd = &cobra.Command{
	Use:   "catalog [ID]",
	Short: "List canonical checks, their tool aliases, weaknesses, compliance mappings and available fix templates",
	RunE: func(cmd *cobra.Command, args []string) error {
		cat := catalog.Default()
		if len(args) == 1 {
			e, ok := cat.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown %s", args[0])
			}
			return output.JSON(os.Stdout, map[string]any{"entry": e, "remediation_formats": remediation.Formats(e.ID)})
		}
		fmt.Printf("%-32s %-10s %-8s %s\n", "ID", "PROVIDER", "SEV", "TITLE")
		for _, id := range cat.IDs() {
			e, _ := cat.Get(id)
			fmt.Printf("%-32s %-10s %-8s %s\n", id, e.Provider, e.Severity, e.Title)
		}
		fmt.Printf("\n%d canonical checks · native IaC rules: %d\n", len(cat.IDs()), len(iac.Rules()))
		return nil
	},
}

var catalogUnmappedFlags struct {
	tool   string
	from   []string
	format string
	golden bool
}

// catalogUnmappedCmd reports catalog coverage of a scanner: which native check ids have no canonical
// id (shortfall #15). Default corpus: the stored database's findings of that scanner; --from scores
// scanner files, --golden the lab IaC golden (lab/golden/expectations.yaml).
var catalogUnmappedCmd = &cobra.Command{
	Use:   "unmapped --tool checkov|trivy [--from <scanner json> | --golden] [--format text|json]",
	Short: "List a scanner's check ids with no canonical mapping, with counts and the mapped percentage",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		f := catalogUnmappedFlags
		tool := strings.ToLower(f.tool)
		if tool != "checkov" && tool != "trivy" {
			return fmt.Errorf("--tool must be checkov or trivy (got %q)", f.tool)
		}
		if f.format != "text" && f.format != "json" {
			return fmt.Errorf("--format must be text or json (got %q)", f.format)
		}
		files, version := f.from, ""
		var r adapters.MappingReport
		src := "scanner output"
		switch {
		case f.golden:
			repo, err := adapters.FindGoldenRoot(".")
			if err != nil {
				return err
			}
			if files, version, err = adapters.GoldenInputs(repo, tool); err != nil {
				return err
			}
			src = "lab golden " + version
		case len(files) == 0:
			// Default: the stored database's FAIL findings of that scanner, re-mapped with the
			// current catalog — works anywhere, not only inside the repository (r4 N10).
			fs, err := storedFindingsOf(tool)
			if err != nil {
				return err
			}
			if len(fs) == 0 {
				return fmt.Errorf("the database (%s) has no %s FAIL findings: ingest %s output first, or pass --from <%s json> or --golden (the repository's lab goldens)",
					firstNonEmpty(flagDB, store.DefaultPath()), tool, tool, tool)
			}
			r = adapters.CoverageOf(tool, catalog.Default().Remapped(fs))
			src = "stored database"
		}
		if len(files) > 0 {
			var err error
			if r, err = adapters.MappingCoverage(tool, files); err != nil {
				return err
			}
		}
		r.Version = version
		if f.format == "json" {
			return output.JSON(os.Stdout, r)
		}
		fmt.Printf("%s (%s): %d/%d FAIL findings mapped to a canonical id (%.1f%%), %d unmapped across %d distinct checks\n",
			r.Tool, src, r.Mapped, r.Findings, r.MappedPct, r.Unmapped, len(r.UnmappedChecks))
		if len(r.UnmappedChecks) > 0 {
			fmt.Printf("\n%-6s %-24s %s\n", "COUNT", "CHECK", "TITLE")
			for _, c := range r.UnmappedChecks {
				fmt.Printf("%-6d %-24s %s\n", c.Count, c.CheckID, c.Title)
			}
		}
		return nil
	},
}

func init() {
	catalogUnmappedCmd.Flags().StringVar(&catalogUnmappedFlags.tool, "tool", "", "scanner whose check ids are scored: checkov or trivy")
	catalogUnmappedCmd.Flags().StringSliceVar(&catalogUnmappedFlags.from, "from", nil, "scanner JSON output file(s) (default: the stored database's findings of --tool)")
	catalogUnmappedCmd.Flags().BoolVar(&catalogUnmappedFlags.golden, "golden", false, "score the repository's lab IaC goldens (lab/golden/expectations.yaml) instead of the database")
	catalogUnmappedCmd.Flags().StringVar(&catalogUnmappedFlags.format, "format", "text", "text or json")
	_ = catalogUnmappedCmd.MarkFlagRequired("tool")
	catalogCmd.AddCommand(catalogUnmappedCmd)
}

func init() {
	onboardCmd.Flags().StringSliceVar(&onboardFlags.providers, "providers", nil, "limit detection: aws,azure,gcp,kubernetes,github,okta,m365")
	for _, p := range []string{"aws", "azure", "gcp", "kubernetes", "github", "okta", "m365"} {
		p := p
		onboardCmd.Flags().Bool(p, false, "detect "+p)
	}
	onboardCmd.Flags().BoolVarP(&onboardFlags.yes, "yes", "y", false, "add everything detected without prompting")
	onboardCmd.Flags().BoolVar(&onboardFlags.scan, "scan", false, "run the first scan immediately")
	onboardCmd.Flags().StringVar(&onboardFlags.awsOrg, "aws-org", "", "print a CloudFormation StackSet creating a read-only role in every account (trusted account ID)")
	onboardCmd.Flags().StringVar(&onboardFlags.externalID, "external-id", "", "External ID for the org role")
	onboardCmd.Flags().StringVar(&onboardFlags.out, "out", "", "config file to write")
	onboardCmd.Flags().BoolVar(&onboardFlags.deployRole, "deploy-role", false, "create the read-only scanning role (generated least-privilege policy + SecurityAudit) in the current AWS account and record it in a manifest")
	onboardCmd.Flags().BoolVar(&onboardFlags.deploy, "deploy", false, "with --aws-org: create the StackSet and its instances (needs --org-ous, --regions) instead of printing the template")
	onboardCmd.Flags().StringVar(&onboardFlags.trusted, "trusted-account", "", "account allowed to assume the role (default: the current account)")
	onboardCmd.Flags().StringSliceVar(&onboardFlags.orgOUs, "org-ous", nil, "organizational unit ids for the StackSet instances")
	onboardCmd.Flags().StringSliceVar(&onboardFlags.regions, "regions", nil, "regions for the StackSet instances")
	onboardCmd.Flags().StringVar(&onboardFlags.profile, "profile", "", "AWS profile used to create the resources")
	onboardCmd.Flags().StringVar(&onboardFlags.manifestDir, "manifest-dir", ".cloud-posture", "where onboard-<account>.json manifests are written")
	onboardCmd.PreRun = func(cmd *cobra.Command, args []string) {
		for _, p := range []string{"aws", "azure", "gcp", "kubernetes", "github", "okta", "m365"} {
			if v, _ := cmd.Flags().GetBool(p); v {
				onboardFlags.providers = append(onboardFlags.providers, p)
			}
		}
	}
	hookInstallCmd.Flags().Bool("pre-commit-config", false, "print the pre-commit framework hook definition")
	hookCmd.AddCommand(hookInstallCmd)
	actionCmd.AddCommand(actionInitCmd)
	prCommentCmd.Flags().StringVar(&prFlags.results, "results", "cloud-posture.json", "scan --output json file")
	prCommentCmd.Flags().StringVar(&prFlags.repo, "repo", "", "owner/name (omit to print the markdown)")
	prCommentCmd.Flags().IntVar(&prFlags.pr, "pr", 0, "pull request number")
	prCommentCmd.Flags().IntVar(&prFlags.max, "max", 30, "max findings in the table")
	_ = strconv.Itoa
	root.AddCommand(onboardCmd, learnCmd, hookCmd, actionCmd, prCommentCmd, askCmd, catalogCmd)
}

// storedFindingsOf returns the stored FAIL findings a scanner produced (source = tool).
func storedFindingsOf(tool string) ([]model.Finding, error) {
	if _, err := os.Stat(firstNonEmpty(flagDB, store.DefaultPath())); err != nil {
		return nil, nil
	}
	st, err := openStore()
	if err != nil {
		return nil, err
	}
	defer st.Close()
	all, err := st.Findings(store.Filter{})
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, f := range all {
		if strings.EqualFold(f.Source, tool) && f.Status == model.Fail {
			out = append(out, f)
		}
	}
	return out, nil
}
