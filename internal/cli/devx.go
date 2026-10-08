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

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
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
	providers []string
	yes       bool
	scan      bool
	awsOrg    string
	externalID string
	out       string
}

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "One-command onboarding: detect AWS/Azure/GCP/Kubernetes/GitHub/Okta/M365 credentials, write config, run the first scan",
	Example: `  cloud-posture onboard
  cloud-posture onboard --aws --azure --gcp --yes --scan
  cloud-posture onboard --aws-org 123456789012 --external-id my-secret   # print the org-wide StackSet template`,
	RunE: func(cmd *cobra.Command, args []string) error {
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
		found := devx.Detect(context.Background(), want)
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
	RunE: func(cmd *cobra.Command, args []string) error {
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

var askCmd = &cobra.Command{
	Use:   "ask <question>",
	Short: "AI security copilot: natural-language questions over your posture (Python layer; offline rule-based fallback)",
	Example: `  cloud-posture ask "show me all public databases with no encryption"
  cloud-posture ask "why did finding 3f9c fire and what is the blast radius"
  cloud-posture ask "write an OPA policy to block public S3 buckets"`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		exe := python(cfg)
		if exe == "" {
			return fmt.Errorf("the copilot lives in the Python layer: pip install -e \"python[ai]\" (works offline; set ANTHROPIC_API_KEY for LLM answers)")
		}
		st, err := openStore()
		if err != nil {
			return err
		}
		dbPath := st.Path()
		st.Close()
		q := strings.Join(args, " ")
		sub := "ask"
		switch {
		case strings.HasPrefix(strings.ToLower(q), "write an opa") || strings.HasPrefix(strings.ToLower(q), "write a rego") || strings.Contains(strings.ToLower(q), "opa policy"):
			sub = "policy"
		case strings.HasPrefix(strings.ToLower(q), "why did") || strings.Contains(strings.ToLower(q), "blast radius"):
			sub = "ask"
		}
		out, err := runPython(cmd.Context(), exe, []string{"CLOUD_POSTURE_DB=" + dbPath}, "-m", "nimbus", sub, q)
		os.Stdout.Write(out)
		return err
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
