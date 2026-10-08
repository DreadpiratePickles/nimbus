package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/gitops"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var fixFlags struct {
	canonical, id, weakness string
	format                  string
	tf, cfn, bicep, k8s     bool
	outDir                  string
	print                   bool
	all                     bool
	patch                   bool
	iacRoot                 string
	autoPR                  bool
	dryRun                  bool
	branch, base, title     string
	labels                  []string
	draft                   bool
	ai                      bool
	outputFmt               string
	tfstate                 string
}

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Generate IaC remediation (Terraform/CloudFormation/Bicep/Kubernetes), patch IaC in place, or open a fix PR",
	Example: `  cloud-posture fix --finding S3_PUBLIC_BUCKET --generate-terraform
  cloud-posture fix --id 3f9c… --format cloudformation --out-dir ./remediation
  cloud-posture fix --finding EC2_IMDSV1 --patch --iac ./infra            # rewrite the offending block
  cloud-posture fix --all --patch --iac ./infra --auto-pr                 # open a PR with every deterministic fix
  cloud-posture fix --finding RDS_PUBLIC --ai --format terraform          # LLM-generated fix via the Python layer`,
	RunE: runFix,
}

func init() {
	f := fixCmd.Flags()
	f.StringVar(&fixFlags.canonical, "finding", "", "canonical finding ID (e.g. S3_PUBLIC_BUCKET); applies to every open finding with that ID")
	f.StringVar(&fixFlags.id, "id", "", "specific finding fingerprint")
	f.StringVar(&fixFlags.weakness, "weakness", "", "every open finding carrying this weakness (e.g. PUBLIC_DATA_STORE)")
	f.StringVar(&fixFlags.format, "format", "", "terraform|cloudformation|bicep|kubernetes")
	f.BoolVar(&fixFlags.tf, "generate-terraform", false, "shorthand for --format terraform")
	f.BoolVar(&fixFlags.cfn, "generate-cloudformation", false, "shorthand for --format cloudformation")
	f.BoolVar(&fixFlags.bicep, "generate-bicep", false, "shorthand for --format bicep")
	f.BoolVar(&fixFlags.k8s, "generate-kubernetes", false, "shorthand for --format kubernetes")
	f.StringVar(&fixFlags.outDir, "out-dir", "cloud-posture-remediation", "where generated files go")
	f.BoolVar(&fixFlags.print, "print", false, "print to stdout instead of writing files")
	f.BoolVar(&fixFlags.all, "all", false, "every open finding (filtered by --finding/--weakness when given)")
	f.BoolVar(&fixFlags.patch, "patch", false, "rewrite the IaC source block in place (Terraform) instead of generating a new file")
	f.StringVar(&fixFlags.iacRoot, "iac", ".", "IaC root for --patch / cloud-to-code mapping")
	f.StringVar(&fixFlags.tfstate, "tfstate", "", "terraform.tfstate (or `terraform show -json`) to map cloud findings to code")
	f.BoolVar(&fixFlags.autoPR, "auto-pr", false, "commit the patches on a branch and open a pull request")
	f.BoolVar(&fixFlags.dryRun, "dry-run", false, "with --auto-pr: show the PR body without pushing")
	f.StringVar(&fixFlags.branch, "branch", "", "PR branch name")
	f.StringVar(&fixFlags.base, "base", "", "PR base branch")
	f.StringVar(&fixFlags.title, "title", "", "PR title")
	f.StringSliceVar(&fixFlags.labels, "label", []string{"security", "cloud-posture"}, "PR labels")
	f.BoolVar(&fixFlags.draft, "draft", false, "open as draft PR")
	f.BoolVar(&fixFlags.ai, "ai", false, "use the Python LLM fix generator (ANTHROPIC_API_KEY) with the template as fallback")
	f.StringVarP(&fixFlags.outputFmt, "output", "o", "text", "text|json")
	root.AddCommand(fixCmd)
}

func chosenFormat() (remediation.Format, error) {
	switch {
	case fixFlags.tf:
		return remediation.Terraform, nil
	case fixFlags.cfn:
		return remediation.CloudFormation, nil
	case fixFlags.bicep:
		return remediation.Bicep, nil
	case fixFlags.k8s:
		return remediation.Kubernetes, nil
	case fixFlags.format != "":
		return remediation.ParseFormat(fixFlags.format)
	}
	return remediation.Terraform, nil
}

func runFix(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	format, err := chosenFormat()
	if err != nil {
		return err
	}
	if fixFlags.canonical == "" && fixFlags.id == "" && fixFlags.weakness == "" && !fixFlags.all {
		return fmt.Errorf("specify --finding <CANONICAL_ID>, --id <fingerprint>, --weakness <W> or --all")
	}
	// Select findings from the store; when the store has none for a canonical ID, synthesise one so
	// templates still render (useful before the first scan).
	var targets []model.Finding
	st, err := openStore()
	if err == nil {
		defer st.Close()
		fl := store.Filter{Status: "FAIL"}
		if fixFlags.canonical != "" {
			fl.CanonicalID = strings.ToUpper(fixFlags.canonical)
		}
		if fixFlags.id != "" {
			if f, err := st.Finding(fixFlags.id); err == nil {
				targets = []model.Finding{*f}
			} else {
				return fmt.Errorf("finding %s not found", fixFlags.id)
			}
		} else {
			fs, _ := st.Findings(fl)
			for _, f := range fs {
				if fixFlags.weakness != "" && !f.HasWeakness(strings.ToUpper(fixFlags.weakness)) {
					continue
				}
				targets = append(targets, f)
			}
		}
	}
	if len(targets) == 0 {
		if fixFlags.canonical == "" {
			return fmt.Errorf("no open findings match")
		}
		e, ok := catalog.Default().Get(fixFlags.canonical)
		if !ok {
			return fmt.Errorf("unknown canonical ID %s (see `cloud-posture catalog`)", fixFlags.canonical)
		}
		targets = []model.Finding{{CanonicalID: e.ID, Title: e.Title, Provider: e.Provider, Severity: e.Severity, Status: model.Fail, Resource: model.Resource{ID: "example", Name: "example", Type: e.ResourceType}}}
		logf("no stored findings for %s; rendering an example template", e.ID)
	}
	if !fixFlags.all && fixFlags.id == "" && len(targets) > 10 && !fixFlags.patch {
		logf("%d matching findings; generating for the first 10 (use --all for everything)", len(targets))
		targets = targets[:10]
	}

	// cloud-to-code: map live findings onto IaC files when a tfstate is given.
	if fixFlags.tfstate != "" {
		mapping, err := iac.MapCloudToCode(fixFlags.tfstate, fixFlags.iacRoot)
		if err != nil {
			return err
		}
		for i := range targets {
			if targets[i].File == "" {
				if loc, ok := iac.Locate(targets[i], mapping); ok {
					targets[i].File, targets[i].LineStart = loc.File, loc.Line
					targets[i].Resource.ID = loc.Address
					logf("mapped %s → %s:%d (%s)", targets[i].Resource.Name, loc.File, loc.Line, loc.Address)
				}
			}
		}
	}

	if fixFlags.patch || fixFlags.autoPR {
		return runPatch(targets, cfg)
	}

	var results []*remediation.Fix
	for _, f := range targets {
		if fixFlags.ai {
			if exe := python(cfg); exe != "" {
				out, err := runPython(cmd.Context(), exe, nil, "-m", "nimbus", "fix", f.ID, "--format", string(format))
				if err == nil && len(out) > 0 {
					results = append(results, &remediation.Fix{Finding: f, CanonicalID: f.CanonicalID, Format: format, FileName: fmt.Sprintf("%s_%s_ai.%s", strings.ToLower(f.CanonicalID), f.Resource.Name, ext(format)), Content: string(out), Apply: "review, then apply with your IaC pipeline"})
					continue
				}
				logf("ai fix unavailable (%v); using template", err)
			}
		}
		fix, err := remediation.Generate(f, format)
		if err != nil {
			return err
		}
		results = append(results, fix)
	}
	if fixFlags.outputFmt == "json" {
		return output.JSON(os.Stdout, results)
	}
	if fixFlags.print {
		for _, r := range results {
			fmt.Println(r.Content)
		}
		return nil
	}
	os.MkdirAll(fixFlags.outDir, 0o755)
	for _, r := range results {
		path := filepath.Join(fixFlags.outDir, r.FileName)
		if err := os.WriteFile(path, []byte(r.Content), 0o644); err != nil {
			return err
		}
		tag := ""
		if r.Generic {
			tag = " (generic stub — no typed template yet)"
		}
		fmt.Printf("✓ %s → %s%s\n  apply: %s\n", r.CanonicalID, path, tag, r.Apply)
	}
	if format == remediation.Terraform && len(results) > 0 {
		fmt.Printf("\nOne command: cd %s && terraform init && terraform plan   # review, then terraform apply\n", fixFlags.outDir)
	}
	return nil
}

func ext(f remediation.Format) string {
	return map[remediation.Format]string{remediation.Terraform: "tf", remediation.CloudFormation: "yaml", remediation.Bicep: "bicep", remediation.Kubernetes: "yaml"}[f]
}

func runPatch(targets []model.Finding, cfg interface{}) error {
	var patches []iac.Patch
	var fixed []model.Finding
	noSource, missing := 0, 0
	for _, f := range targets {
		if f.File == "" {
			noSource++
			if !fixFlags.all {
				logf("skip %s on %s: no source file (use --tfstate to map cloud findings to code)", f.CanonicalID, f.Resource.Name)
			}
			continue
		}
		p, err := iac.PatchTerraform(f, fixFlags.iacRoot)
		if err != nil {
			missing++
			if !fixFlags.all {
				logf("skip %s (%s): %v", f.CanonicalID, f.File, err)
			}
			continue
		}
		if p == nil {
			logf("skip %s: no deterministic patch; use `fix --finding %s --generate-terraform`", f.CanonicalID, f.CanonicalID)
			continue
		}
		// validation: re-scan the patched content in a temp copy and confirm the finding is gone.
		if ok := verifyPatch(f, *p); !ok {
			logf("skip %s: patch did not clear the finding on re-scan", f.CanonicalID)
			continue
		}
		patches = append(patches, *p)
		fixed = append(fixed, f)
	}
	if fixFlags.all && (noSource > 0 || missing > 0) {
		logf("skipped %d cloud finding(s) without source (use --tfstate) and %d with files outside --iac %s", noSource, missing, fixFlags.iacRoot)
	}
	if len(patches) == 0 {
		return fmt.Errorf("nothing patched")
	}
	// merge multiple patches to the same file sequentially
	patches = mergePatches(patches)
	if fixFlags.outputFmt == "json" {
		if len(patches) == 1 {
			return output.JSON(os.Stdout, patches[0])
		}
		return output.JSON(os.Stdout, patches)
	}
	if fixFlags.autoPR {
		st, _ := openStore()
		var paths []model.AttackPath
		if st != nil {
			all, _ := st.AttackPaths()
			ids := map[string]bool{}
			for _, f := range fixed {
				ids[f.ID] = true
			}
			for _, p := range all {
				for _, id := range p.FindingIDs {
					if ids[id] {
						paths = append(paths, p)
						break
					}
				}
			}
			st.Close()
		}
		res, err := gitops.OpenFixPR(contextBackground(), patches, fixed, paths, gitops.PROptions{RepoDir: fixFlags.iacRoot, Branch: fixFlags.branch, BaseBranch: fixFlags.base, Title: fixFlags.title, Labels: fixFlags.labels, Draft: fixFlags.draft, DryRun: fixFlags.dryRun, Author: "cloud-posture <bot@cloud-posture.dev>"})
		if err != nil {
			return err
		}
		if res.DryRun {
			fmt.Printf("DRY RUN — branch %s would change %s\n\n%s\n", res.Branch, strings.Join(res.Files, ", "), res.Body)
			return nil
		}
		fmt.Printf("✓ branch %s (%s) pushed; PR: %s\n", res.Branch, res.Commit, res.URL)
		return nil
	}
	for _, p := range patches {
		full := p.File
		if !filepath.IsAbs(full) {
			full = filepath.Join(fixFlags.iacRoot, p.File)
		}
		if fixFlags.print {
			fmt.Println(p.Diff)
			continue
		}
		if p.WidensAccess {
			return fmt.Errorf("guardrail: patch to %s would widen access", p.File)
		}
		if err := os.WriteFile(full, []byte(p.After), 0o644); err != nil {
			return err
		}
		fmt.Printf("✓ patched %s (%s): %s\n", p.File, p.Address, p.Explanation)
	}
	return nil
}

func verifyPatch(f model.Finding, p iac.Patch) bool {
	tmp, err := os.MkdirTemp("", "cp-verify")
	if err != nil {
		return true
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "main.tf"), []byte(p.After), 0o644); err != nil {
		return true
	}
	fs, err := iac.ScanTerraform(tmp, time.Now())
	if err != nil {
		return false
	}
	for _, x := range fs {
		if x.Status == model.Fail && x.CanonicalID == f.CanonicalID && x.Resource.ID == f.Resource.ID {
			return false
		}
	}
	return true
}

// mergePatches chains patches that touch the same file so each applies on top of the previous one.
func mergePatches(ps []iac.Patch) []iac.Patch {
	byFile := map[string]int{}
	var out []iac.Patch
	for _, p := range ps {
		if i, ok := byFile[p.File]; ok {
			prev := out[i]
			// re-apply this patch on top of prev.After by re-running the patcher on a temp copy
			tmp, err := os.MkdirTemp("", "cp-merge")
			if err != nil {
				continue
			}
			os.WriteFile(filepath.Join(tmp, "main.tf"), []byte(prev.After), 0o644)
			f := model.Finding{CanonicalID: p.CanonicalID, File: "main.tf", Resource: model.Resource{ID: p.Address}}
			np, err := iac.PatchTerraform(f, tmp)
			os.RemoveAll(tmp)
			if err != nil || np == nil {
				continue
			}
			prev.After = np.After
			prev.Diff = iac.UnifiedDiff(prev.File, prev.Before, prev.After)
			prev.Explanation += " " + p.Explanation
			prev.CanonicalID += "," + p.CanonicalID
			prev.WidensAccess = prev.WidensAccess || np.WidensAccess
			out[i] = prev
			continue
		}
		byFile[p.File] = len(out)
		out = append(out, p)
	}
	return out
}
