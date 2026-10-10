package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/gitops"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/spf13/cobra"
)

var fixFlags struct {
	canonical, id, weakness string
	passRole, passRoleTo    string
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
	requireVerify           bool
	allCallers              bool
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
	f.BoolVar(&fixFlags.allCallers, "all-callers", false, "with --patch: allow patching a module source shared by several module calls (the patch changes every caller)")
	f.StringVar(&fixFlags.passRole, "passrole", "", "principal ARN whose iam:PassRole statement to scope (with --role; see `plan`)")
	f.StringVar(&fixFlags.passRoleTo, "role", "", "with --passrole: the escalation role the principal must no longer pass")
	f.BoolVar(&fixFlags.requireVerify, "require-verify", false, "with --patch: write a patch only when the re-scan proves the finding is gone; exit non-zero for any unverified patch")
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
	if fixFlags.passRole != "" {
		return runPassRoleFix(fixFlags.passRole, fixFlags.passRoleTo)
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
		applyCodeMapping(targets, mapping, logf)
	}

	if fixFlags.patch || fixFlags.autoPR {
		return runPatch(targets, cfg)
	}

	var results []*remediation.Fix
	var g *graph.Graph // loaded once, only for a fix that targets the Service selecting a pod
	for _, f := range targets {
		if st != nil && remediation.TargetsK8sService(f.CanonicalID) {
			if g == nil {
				if g, _ = loadGraph(st); g == nil {
					g = graph.New()
				}
			}
			f = remediation.WithK8sService(f, g)
		}
		if fixFlags.ai {
			if exe := python(cfg); exe != "" {
				out, err := runPython(cmd.Context(), exe, nil, "-m", "nimbus", "fix", f.ID, "--format", string(format))
				if err == nil && len(out) > 0 {
					results = append(results, &remediation.Fix{Finding: f, CanonicalID: f.CanonicalID, Format: format, FileName: aiFixFileName(f, format), Content: string(out), Apply: "review, then apply with your IaC pipeline"})
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
	ix := loadIssueIndex(st) // the verify phase names each finding's Issue id
	for _, r := range results {
		path := filepath.Join(fixFlags.outDir, r.FileName)
		if err := writeFixFile(fixFlags.outDir, r.FileName, r.Content); err != nil {
			return err
		}
		tag := ""
		if r.Generic {
			tag = " (generic stub — no typed template yet)"
		}
		fmt.Printf("✓ %s → %s%s\n  apply: %s\n", r.CanonicalID, path, tag, r.Apply)
		printPhases(os.Stdout, r, "  ", ix)
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
	var notFixedReasons, unverifiedReasons, refusedReasons []string
	unverifiedFile := map[string]string{} // patch file -> reason, for the final report
	unscanned := unscannedFiles(fixFlags.iacRoot)
	for _, f := range targets {
		if f.File == "" {
			noSource++
			if !fixFlags.all {
				logf("skip %s on %s: no source file (use --tfstate to map cloud findings to code)", f.CanonicalID, f.Resource.Name)
			}
			continue
		}
		// Containment before the read: the same root is used for reading and writing.
		if _, err := gitops.SafeJoin(fixFlags.iacRoot, f.File); err != nil {
			missing++
			logf("skip %s: %v", f.CanonicalID, err)
			continue
		}
		// A file the scanner could not parse was not examined: its stored findings may be
		// stale and the patcher cannot rewrite it safely (V3-iac UnscannedFiles contract).
		if reason, ok := unscanned[filepath.ToSlash(filepath.Clean(f.File))]; ok {
			r := fmt.Sprintf("%s on %s refused: %s was not scanned (%s); make it parse, re-scan, then patch", f.CanonicalID, firstNonEmpty(f.Resource.ID, f.Resource.Name), f.File, reason)
			refusedReasons = append(refusedReasons, r)
			fmt.Fprintf(os.Stderr, "✗ %s\n", r)
			continue
		}
		p, err := iac.PatchTerraformWith(f, fixFlags.iacRoot, iac.PatchOptions{AllCallers: fixFlags.allCallers})
		if err != nil {
			var te *iac.TargetError
			if errors.As(err, &te) && strings.Contains(te.Reason, "--all-callers") {
				// A shared module source is a deliberate refusal, never a silent skip.
				r := fmt.Sprintf("%s on %s refused: %s (callers: %s)", f.CanonicalID, f.Resource.ID, te.Reason, strings.Join(te.Candidates, ", "))
				refusedReasons = append(refusedReasons, r)
				fmt.Fprintf(os.Stderr, "✗ %s\n", r)
				continue
			}
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
		// validation: re-scan the patched content in a temp copy; the specific finding
		// (canonical id + resource + file) must be evaluated and gone.
		switch v := verifyPatchResult(f, *p); v.Verdict {
		case verdictNotFixed:
			notFixedReasons = append(notFixedReasons, v.Reason)
			fmt.Fprintf(os.Stderr, "✗ %s on %s: %s; patch not applied\n", f.CanonicalID, firstNonEmpty(p.Address, f.Resource.ID), v.Reason)
			continue
		case verdictUnverified:
			reason := fmt.Sprintf("%s on %s unverified: %s", f.CanonicalID, firstNonEmpty(p.Address, f.Resource.ID), v.Reason)
			unverifiedReasons = append(unverifiedReasons, reason)
			if fixFlags.requireVerify || fixFlags.autoPR {
				// A PR presents its patches as fixes: only proven ones go in.
				fmt.Fprintf(os.Stderr, "✗ %s; patch not applied (--require-verify / --auto-pr)\n", reason)
				continue
			}
			unverifiedFile[p.File] = reason
		}
		patches = append(patches, *p)
		fixed = append(fixed, f)
	}
	if fixFlags.all && (noSource > 0 || missing > 0) {
		logf("skipped %d cloud finding(s) without source (use --tfstate) and %d with files outside --iac %s", noSource, missing, fixFlags.iacRoot)
	}
	// merge multiple patches to the same file sequentially; a patch that cannot be
	// re-applied on top of another is reported, never dropped silently.
	patches, dropped := mergePatches(patches)
	for _, d := range dropped {
		notFixedReasons = append(notFixedReasons, d)
		fmt.Fprintf(os.Stderr, "✗ %s\n", d)
	}
	notFixedReasons = append(notFixedReasons, refusedReasons...)
	if len(patches) == 0 {
		var why []string
		why = append(why, notFixedReasons...)
		why = append(why, unverifiedReasons...)
		if len(why) > 0 {
			return fmt.Errorf("nothing patched: %s", strings.Join(why, "; "))
		}
		return fmt.Errorf("nothing patched")
	}
	if fixFlags.outputFmt == "json" {
		var err error
		if len(patches) == 1 {
			err = output.JSON(os.Stdout, patches[0])
		} else {
			err = output.JSON(os.Stdout, patches)
		}
		if err != nil {
			return err
		}
		return verifyFailure(notFixedReasons, unverifiedReasons)
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
			return verifyFailure(notFixedReasons, unverifiedReasons)
		}
		fmt.Printf("✓ branch %s (%s) pushed; PR: %s\n", res.Branch, res.Commit, res.URL)
		return verifyFailure(notFixedReasons, unverifiedReasons)
	}
	for _, p := range patches {
		full, err := gitops.SafeJoin(fixFlags.iacRoot, p.File)
		if err != nil {
			return err
		}
		if fixFlags.print {
			if reason, ok := unverifiedFile[p.File]; ok {
				fmt.Printf("# unverified: %s\n", reason)
			}
			if len(p.Callers) > 0 {
				fmt.Printf("# callers: %s\n", strings.Join(p.Callers, ", "))
			}
			fmt.Println(p.Diff)
			continue
		}
		if p.WidensAccess {
			return fmt.Errorf("guardrail: patch to %s would widen access", p.File)
		}
		if err := os.WriteFile(full, []byte(p.After), 0o644); err != nil {
			return err
		}
		if reason, ok := unverifiedFile[p.File]; ok {
			fmt.Printf("⚠ patched %s (%s), unverified: %s\n  %s\n", p.File, p.Address, reason, p.Explanation)
		} else {
			fmt.Printf("✓ patched %s (%s): %s\n", p.File, p.Address, p.Explanation)
		}
		if len(p.Callers) > 0 {
			fmt.Printf("  callers: %s\n", strings.Join(p.Callers, ", "))
		}
	}
	return verifyFailure(notFixedReasons, unverifiedReasons)
}

// verifyFailure is the exit status after the verified patches were written: any finding
// a patch did not fix fails the command, and so does any unverified one under
// --require-verify.
func verifyFailure(notFixed, unverified []string) error {
	var why []string
	why = append(why, notFixed...)
	if fixFlags.requireVerify || fixFlags.autoPR {
		why = append(why, unverified...)
	}
	if len(why) == 0 {
		return nil
	}
	return fmt.Errorf("patch verification failed: %s", strings.Join(why, "; "))
}

// applyCodeMapping points cloud findings at their IaC blocks. A finding whose mapping
// LocateStrict refuses (ambiguous or unresolved target) is left unmapped and the reason,
// with the candidate blocks, is logged rather than skipped silently.
func applyCodeMapping(targets []model.Finding, mapping map[string]iac.CodeLocation, logf func(string, ...any)) {
	for i := range targets {
		if targets[i].File != "" {
			continue
		}
		loc, err := iac.LocateStrict(targets[i], mapping)
		if err != nil {
			if errors.Is(err, iac.ErrAmbiguousTarget) {
				logf("not mapped %s on %s: %v", targets[i].CanonicalID, firstNonEmpty(targets[i].Resource.Name, targets[i].Resource.ID), err)
			}
			continue
		}
		targets[i].File, targets[i].LineStart = loc.File, loc.Line
		targets[i].Resource.ID = loc.Address
		logf("mapped %s → %s:%d (%s)", targets[i].Resource.Name, loc.File, loc.Line, loc.Address)
	}
}

var (
	verifyModuleSegment = regexp.MustCompile(`^module\.[A-Za-z0-9_-]+(\[[^\]]*\])?\.`)
	verifyIndexSuffix   = regexp.MustCompile(`\[[^\]]*\]$`)
)

// shortAddress reduces a Terraform address to type.name (module prefixes and the
// instance key stripped), the form the single-file re-scan in verifyPatch reports, so a
// tfstate-mapped finding (module.a.aws_instance.web[0]) is compared like with like.
func shortAddress(id string) string {
	a := strings.TrimSpace(id)
	for verifyModuleSegment.MatchString(a) {
		a = verifyModuleSegment.ReplaceAllString(a, "")
	}
	return verifyIndexSuffix.ReplaceAllString(a, "")
}

// mergePatches chains patches that touch the same file so each applies on top of the previous
// one. The re-patch targets the block by Patch.LocalAddress (type.name in its file): a module
// patch's Address carries the module prefix, which cannot resolve inside the temp copy. A patch
// that cannot be re-applied is returned in dropped with the reason (never silently lost).
func mergePatches(ps []iac.Patch) (out []iac.Patch, dropped []string) {
	byFile := map[string]int{}
	for _, p := range ps {
		i, ok := byFile[p.File]
		if !ok {
			byFile[p.File] = len(out)
			out = append(out, p)
			continue
		}
		prev := out[i]
		addr := firstNonEmpty(p.LocalAddress, shortAddress(p.Address))
		why := func(err error) string {
			return fmt.Sprintf("%s on %s not applied: could not merge it with the other patch to %s: %v", p.CanonicalID, firstNonEmpty(p.Address, addr), p.File, err)
		}
		// Same base name as the real file, so file-scoped rules and messages read alike.
		tmp, err := os.MkdirTemp("", "cp-merge")
		if err != nil {
			dropped = append(dropped, why(err))
			continue
		}
		name := filepath.Base(p.File)
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(prev.After), 0o644); err != nil {
			os.RemoveAll(tmp)
			dropped = append(dropped, why(err))
			continue
		}
		f := model.Finding{CanonicalID: p.CanonicalID, File: name, Resource: model.Resource{ID: addr}}
		np, err := iac.PatchTerraform(f, tmp)
		os.RemoveAll(tmp)
		if err == nil && np == nil {
			err = errors.New("no deterministic patch on the merged content")
		}
		if err != nil {
			dropped = append(dropped, why(err))
			continue
		}
		prev.After = np.After
		prev.Diff = iac.UnifiedDiff(prev.File, prev.Before, prev.After)
		prev.Explanation += " " + p.Explanation
		prev.CanonicalID += "," + p.CanonicalID
		prev.WidensAccess = prev.WidensAccess || np.WidensAccess
		prev.Callers = unionStrings(prev.Callers, p.Callers)
		out[i] = prev
	}
	return out, dropped
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range append(append([]string{}, a...), b...) {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// unscannedFiles maps each root-relative file the Terraform scanner cannot parse under root
// to its reason (iac.ScanTerraformResult UnscannedFiles / UnscannedReasons).
func unscannedFiles(root string) map[string]string {
	out := map[string]string{}
	res, _ := iac.ScanTerraformResult(root, time.Now())
	for _, f := range res.UnscannedFiles {
		out[filepath.ToSlash(filepath.Clean(f))] = res.UnscannedReasons[f]
	}
	return out
}

// aiFixFileName names an LLM-generated fix; the resource name is reduced to [A-Za-z0-9._-]
// so it can never introduce a path separator.
func aiFixFileName(f model.Finding, format remediation.Format) string {
	return fmt.Sprintf("%s_%s_ai.%s", safeFileComponent(strings.ToLower(f.CanonicalID)), safeFileComponent(f.Resource.Name), ext(format))
}

func safeFileComponent(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '_'
		}
	}
	if out := strings.Trim(string(b), "."); out != "" {
		return out
	}
	return "resource"
}

// writeFixFile writes a generated fix inside dir, refusing names that resolve outside it.
func writeFixFile(dir, name, content string) error {
	full, err := gitops.SafeJoin(dir, name)
	if err != nil {
		return err
	}
	return os.WriteFile(full, []byte(content), 0o644)
}

// printPhases prints a fix's sidecar as the AWS-remediation-plan sequence: prerequisite
// (permissions, breaks-function, effort, mitigation) → snapshot → fix → verify (the sidecar's
// validation SQL) → rollback.
func printPhases(w io.Writer, r *remediation.Fix, indent string, ix issueIndex) {
	if m := r.Metadata; m != nil {
		fmt.Fprintf(w, "%seffort %s · confidence %s · template %s\n", indent, m.Effort, m.Confidence, r.Template)
	}
	f := r.Finding
	for i, ph := range withIssueVerify(server.RemediationPhases(r), ix.target(&f, nil)) {
		fmt.Fprintf(w, "%s%d. %s\n", indent, i+1, ph.Name)
		for _, s := range ph.Steps {
			fmt.Fprintf(w, "%s     %s\n", indent, s)
		}
	}
}
