package cli

// Integration pass 2 items 9–11 (V3-iac handoff): module patches merge by LocalAddress and
// show their callers, --all-callers gates shared module sources, and fix never claims or
// attempts a patch on an IaC file the scanner could not parse.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/output"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

const moduleSrc = `resource "aws_s3_bucket" "b" {
  bucket = "b"
  acl    = "public-read"
}

resource "aws_instance" "web" {
  ami           = "ami-1"
  instance_type = "t3.micro"
}
`

// moduleRoot writes root/main.tf calling ./modules/app from each of calls, and the module.
func moduleRoot(t *testing.T, calls ...string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "infra")
	os.MkdirAll(filepath.Join(root, "modules", "app"), 0o755)
	var b strings.Builder
	for _, c := range calls {
		b.WriteString("module \"" + c + "\" {\n  source = \"./modules/app\"\n}\n\n")
	}
	os.WriteFile(filepath.Join(root, "main.tf"), []byte(b.String()), 0o644)
	os.WriteFile(filepath.Join(root, "modules", "app", "main.tf"), []byte(moduleSrc), 0o644)
	return root
}

func moduleFinding(canonical, addr string) model.Finding {
	f := model.Finding{Source: "nimbus-iac", CheckID: "x_" + canonical, CanonicalID: canonical, Title: canonical, Severity: model.High, Status: model.Fail,
		Provider: "aws", Account: "iac", File: "modules/app/main.tf", Resource: model.Resource{ID: addr, Type: "x", Name: addr}}
	f.Finalize(time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC))
	return f
}

// Item 9: two findings in one module file → one merged patch carrying both changes.
func TestMergePatchesKeepsSecondModulePatch(t *testing.T) {
	root := moduleRoot(t, "app")
	var ps []iac.Patch
	for _, f := range []model.Finding{moduleFinding("S3_PUBLIC_BUCKET", "module.app.aws_s3_bucket.b"), moduleFinding("EC2_IMDSV1", "module.app.aws_instance.web")} {
		p, err := iac.PatchTerraformWith(f, root, iac.PatchOptions{})
		if err != nil || p == nil {
			t.Fatalf("patch %s: %v", f.CanonicalID, err)
		}
		ps = append(ps, *p)
	}
	merged, dropped := mergePatches(ps)
	if len(merged) != 1 || len(dropped) != 0 {
		t.Fatalf("merged %d, dropped %v", len(merged), dropped)
	}
	after := merged[0].After
	if !strings.Contains(after, "http_tokens") || strings.Contains(after, `"public-read"`) {
		t.Fatalf("merged patch lost a fix:\n%s", after)
	}
	if !strings.Contains(merged[0].CanonicalID, "EC2_IMDSV1") || len(merged[0].Callers) == 0 {
		t.Errorf("merged patch metadata: %s callers %v", merged[0].CanonicalID, merged[0].Callers)
	}
}

func seedFindings(t *testing.T, fs ...model.Finding) {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.ApplyScan("s1", fs, time.Now().UTC(), store.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
}

// Items 9 + 10 through the CLI: callers are printed; a shared module source is refused
// (callers listed) without --all-callers and patched for every caller with it.
func TestFixPatchModuleCallersAndAllCallers(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	root := moduleRoot(t, "app", "app2")
	seedFindings(t, moduleFinding("S3_PUBLIC_BUCKET", "module.app.aws_s3_bucket.b"), moduleFinding("EC2_IMDSV1", "module.app.aws_instance.web"))
	mod := filepath.Join(root, "modules", "app", "main.tf")

	out, err := runErr(t, "fix", "--all", "--patch", "--iac", root)
	if err == nil {
		t.Fatalf("shared module source patched without --all-callers:\n%s", out)
	}
	out += err.Error() // the error is printed once, by main (root.SilenceErrors, r4 N5)
	if !strings.Contains(out, "refused") || !strings.Contains(out, "module.app2") || !strings.Contains(out, "--all-callers") {
		t.Errorf("refusal must name the callers and the flag:\n%s", out)
	}
	if b, _ := os.ReadFile(mod); string(b) != moduleSrc {
		t.Fatalf("module file changed by a refused patch")
	}

	out = run(t, "fix", "--all", "--patch", "--iac", root, "--all-callers")
	b, _ := os.ReadFile(mod)
	if !strings.Contains(string(b), "http_tokens") || strings.Contains(string(b), `"public-read"`) {
		t.Fatalf("both fixes must land in the shared module file:\n%s\n%s", out, b)
	}
	if !strings.Contains(out, "callers: module.app, module.app2") {
		t.Errorf("fix output must list the callers:\n%s", out)
	}
}

// Item 11: a finding whose file is currently unscanned (IAC_PARSE_LIMIT) is never patched,
// and the refusal says why; verification never counts an unscannable re-scan as fixed.
func TestFixRefusesUnscannedFile(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	root := filepath.Join(dir, "infra")
	os.MkdirAll(root, 0o755)
	main := filepath.Join(root, "main.tf")
	broken := evadeBucket + evadeTail
	os.WriteFile(main, []byte(broken), 0o644)
	f := model.Finding{Source: "nimbus-iac", CheckID: "NIMBUS_TF_S3_PUBLIC", CanonicalID: "S3_PUBLIC_BUCKET", Title: "pub", Severity: model.High, Status: model.Fail,
		Provider: "aws", Account: "iac", File: "main.tf", Resource: model.Resource{ID: "aws_s3_bucket.pub", Type: "aws_s3_bucket", Name: "pub"}}
	f.Finalize(time.Now())
	gap := model.Finding{Source: "nimbus-iac", CheckID: "NIMBUS_TF_PARSE_LIMIT", CanonicalID: "IAC_PARSE_LIMIT", Title: "not scanned", Severity: model.High, Status: model.Error,
		Provider: "aws", Account: "iac", File: "main.tf", Resource: model.Resource{ID: "main.tf", Name: "main.tf"}, Tags: map[string]string{output.TagScanGap: "depth: nesting"}}
	gap.Finalize(time.Now())
	seedFindings(t, f, gap)
	out, err := runErr(t, "fix", "--finding", "S3_PUBLIC_BUCKET", "--patch", "--iac", root)
	if err == nil || !strings.Contains(out+err.Error(), "not scanned") { // error printed once, by main
		t.Fatalf("patch of an unscanned file must be refused with the reason (err %v):\n%s", err, out)
	}
	if b, _ := os.ReadFile(main); string(b) != broken {
		t.Fatalf("unscanned file was modified")
	}

	// Verification: a patched file that still does not parse is never "verified".
	p := iac.Patch{File: "main.tf", Address: "aws_s3_bucket.pub", CanonicalID: "S3_PUBLIC_BUCKET", After: strings.Replace(broken, "public-read", "private", 1)}
	if v := verifyPatchResult(f, p); v.Verdict != verdictUnverified || !strings.Contains(v.Reason, "not scanned") {
		t.Fatalf("re-scan of an unparseable patched file: %v %q, want unverified (not scanned)", v.Verdict, v.Reason)
	}
}

// The CLI gate is output.GateCount (scan gaps block every threshold).
func TestGateCountMatchesOutputGateCount(t *testing.T) {
	gap := model.Finding{CanonicalID: "IAC_PARSE_LIMIT", Status: model.Error, Severity: model.High, Tags: map[string]string{output.TagScanGap: "syntax"}}
	fs := []model.Finding{gap, {Status: model.Fail, Severity: model.Medium}, {Status: model.Fail, Severity: model.Critical}, {Status: model.Pass, Severity: model.Critical}}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if got, want := gateCount(fs, sev), output.GateCount(fs, sev); got != want {
			t.Errorf("--fail-on %s: gateCount %d, output.GateCount %d", sev, got, want)
		}
	}
}
