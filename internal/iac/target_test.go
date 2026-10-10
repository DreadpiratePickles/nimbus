package iac

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// copyFixture copies testdata/iac/<name> into a temp dir so patch tests never touch the fixtures.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "iac", name)
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func imdsFinding(res model.Resource) model.Finding {
	return model.Finding{CanonicalID: "EC2_IMDSV1", File: "main.tf", Resource: res}
}

// Defect 7 (verified probe): a cloud finding whose ID merely ends with a block name ("logs")
// was patched into aws_kms_key.logs. The patcher must refuse, listing the candidates.
func TestPatchDoesNotEditSuffixMatchedResource(t *testing.T) {
	dir := copyFixture(t, "wrong_target")
	f := imdsFinding(model.Resource{ID: "arn:aws:ec2:us-east-1:111111111111:instance/app-logs", Type: "aws_instance", Name: "app-logs"})
	p, err := PatchTerraform(f, dir)
	if p != nil {
		t.Fatalf("patched %s although no block is aws_instance.app-logs:\n%s", p.Address, p.Diff)
	}
	if !errors.Is(err, ErrAmbiguousTarget) {
		t.Fatalf("want ErrAmbiguousTarget, got %v", err)
	}
	var te *TargetError
	if !errors.As(err, &te) {
		t.Fatalf("want *TargetError, got %T", err)
	}
	got := strings.Join(te.Candidates, ",")
	if !strings.Contains(got, "aws_instance.web") || !strings.Contains(got, "aws_instance.worker") || strings.Contains(got, "aws_kms_key") {
		t.Errorf("candidates = %v (want the aws_instance blocks only)", te.Candidates)
	}
}

func TestPatchRefusesFixOnWrongResourceType(t *testing.T) {
	dir := copyFixture(t, "wrong_target")
	p, err := PatchTerraform(imdsFinding(model.Resource{ID: "aws_kms_key.logs"}), dir)
	if p != nil || !errors.Is(err, ErrAmbiguousTarget) {
		t.Fatalf("EC2 fix applied to aws_kms_key.logs: patch=%v err=%v", p != nil, err)
	}
}

func TestPatchResolvesTarget(t *testing.T) {
	cases := []struct {
		name string
		res  model.Resource
		line int
		want string
	}{
		{"exact address", model.Resource{ID: "aws_instance.worker"}, 0, "aws_instance.worker"},
		// "module address" (module.app.aws_instance.web) moved to TestPatchRefusesUnresolvableModule:
		// no module "app" is declared, so it must not patch the root block (Verification 3 defect 7).
		{"indexed address", model.Resource{ID: `aws_instance.worker["blue"]`}, 0, "aws_instance.worker"},
		{"yor_trace tag", model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-0abc", Attributes: map[string]any{"tags": map[string]any{"yor_trace": "trace-worker"}}}, 0, "aws_instance.worker"},
		{"type and name", model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-0abc", Type: "aws_instance", Name: "web"}, 0, "aws_instance.web"},
		{"line within block", model.Resource{ID: "i-0abc", Type: "aws_instance"}, 18, "aws_instance.worker"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyFixture(t, "wrong_target")
			f := imdsFinding(c.res)
			f.LineStart = c.line
			p, err := PatchTerraform(f, dir)
			if err != nil || p == nil {
				t.Fatalf("patch: %v", err)
			}
			if p.Address != c.want {
				t.Fatalf("patched %s, want %s", p.Address, c.want)
			}
			changed := changedBlocks(t, p.Before, p.After)
			if len(changed) != 1 || changed[0] != c.want {
				t.Fatalf("blocks changed = %v, want only %s\n%s", changed, c.want, p.Diff)
			}
		})
	}
}

func TestPatchRefusesDuplicateYorTrace(t *testing.T) {
	dir := copyFixture(t, "wrong_target")
	f := imdsFinding(model.Resource{ID: "i-0dup", Attributes: map[string]any{"tags": map[string]any{"yor_trace": "trace-dup"}}})
	p, err := PatchTerraform(f, dir)
	var te *TargetError
	if p != nil || !errors.As(err, &te) || len(te.Candidates) != 2 {
		t.Fatalf("want refusal listing aws_instance.batch_a and batch_b, got patch=%v err=%v", p != nil, err)
	}
}

// changedBlocks returns the addresses of top-level blocks whose source text differs.
func changedBlocks(t *testing.T, before, after string) []string {
	t.Helper()
	text := func(src string) map[string]string {
		f, d := hclsyntax.ParseConfig([]byte(src), "x.tf", hcl.Pos{Line: 1, Column: 1})
		if d.HasErrors() {
			t.Fatalf("parse: %s", d.Error())
		}
		out := map[string]string{}
		for _, b := range f.Body.(*hclsyntax.Body).Blocks {
			r := b.Range()
			out[b.Type+":"+strings.Join(b.Labels, ".")] = strings.Join(strings.Fields(string(r.SliceBytes([]byte(src)))), " ")
		}
		return out
	}
	a, b := text(before), text(after)
	var out []string
	for k, v := range b {
		if a[k] != v {
			out = append(out, strings.TrimPrefix(k, "resource:"))
		}
	}
	sort.Strings(out)
	return out
}

// Every patch the native patcher can produce must parse, reference only declared var./local.
// symbols, not widen access, and clear the finding on re-scan.
func TestEveryPatchParsesAndDeclaresSymbols(t *testing.T) {
	dir := copyFixture(t, "patch_all")
	fs, err := ScanTerraform(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	patched := map[string]bool{}
	for _, f := range fs {
		if f.Status != model.Fail {
			continue
		}
		p, err := PatchTerraform(f, dir)
		if err != nil {
			t.Errorf("%s %s: %v", f.CanonicalID, f.Resource.ID, err)
			continue
		}
		if p == nil {
			continue
		}
		patched[f.CanonicalID] = true
		label := f.CanonicalID + " " + f.Resource.ID
		undeclared, err := UndeclaredSymbols([]byte(p.After), "patched.tf")
		if err != nil {
			t.Errorf("%s: patched file does not parse: %v\n%s", label, err, p.After)
			continue
		}
		if len(undeclared) > 0 {
			t.Errorf("%s: references undeclared %v\n%s", label, undeclared, p.After)
		}
		if p.WidensAccess {
			t.Errorf("%s: patch widens access", label)
		}
		after, err := ScanHCL([]byte(p.After), "main.tf", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range after {
			if x.Status == model.Fail && x.CanonicalID == f.CanonicalID && x.Resource.ID == f.Resource.ID {
				t.Errorf("%s: still failing after patch (%s)", label, x.Description)
			}
		}
	}
	for _, want := range []string{"S3_PUBLIC_BUCKET", "EC2_SG_OPEN_SSH", "EC2_IMDSV1", "EC2_PUBLIC_IP", "EBS_UNENCRYPTED", "RDS_PUBLIC", "RDS_UNENCRYPTED",
		"CLOUDTRAIL_NO_LOG_VALIDATION", "CLOUDTRAIL_DISABLED", "KMS_ROTATION_DISABLED", "EKS_PUBLIC_ENDPOINT", "AZ_STORAGE_PUBLIC_BLOB",
		"AZ_STORAGE_HTTP_ALLOWED", "AZ_NSG_OPEN_SSH", "GCP_BUCKET_PUBLIC", "GCP_FIREWALL_OPEN_SSH", "GCP_SQL_PUBLIC"} {
		if !patched[want] {
			t.Errorf("no patch produced for %s", want)
		}
	}
}

func TestPatchDoesNotRedeclareSiblingVariable(t *testing.T) {
	dir := copyFixture(t, "module_vars")
	fs, _ := ScanTerraform(dir, time.Now())
	for _, f := range fs {
		if f.Status != model.Fail {
			continue
		}
		p, err := PatchTerraform(f, dir)
		if err != nil || p == nil {
			t.Fatalf("patch: %v", err)
		}
		if strings.Contains(p.After, `variable "allowed_cidrs"`) || !strings.Contains(p.After, "var.allowed_cidrs") {
			t.Fatalf("variable redeclared or not used:\n%s", p.After)
		}
		return
	}
	t.Fatal("fixture produced no failing finding")
}

func TestUndeclaredSymbolsSeesNestedAndModuleDeclarations(t *testing.T) {
	src := []byte(`locals { a = 1 }
resource "x_y" "z" {
  v = var.declared
  dynamic "d" {
    for_each = var.missing
    content { w = local.a + local.b }
  }
}`)
	got, err := UndeclaredSymbols(src, "t.tf", []byte(`variable "declared" {}`))
	if err != nil || strings.Join(got, ",") != "local.b,var.missing" {
		t.Fatalf("got %v %v", got, err)
	}
}
