package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verify-3 defect 4: verifyPatch must re-scan and require the SPECIFIC finding
// (canonical id + resource + file) to be gone; anything it cannot confirm is
// "unverified", never success.

// fixvOriginal is scratchpad verify-3/me/fixv/infra/main.tf before the patch: port 22
// world-open in a static ingress, 3389 world-open through a dynamic ingress.
const fixvOriginal = `resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = [3389]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`

// fixvPatched is the same file after `fix --patch` narrowed only the port-22 rule.
const fixvPatched = `resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
  dynamic "ingress" {
    for_each = [3389]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
`

func sgFinding(canon string) model.Finding {
	return model.Finding{CanonicalID: canon, File: "main.tf", Resource: model.Resource{ID: "aws_security_group.web"}}
}

func TestVerifyPatchSGRDPStillOpenIsNotFixed(t *testing.T) {
	r := verifyPatchResult(sgFinding("EC2_SG_OPEN_RDP"), iac.Patch{File: "main.tf", Address: "aws_security_group.web", After: fixvPatched})
	if r.Verdict != verdictNotFixed || !strings.Contains(r.Reason, "EC2_SG_OPEN_RDP still present") {
		t.Fatalf("RDP still open via dynamic ingress: %+v, want not fixed: EC2_SG_OPEN_RDP still present", r)
	}
	if r := verifyPatchResult(sgFinding("EC2_SG_OPEN_ALL"), iac.Patch{File: "main.tf", After: fixvPatched}); r.Verdict != verdictNotFixed {
		t.Errorf("EC2_SG_OPEN_ALL with 3389 world-open: %+v, want not fixed", r)
	}
	// Port 22 is narrowed to a variable: SSH is fixed as far as the file shows, but a
	// variable cidr cannot be confirmed closed statically.
	if r := verifyPatchResult(sgFinding("EC2_SG_OPEN_SSH"), iac.Patch{File: "main.tf", After: fixvPatched}); r.Verdict == verdictNotFixed {
		t.Errorf("SSH narrowed to var.allowed_cidrs reported still present: %+v", r)
	}
	closed := strings.Replace(fixvPatched, `cidr_blocks = ["0.0.0.0/0"]`, `cidr_blocks = ["10.0.0.0/8"]`, 1)
	closed = strings.Replace(closed, "var.allowed_cidrs", `["10.1.0.0/16"]`, 1)
	if r := verifyPatchResult(sgFinding("EC2_SG_OPEN_RDP"), iac.Patch{File: "main.tf", After: closed}); r.Verdict != verdictVerified {
		t.Errorf("RDP closed in every rule: %+v, want verified", r)
	}
	// Unknown for_each: cannot confirm.
	unk := strings.Replace(closed, "for_each = [3389]", "for_each = var.ports", 1)
	unk = strings.Replace(unk, `cidr_blocks = ["10.0.0.0/8"]`, `cidr_blocks = ["0.0.0.0/0"]`, 1)
	if r := verifyPatchResult(sgFinding("EC2_SG_OPEN_RDP"), iac.Patch{File: "main.tf", After: unk}); r.Verdict != verdictUnverified {
		t.Errorf("dynamic ingress over var.ports open to the world: %+v, want unverified", r)
	}
}

func TestVerifyPatchUnmappedOrUnusableIsUnverified(t *testing.T) {
	fixed := "resource \"aws_instance\" \"web\" {\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n"
	arn := model.Finding{CanonicalID: "EC2_IMDSV1", Resource: model.Resource{ID: "arn:aws:ec2:us-east-1:1:instance/i-1"}}
	if r := verifyPatchResult(arn, iac.Patch{File: "main.tf", After: fixed}); r.Verdict != verdictUnverified {
		t.Errorf("unmapped ARN: %+v, want unverified", r)
	}
	// The scanner has no check that can confirm this canonical id.
	nsg := model.Finding{CanonicalID: "AZ_NSG_OPEN_RDP", File: "main.tf", Resource: model.Resource{ID: "azurerm_network_security_rule.r"}}
	if r := verifyPatchResult(nsg, iac.Patch{File: "main.tf", After: "resource \"azurerm_network_security_rule\" \"r\" {\n  access = \"Deny\"\n}\n"}); r.Verdict != verdictUnverified {
		t.Errorf("no scanner check for AZ_NSG_OPEN_RDP: %+v, want unverified", r)
	}
	// A different resource's PASS does not verify this one.
	other := model.Finding{CanonicalID: "EC2_IMDSV1", File: "main.tf", Resource: model.Resource{ID: "aws_instance.other"}}
	if r := verifyPatchResult(other, iac.Patch{File: "main.tf", After: fixed}); r.Verdict != verdictUnverified {
		t.Errorf("finding resource absent from the re-scan: %+v, want unverified", r)
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))
	ok := model.Finding{CanonicalID: "EC2_IMDSV1", File: "main.tf", Resource: model.Resource{ID: "aws_instance.web"}}
	if r := verifyPatchResult(ok, iac.Patch{File: "main.tf", After: fixed}); r.Verdict != verdictUnverified {
		t.Errorf("unusable temp dir: %+v, want unverified", r)
	}
}

// CLI: the me/fixv repro end to end. fix --patch must not report "✓ patched" and
// must leave the file untouched when the finding it was asked to fix is still there.
func TestFixPatchSGRDPReportsNotFixed(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "f.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	tf := filepath.Join(infra, "main.tf")
	os.WriteFile(tf, []byte(fixvOriginal), 0o644)
	find := filepath.Join(dir, "find.json")
	os.WriteFile(find, []byte(`[{"source":"x","check_id":"sg_rdp","canonical_id":"EC2_SG_OPEN_RDP","title":"rdp open","severity":"HIGH","status":"FAIL","provider":"aws","account":"111122223333","region":"us-east-1","resource":{"id":"arn:aws:ec2:us-east-1:111122223333:security-group/sg-0rdp","type":"aws_security_group","name":"sg-0rdp"}}]`), 0o644)
	state := filepath.Join(dir, "state.json")
	os.WriteFile(state, []byte(`{"version":4,"resources":[{"mode":"managed","type":"aws_security_group","name":"web","instances":[{"attributes":{"id":"sg-0rdp","arn":"arn:aws:ec2:us-east-1:111122223333:security-group/sg-0rdp"}}]}]}`), 0o644)
	run(t, "ingest", find, "--source", "native", "-o", "summary")
	out, err := runErr(t, "fix", "--finding", "EC2_SG_OPEN_RDP", "--patch", "--iac", infra, "--tfstate", state)
	if err == nil || !strings.Contains(err.Error(), "not fixed: EC2_SG_OPEN_RDP still present") {
		t.Fatalf("fix --patch on the RDP repro: err=%v out=%s\nwant an error naming \"not fixed: EC2_SG_OPEN_RDP still present\"", err, out)
	}
	if strings.Contains(out, "✓ patched") {
		t.Fatalf("claimed a fix it did not make:\n%s", out)
	}
	if b, _ := os.ReadFile(tf); string(b) != fixvOriginal {
		t.Fatalf("file changed although the finding was not fixed:\n%s", b)
	}
}

// --require-verify: a patch that cannot be confirmed is not written and the command fails.
func TestFixPatchRequireVerifyRefusesUnverified(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "f.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	tf := filepath.Join(infra, "main.tf")
	src := "resource \"aws_security_group\" \"web\" {\n  dynamic \"ingress\" {\n    for_each = var.ports\n    content {\n      from_port   = ingress.value\n      to_port     = ingress.value\n      protocol    = \"tcp\"\n      cidr_blocks = [\"0.0.0.0/0\"]\n    }\n  }\n  ingress {\n    from_port   = 3389\n    to_port     = 3389\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n"
	os.WriteFile(tf, []byte(src), 0o644)
	find := filepath.Join(dir, "find.json")
	os.WriteFile(find, []byte(`[{"source":"x","check_id":"sg_rdp","canonical_id":"EC2_SG_OPEN_RDP","severity":"HIGH","status":"FAIL","provider":"aws","account":"1","file":"main.tf","resource":{"id":"aws_security_group.web","type":"aws_security_group","name":"web"}}]`), 0o644)
	run(t, "ingest", find, "--source", "native", "-o", "summary")
	_, err := runErr(t, "fix", "--finding", "EC2_SG_OPEN_RDP", "--patch", "--iac", infra, "--require-verify")
	if err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("--require-verify with an unconfirmable patch: err=%v, want an unverified failure", err)
	}
	if b, _ := os.ReadFile(tf); string(b) != src {
		t.Fatalf("--require-verify wrote an unverified patch:\n%s", b)
	}
	// Without --require-verify the patch is written but reported as unverified, not ✓.
	out, err := runErr(t, "fix", "--finding", "EC2_SG_OPEN_RDP", "--patch", "--iac", infra)
	if err != nil {
		t.Fatalf("fix without --require-verify: %v\n%s", err, out)
	}
	if strings.Contains(out, "✓ patched") || !strings.Contains(out, "unverified") {
		t.Fatalf("an unconfirmed patch must be reported as unverified, not ✓:\n%s", out)
	}
}
