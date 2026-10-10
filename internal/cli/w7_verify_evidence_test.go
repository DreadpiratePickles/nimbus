package cli

import (
	"archive/zip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// W7-VERIFY r5 #9: `report --evidence-zip` signs the v2 manifest with NIMBUS_EVIDENCE_KEY (a
// throw-away test key here) and `verify --evidence <zip> --key <pub>` checks every digest and the
// signature: exit 0 on an untouched package, 2 on a tampered one or without the key.
func TestVerifyEvidenceCommand(t *testing.T) {
	bin, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign not installed")
	}
	h := withVerifyHooks(t)
	dir := labDB(t)
	kd := t.TempDir()
	gen := exec.Command(bin, "generate-key-pair")
	gen.Dir = kd
	gen.Env = append(os.Environ(), "COSIGN_PASSWORD=")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("test key: %v %s", err, out)
	}
	t.Setenv("COSIGN_PASSWORD", "")
	t.Setenv("NIMBUS_EVIDENCE_KEY", filepath.Join(kd, "cosign.key"))
	zp := filepath.Join(dir, "ev.zip")
	run(t, "report", "--framework", "cis_7.0_aws", "--evidence-zip", zp, "--out", filepath.Join(dir, "r.md"))

	out := run(t, "verify", "--evidence", zp, "--key", filepath.Join(kd, "cosign.pub"))
	if h.exit != -1 || !strings.Contains(out, "✓ evidence verified") || !strings.Contains(out, "signature valid") || !strings.Contains(out, "of 90 days") {
		t.Fatalf("untouched package (exit %d):\n%s", h.exit, out)
	}
	h.reset()
	out = run(t, "verify", "--evidence", zp)
	if h.exit != 2 || !strings.Contains(out, "--key") {
		t.Errorf("without --key the package is not called verified (exit %d):\n%s", h.exit, out)
	}
	// Tamper with report.md.
	bad := filepath.Join(dir, "bad.zip")
	copyZip(t, zp, bad, "report.md")
	h.reset()
	out = run(t, "verify", "--evidence", bad, "--key", filepath.Join(kd, "cosign.pub"))
	if h.exit != 2 || !strings.Contains(out, "report.md") {
		t.Errorf("tampered package (exit %d):\n%s", h.exit, out)
	}
	h.reset()
	out = run(t, "verify", "--evidence", zp, "--key", filepath.Join(kd, "cosign.pub"), "--json")
	if h.exit != -1 || !strings.Contains(out, `"signature_ok": true`) {
		t.Errorf("--json (exit %d):\n%s", h.exit, out)
	}
}

func copyZip(t *testing.T, src, dst, tamper string) {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	f, _ := os.Create(dst)
	zw := zip.NewWriter(f)
	for _, e := range zr.File {
		rc, _ := e.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if e.Name == tamper {
			b = append(b, []byte("\nedited\n")...)
		}
		w, _ := zw.Create(e.Name)
		w.Write(b)
	}
	zw.Close()
	f.Close()
}

// Verification 7 defect 8 (CLI): verify on a suppressed Issue that observes the weakness again
// printed "✗ reopened" while the Issue stayed suppressed. It now says it stays suppressed.
func TestVerifyOnSuppressedIssueSaysItStaysSuppressed(t *testing.T) {
	h := withVerifyHooks(t)
	ingestLab(t, labConfig(t), labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	run(t, "issues", "suppress", w01.ID, "--reason", "accepted for the audit", "--expires", "30d")
	out := run(t, "verify", w01.ID, "--from-file", labFile(t, "estate.findings.json"), "--attempts", "1")
	if strings.Contains(out, "✗ reopened") || !strings.Contains(out, "stays suppressed") {
		t.Fatalf("verify on a suppressed Issue (exit %d):\n%s", h.exit, out)
	}
	if got := issueByID(t, w01.ID); got.State != "suppressed" {
		t.Errorf("state = %s", got.State)
	}
}
