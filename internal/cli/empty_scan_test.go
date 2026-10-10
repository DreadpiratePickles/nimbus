package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Delta review 2 shortfall #11 / release readiness row 5: a first `scan` with nothing to scan
// (no accounts, no IaC root, no tools) must never report a false "clean". It exits 2 and says
// nothing was scanned, and writes nothing to the posture database.
func TestScanNothingScannedExits2(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o755)
	db := filepath.Join(dir, "p.db")
	env := append(iacEnv(t), "HOME="+home, "CLOUD_POSTURE_DB=")
	out, code := runSelfExit(t, dir, env, "scan", "--db", db, "-o", "summary")
	if code != 2 {
		t.Fatalf("empty scan exit %d, want 2:\n%s", code, out)
	}
	for _, want := range []string{"nothing scanned", "cloud-posture onboard", "--iac"} {
		if !strings.Contains(out, want) {
			t.Errorf("empty scan output lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"No findings", "Scan complete", "0 open findings"} {
		if strings.Contains(out, bad) {
			t.Errorf("empty scan must not claim a clean result (%q):\n%s", bad, out)
		}
	}
	// --fail-on never passes a scan that had no targets.
	if _, code := runSelfExit(t, dir, env, "scan", "--db", db, "-o", "summary", "--fail-on", "critical"); code != 2 {
		t.Errorf("empty scan with --fail-on critical exit %d, want 2", code)
	}
}

// An IaC root still counts as something scanned: a clean root exits 0.
func TestScanIaCRootIsNotEmpty(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o755)
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	os.WriteFile(filepath.Join(infra, "main.tf"), []byte("resource \"aws_instance\" \"web\" {\n  ami = \"a\"\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n"), 0o644)
	out, code := runSelfExit(t, dir, append(iacEnv(t), "HOME="+home), "scan", "--db", filepath.Join(dir, "p.db"), "-q", "--iac", infra, "-o", "summary")
	if code != 0 || strings.Contains(out, "nothing scanned") {
		t.Fatalf("IaC scan exit %d:\n%s", code, out)
	}
}

// `ingest` of an empty file (0 bytes, whitespace, or an empty JSON array) exits 2 with a
// message naming the file, not the misleading "no findings parsed".
func TestIngestEmptyFileExits2(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o755)
	env := append(iacEnv(t), "HOME="+home)
	for name, body := range map[string]string{"zero.json": "", "blank.json": " \n\t\n", "arr.json": "[]\n"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		out, code := runSelfExit(t, dir, env, "ingest", "--db", filepath.Join(dir, name+".db"), p)
		if code != 2 {
			t.Errorf("%s: ingest exit %d, want 2:\n%s", name, code, out)
		}
		if !strings.Contains(out, "nothing to ingest") || !strings.Contains(out, name) {
			t.Errorf("%s: message must say nothing to ingest and name the file:\n%s", name, out)
		}
		if strings.Contains(out, "no findings parsed") {
			t.Errorf("%s: misleading parse message:\n%s", name, out)
		}
	}
	// An unparseable file stays a parse error (exit 1) with the old hint.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{\"not\": \"a scanner format\"}"), 0o644)
	out, code := runSelfExit(t, dir, env, "ingest", "--db", filepath.Join(dir, "bad.db"), bad)
	if code != 1 || !strings.Contains(out, "--source") {
		t.Errorf("unparseable file: exit %d, want 1 with the --source hint:\n%s", code, out)
	}
}
