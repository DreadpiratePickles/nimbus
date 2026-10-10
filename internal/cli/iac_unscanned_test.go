package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Verify-3 defect 2: an IaC file the scanner could not parse (syntax error, size or
// depth limit) must fail closed. Its scope was not observed, so its stored findings
// stay open, and its IAC_PARSE_LIMIT finding counts toward --fail-on as HIGH unless
// --fail-on-unscanned=false.

const evadeBucket = "resource \"aws_s3_bucket\" \"pub\" {\n  bucket = \"x\"\n  acl    = \"public-read\"\n}\n"

// evadeTail is the verify-3/evade/bad payload: 300 nested '[' in a locals block.
var evadeTail = "locals {\n  pad = " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n}\n"

func bucketStates(t *testing.T, db string) map[string]string {
	t.Helper()
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.DB().Query("SELECT canonical_id || '|' || COALESCE(file,''), state FROM findings WHERE status = 'FAIL' AND canonical_id LIKE 'S3_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, s string
		rows.Scan(&k, &s)
		m[k] = s
	}
	return m
}

func iacEnv(t *testing.T) []string {
	return []string{"CLOUD_POSTURE_PYTHON=/nonexistent/python", "PATH=/nonexistent", "CLOUD_POSTURE_NO_NETWORK=1"}
}

// The evade repro: the bucket and 300 nested '[' in the same file, next to a clean
// file. The scan must exit non-zero under --fail-on high and the bucket stays open.
func TestIaCUnparseableFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "x.db")
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	main := filepath.Join(infra, "main.tf")
	os.WriteFile(main, []byte(evadeBucket), 0o644)
	os.WriteFile(filepath.Join(infra, "other.tf"), []byte("resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"logs\"\n  acl    = \"public-read\"\n}\n"), 0o644)
	if _, code := runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary"); code != 0 {
		t.Fatalf("baseline scan exit %d", code)
	}
	before := bucketStates(t, db)
	if !model.IsActive(before["S3_PUBLIC_BUCKET|main.tf"]) {
		t.Fatalf("setup: main.tf bucket must be open: %v", before)
	}
	os.WriteFile(main, []byte(evadeBucket+evadeTail), 0o644)
	out, code := runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "high")
	if code == 0 {
		t.Fatalf("scan with an unparseable file exited 0 under --fail-on high:\n%s", out)
	}
	// The evade repro at --fail-on critical: the public bucket is HIGH, so only the gap can
	// trip this threshold, and it must.
	if out, code := runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "critical"); code != 2 {
		t.Fatalf("evade repro passed --fail-on critical (exit %d):\n%s", code, out)
	}
	after := bucketStates(t, db)
	if !model.IsActive(after["S3_PUBLIC_BUCKET|main.tf"]) {
		t.Fatalf("bucket finding in the unparseable file was resolved: %v", after)
	}
}

// The gap alone (no other HIGH finding) trips the gate; --fail-on-unscanned=false
// turns that off; a whole-file corruption never resolves the file's findings.
func TestIaCUnscannedGateAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "y.db")
	infra := filepath.Join(dir, "infra")
	os.MkdirAll(infra, 0o755)
	bad := filepath.Join(infra, "bucket.tf")
	os.WriteFile(bad, []byte(evadeBucket), 0o644)
	os.WriteFile(filepath.Join(infra, "net.tf"), []byte("resource \"aws_instance\" \"web\" {\n  ami = \"a\"\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n"), 0o644)
	runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary")
	os.WriteFile(bad, []byte("resource \"aws_s3_bucket\" \"pub\" {\n  bucket = \"x\"\n  acl    = \"public-read\"\n"+evadeTail), 0o644) // unclosed block + deep nesting
	out, code := runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "high")
	if code == 0 {
		t.Fatalf("unscanned file did not trip --fail-on high:\n%s", out)
	}
	if st := bucketStates(t, db); !model.IsActive(st["S3_PUBLIC_BUCKET|bucket.tf"]) {
		t.Fatalf("finding of an unscanned file resolved: %v", st)
	}
	// Integration pass 2 item 4 (main-session decision): a scan gap blocks EVERY threshold
	// (output.GateBlocks), so --fail-on critical cannot be used to slip it through.
	out, code = runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "critical")
	if code != 2 || !strings.Contains(out, "not scanned") {
		t.Fatalf("a scan gap must block --fail-on critical (exit %d, want 2):\n%s", code, out)
	}
	for _, sev := range []string{"low", "medium", "info"} {
		if _, code := runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", sev); code != 2 {
			t.Errorf("--fail-on %s with a scan gap: exit %d, want 2", sev, code)
		}
	}
	out, code = runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "critical", "--fail-on-unscanned=false")
	if code != 0 {
		t.Fatalf("--fail-on-unscanned=false opts out at every threshold (exit %d):\n%s", code, out)
	}
	out, code = runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary", "--fail-on", "high", "--fail-on-unscanned=false")
	if code != 0 {
		t.Fatalf("--fail-on-unscanned=false must not count the scan gap (exit %d):\n%s", code, out)
	}
	// Fixing the file brings the scope back: the bucket is observed again (still open).
	os.WriteFile(bad, []byte(evadeBucket), 0o644)
	runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary")
	if st := bucketStates(t, db); !model.IsActive(st["S3_PUBLIC_BUCKET|bucket.tf"]) {
		t.Fatalf("bucket after the file was repaired: %v", st)
	}
	// Deleting the bucket from a parseable file still resolves it.
	os.WriteFile(bad, []byte("variable \"x\" {}\n"), 0o644)
	runSelfExit(t, dir, iacEnv(t), "scan", "--db", db, "-q", "--iac", infra, "-o", "summary")
	if st := bucketStates(t, db); st["S3_PUBLIC_BUCKET|bucket.tf"] != model.StateResolved {
		t.Fatalf("bucket removed from a parseable file must resolve: %v", st)
	}
}
