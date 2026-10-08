package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	root.SetArgs(args)
	err := root.Execute()
	w.Close()
	os.Stdout = old
	var out bytes.Buffer
	out.ReadFrom(r)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String() + buf.String()
}

func TestIngestQueryPathsFix(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	testdata, _ := filepath.Abs(filepath.Join("..", "..", "testdata"))
	out := run(t, "ingest", testdata, "-o", "summary")
	if !strings.Contains(out, "Attack paths:") {
		t.Fatalf("ingest output: %s", out)
	}
	out = run(t, "query", "SELECT name FROM aws_s3_buckets WHERE public_access = 1", "--engine", "local")
	if !strings.Contains(out, "customer-pii-exports") {
		t.Fatalf("query: %s", out)
	}
	out = run(t, "paths", "--fixes", "--limit", "2")
	if !strings.Contains(out, "Cheapest fix set") {
		t.Fatalf("paths: %s", out)
	}
	out = run(t, "fix", "--finding", "S3_PUBLIC_BUCKET", "--generate-terraform", "--print")
	if !strings.Contains(out, "aws_s3_bucket_public_access_block") {
		t.Fatalf("fix: %s", out)
	}
	out = run(t, "report", "--framework", "cis", "--provider", "aws")
	if !strings.Contains(out, "2.1.4") {
		t.Fatalf("report: %s", out)
	}
	run(t, "dashboard", "--out", filepath.Join(dir, "d.html"))
	if st, err := os.Stat(filepath.Join(dir, "d.html")); err != nil || st.Size() < 50000 {
		t.Fatalf("dashboard not rendered")
	}
}
