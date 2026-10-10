package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/devx"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/query"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// TestIngestCraftedResourceTypeCannotDropTables reproduces inventory defect 3: a resource type
// in an ingested file was interpolated into view DDL, and this payload dropped `findings`.
func TestIngestCraftedResourceTypeCannotDropTables(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	crafted := filepath.Join(dir, "crafted.findings.json")
	payload := `[{"source":"native","check_id":"c","canonical_id":"S3_PUBLIC_BUCKET","title":"t","severity":"HIGH","status":"FAIL","provider":"aws","account":"1",
	  "resource":{"id":"r1","type":"x;DROP\tTABLE\tfindings;--","name":"r1"}},
	 {"source":"native","check_id":"c2","canonical_id":"S3_PUBLIC_BUCKET","title":"t2","severity":"HIGH","status":"FAIL","provider":"aws","account":"1",
	  "resource":{"id":"r2","type":"aws_s3_bucket","name":"good"}}]`
	if err := os.WriteFile(crafted, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, "ingest", crafted, "--source", "native", "-o", "summary")
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := query.EnsureAllViews(st); err != nil { // what every query/schema call runs
		t.Errorf("EnsureAllViews: %v", err)
	}
	if !st.TableExists("findings") {
		t.Fatal("crafted resource type dropped the findings table")
	}
	var n int
	st.DB().QueryRow("SELECT COUNT(*) FROM findings").Scan(&n)
	if n != 2 {
		t.Fatalf("findings count = %d, want 2", n)
	}
	out := run(t, "query", "SELECT name FROM aws_s3_buckets", "--engine", "local")
	if !strings.Contains(out, "good") {
		t.Fatalf("legit view missing after crafted ingest: %s", out)
	}
}

// runSelf re-executes the test binary so flag defaults are computed with the given env (they
// are bound at init time, which is exactly how the token leaked into --help).
func runSelf(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCLI$")
	cmd.Env = append(os.Environ(), append(env, "NIMBUS_CLI_HELPER_ARGS="+strings.Join(args, "\x1f"))...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestHelperCLI is not a real test: runSelf uses it to run the CLI in a child process.
func TestHelperCLI(t *testing.T) {
	a := os.Getenv("NIMBUS_CLI_HELPER_ARGS")
	if a == "" {
		t.Skip("helper")
	}
	root.SetArgs(strings.Split(a, "\x1f"))
	if err := root.Execute(); err != nil {
		fmt.Println("error:", err)
	}
	os.Exit(0)
}

func TestServeDefaultsLoopbackAndHidesToken(t *testing.T) {
	const secret = "tok-should-never-print-4242"
	out := runSelf(t, []string{"CLOUD_POSTURE_TOKEN=" + secret}, "serve", "--help")
	if strings.Contains(out, secret) {
		t.Errorf("serve --help leaks CLOUD_POSTURE_TOKEN:\n%s", out)
	}
	if !strings.Contains(out, "$CLOUD_POSTURE_TOKEN") {
		t.Errorf("serve --help should say the token comes from $CLOUD_POSTURE_TOKEN:\n%s", out)
	}
	if f := serveCmd.Flags().Lookup("addr"); f == nil || f.DefValue != "127.0.0.1:8080" {
		t.Errorf("--addr default = %v, want 127.0.0.1:8080", f)
	}
	for _, name := range []string{"allowed-host", "query-timeout"} {
		if serveCmd.Flags().Lookup(name) == nil {
			t.Errorf("serve is missing --%s", name)
		}
	}
	if f := serveCmd.Flags().Lookup("query-timeout"); f != nil && f.DefValue != "10s" {
		t.Errorf("--query-timeout default = %s, want 10s", f.DefValue)
	}
}

func TestNeo4jPasswordFlagRemoved(t *testing.T) {
	out := runSelf(t, nil, "graph", "push", "--help")
	if strings.Contains(out, "--password") {
		t.Errorf("graph push --help still offers --password:\n%s", out)
	}
	out = runSelf(t, nil, "graph", "push", "--uri", "bolt://127.0.0.1:1", "--password", "hunter2")
	if !strings.Contains(out, "NEO4J_PASSWORD") || strings.Contains(out, "hunter2") {
		t.Errorf("--password must fail with a pointer to NEO4J_PASSWORD and not echo the value:\n%s", out)
	}
}

const imdsTF = `resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
`

// Inventory defect 5: --patch read and wrote finding.File relative to --iac with no containment.
func TestPatchRejectsFilesOutsideIaCRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "iac")
	os.MkdirAll(root, 0o755)
	outside := filepath.Join(base, "outside.tf")
	os.WriteFile(outside, []byte(imdsTF), 0o644)
	os.Symlink(outside, filepath.Join(root, "link.tf"))
	old := fixFlags
	t.Cleanup(func() { fixFlags = old })
	fixFlags.iacRoot, fixFlags.patch, fixFlags.all = root, true, false
	flagQuiet = true
	for _, file := range []string{"../outside.tf", outside, "link.tf"} {
		f := model.Finding{CanonicalID: "EC2_IMDSV1", File: file, Resource: model.Resource{ID: "aws_instance.web", Name: "web"}}
		if err := runPatch([]model.Finding{f}, nil); err == nil {
			t.Errorf("runPatch(%q) succeeded", file)
		}
		if b, _ := os.ReadFile(outside); string(b) != imdsTF {
			t.Fatalf("runPatch(%q) rewrote a file outside --iac:\n%s", file, b)
		}
	}
}

// The `fix --ai` file name embeds the resource name; it must not escape --out-dir.
func TestFixOutputFileContained(t *testing.T) {
	out := t.TempDir()
	f := model.Finding{CanonicalID: "S3_PUBLIC_BUCKET", Resource: model.Resource{Name: "../../../tmp/evil"}}
	name := aiFixFileName(f, remediation.Terraform)
	if strings.ContainsAny(name, `/\`) || name == ".." {
		t.Errorf("ai fix file name not sanitized: %q", name)
	}
	escaped := filepath.Join(filepath.Dir(filepath.Dir(out)), "escape.tf")
	os.Remove(escaped) // left behind by a pre-fix run
	if err := writeFixFile(out, "../../escape.tf", "x"); err == nil {
		t.Error("writeFixFile accepted a path outside --out-dir")
	}
	if _, err := os.Stat(escaped); err == nil {
		t.Error("escape.tf written outside --out-dir")
	}
	if err := writeFixFile(out, name, "ok"); err != nil {
		t.Errorf("writeFixFile(%q): %v", name, err)
	}
}

// Inventory defect 12: the CLI ran `python -m nimbus…` from ./python or ../python (and with the
// working directory on sys.path), so a malicious checkout executed code on any scan.
func TestPythonNotLoadedFromWorkingDirectory(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	marker := filepath.Join(base, "PWNED")
	evil := fmt.Sprintf("open(%q, 'a').write(__file__ + '\\n')\n", marker)
	for _, pkg := range []string{filepath.Join(work, "python", "nimbus"), filepath.Join(base, "python", "nimbus"), filepath.Join(work, "nimbus")} {
		os.MkdirAll(pkg, 0o755)
		for _, f := range []string{"__init__.py", "__main__.py", "risk.py"} {
			os.WriteFile(filepath.Join(pkg, f), []byte(evil), 0o644)
		}
	}
	t.Chdir(work)
	t.Setenv("NIMBUS_PYTHON_DIR", "")
	t.Setenv("PYTHONPATH", "")
	t.Setenv("CLOUD_POSTURE_PYTHON", py)
	python(nil)
	runPython(context.Background(), py, nil, "-m", "nimbus.risk", "--help")
	runPython(context.Background(), py, nil, "-c", "import nimbus")
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("Python code from the working directory was executed:\n%s", b)
	}
}

// Inventory defect 8: --fail-on, JSON/SARIF output and --alert used every stored finding, so a
// clean scan still failed CI (and uploaded stale SARIF) because of an earlier scan's findings.
func TestScanGateUsesOnlyCurrentScanFindings(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python") // keep the Python layer out of this test
	mk := func(scan, check string, sev model.Severity) model.Finding {
		f := model.Finding{Source: "native", CheckID: check, CanonicalID: "X_" + check, Title: check, Severity: sev, Status: model.Fail, Provider: "aws", Account: "1",
			Resource: model.Resource{ID: "r-" + check, Type: "aws_s3_bucket", Name: check}, ScanID: scan}
		f.Finalize(time.Now())
		return f
	}
	ctx := context.Background()
	if _, err := finishScan(ctx, nil, []model.Finding{mk("scan-1", "old", model.Critical)}, graph.New(), nil, model.ScanSummary{ScanID: "scan-1"}, false); err != nil {
		t.Fatal(err)
	}
	res, err := finishScan(ctx, nil, []model.Finding{mk("scan-2", "new", model.Low)}, graph.New(), nil, model.ScanSummary{ScanID: "scan-2"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].ScanID != "scan-2" {
		t.Fatalf("scan result holds %d finding(s) %v; want only scan-2's", len(res.Findings), scanIDs(res.Findings))
	}
	if n := gateCount(res.Findings, "HIGH"); n != 0 {
		t.Errorf("--fail-on HIGH counts %d finding(s) from an earlier scan", n)
	}
	out := filepath.Join(dir, "out.sarif")
	if err := emit(res, "summary", "", out, 0); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if sarif := strings.ToUpper(string(b)); strings.Contains(sarif, "X_OLD") || !strings.Contains(sarif, "X_NEW") {
		t.Errorf("SARIF must contain only the current scan's findings:\n%s", b)
	}
	// stored history is kept; since Track G (defect 19a) scan-2 re-examined the same
	// source/provider/account scope, so scan-1's finding is resolved rather than current.
	st, _ := store.Open(flagDB)
	defer st.Close()
	if all, _ := st.Findings(store.Filter{IncludeResolved: true}); len(all) != 2 {
		t.Errorf("store should keep both scans' findings, has %d", len(all))
	}
	if cur, _ := st.Findings(store.Filter{}); len(cur) != 1 || cur[0].ScanID != "scan-2" {
		t.Errorf("current posture should hold only scan-2's finding, has %v", scanIDs(cur))
	}
}

func scanIDs(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ScanID)
	}
	return out
}

func TestPreCommitHookDoesNotStore(t *testing.T) {
	for name, s := range map[string]string{"git hook": devx.GitHookScript, "pre-commit yaml": devx.PreCommitHooksYAML} {
		if !strings.Contains(s, "--no-store") {
			t.Errorf("%s must pass --no-store:\n%s", name, s)
		}
	}
}
