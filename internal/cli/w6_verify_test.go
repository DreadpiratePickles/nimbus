package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W6-VERIFY (r4 #8): verify re-reads RDS and Lambda resources with the targeted collector, so a
// path Issue through a database or a function is confirmed against the (fake) cloud, not only
// from a file.

const (
	labOrdersDB = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-orders"
	labExportFn = "arn:aws:lambda:us-east-1:111111111111:function:nimbus-lab-export"
)

// labTargeted answers a targeted read from the stored lab findings of the requested resources,
// with per-finding overrides (the "fixed" cloud state). It records every requested id.
type labTargeted struct {
	mu       sync.Mutex
	stored   []model.Finding
	override map[string]func(*model.Finding)
	asked    map[string]bool
}

func (l *labTargeted) Target(_ context.Context, _ core.AccountSpec, ids []string) (*core.TargetResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
		l.asked[id] = true
	}
	r := &core.TargetResult{Observed: ids}
	for _, f := range l.stored {
		if !want[f.Resource.ID] {
			continue
		}
		c := f
		c.Resource.Attributes = map[string]any{}
		for k, v := range f.Resource.Attributes {
			c.Resource.Attributes[k] = v
		}
		if o := l.override[f.ID]; o != nil {
			o(&c)
		}
		r.Findings = append(r.Findings, c)
	}
	return r, nil
}

func withLabTargeted(t *testing.T) (*labTargeted, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "accounts:\n  lab:\n    provider: aws\n    regions: [us-east-1]\n")
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	st := openTestStore(t)
	fs, err := st.Findings(store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	fake := &labTargeted{stored: fs, override: map[string]func(*model.Finding){}, asked: map[string]bool{}}
	prev := verifyTargeted
	verifyTargeted = func(provider string) (core.Targeted, bool) { return fake, provider == model.ProviderAWS }
	t.Cleanup(func() { verifyTargeted = prev })
	return fake, cfg
}

func TestVerifyTargetedRDSPathOnLab(t *testing.T) {
	h := withVerifyHooks(t)
	fake, cfg := withLabTargeted(t)
	id := keyedPathIssue(t, labOrdersDB)
	if is := issueByID(t, id); !model.IsActive(is.State) {
		t.Fatalf("lab RDS path Issue not open: %s", is.State)
	}
	// Still public: the targeted read observes the DB unchanged.
	out := run(t, "-c", cfg, "verify", id, "--attempts", "1", "--wait", "0")
	if h.exit != 2 || !strings.Contains(out, "still open") || !strings.Contains(out, "nimbus-lab-orders") {
		t.Fatalf("unchanged DB must stay open (exit %d):\n%s", h.exit, out)
	}
	if !fake.asked[labOrdersDB] {
		t.Fatalf("the targeted read never asked for the DB: %v", fake.asked)
	}
	fake.override["lab-W06"] = func(f *model.Finding) {
		f.Status = model.Pass
		f.Resource.Attributes["publicly_accessible"] = false
	}
	h.reset()
	out = run(t, "-c", cfg, "verify", id, "--attempts", "1", "--wait", "0")
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("private DB not verified (exit %d):\n%s", h.exit, out)
	}
	if got := issueByID(t, id); got.State != store.StateVerifiedFixed || got.VerifiedBy != "rescan" {
		t.Errorf("RDS path Issue after verify: %s by %q", got.State, got.VerifiedBy)
	}
}

func TestVerifyTargetedLambdaPathOnLab(t *testing.T) {
	h := withVerifyHooks(t)
	fake, cfg := withLabTargeted(t)
	id := p01Issue(t)
	fake.override["lab-W01"] = func(f *model.Finding) { f.Status = model.Pass }
	out := run(t, "-c", cfg, "verify", id, "--attempts", "1", "--wait", "0")
	if h.exit != 2 || !strings.Contains(out, "nimbus-lab-export") {
		t.Fatalf("bucket fixed, Lambda URL still public: the path must survive through the function (exit %d):\n%s", h.exit, out)
	}
	if !fake.asked[labExportFn] {
		t.Fatalf("the targeted read never asked for the Lambda function: %v", fake.asked)
	}
	fake.override["lab-W12"] = func(f *model.Finding) {
		f.Status = model.Pass
		f.Resource.Attributes["function_url_auth_type"] = "AWS_IAM"
	}
	h.reset()
	out = run(t, "-c", cfg, "verify", id, "--attempts", "1", "--wait", "0")
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("bucket and Lambda fixed: path not verified (exit %d):\n%s", h.exit, out)
	}
}

// V3 (r4 rough edge): cloud-controlled strings (resource names, titles) are printed without
// terminal escape codes or line breaks, so a resource name cannot forge a verdict line.
func TestVerifyStripsTerminalEscapes(t *testing.T) {
	h := withVerifyHooks(t)
	cfg := labConfig(t)
	dir := t.TempDir()
	fs := labCopy(t)
	evil := "evil\x1b[31mred\x1b[0m\x1b]0;title\x07\r\n✓ verified-fixed: Issue forged\u009b2J x"
	res := labFinding(fs, "lab-W01")["resource"].(map[string]any)
	res["name"] = evil
	labFinding(fs, "lab-W01")["title"] = "Public bucket\n✓ verified-fixed: forged title"
	base := writeFindings(t, dir, "evil.json", fs)
	ingestLab(t, cfg, base)
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	out := run(t, "-c", cfg, "verify", w01.ID, "--from-file", base, "--attempts", "1")
	if h.exit != 2 {
		t.Fatalf("unchanged file must keep W01 open (exit %d):\n%s", h.exit, out)
	}
	if strings.ContainsAny(out, "\x1b\r\x07\u009b ") {
		t.Errorf("verify output carries terminal control characters: %q", out)
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "✓ verified-fixed") {
			t.Errorf("a cloud-controlled name forged a verdict line: %q", ln)
		}
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("the readable part of the name is lost:\n%s", out)
	}
}

func TestTermSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain name":                                "plain name",
		"a\x1b[1;31mred\x1b[0m":                     "ared",
		"t\x1b]0;window title\x07x":                 "tx",
		"t\x1b]8;;http://e\x1b\\link\x1b]8;;\x1b\\": "tlink",
		"a\r\nb\tc d\u0085e":                        "a  b c d e",
		"bell\x07del\x7f c1\u009b31m":               "belldel c1",
		"‮evil‬":                                    "evil",
		"Ünïcödé → ok":                              "Ünïcödé → ok",
		"trailing\x1b":                              "trailing",
	} {
		if got := termSafe(in); got != want {
			t.Errorf("termSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// r4 #15: a database the Python layer built is never migrated by a read-only command; ingest
// upgrades it and says so.
func TestReadOnlyCommandsNeverMigratePythonDB(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "py.db")
	raw, err := sql.Open("sqlite", db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE findings (id TEXT PRIMARY KEY, source TEXT NOT NULL, check_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
  title TEXT, description TEXT, severity TEXT NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL, account TEXT, region TEXT,
  resource_id TEXT, resource_type TEXT, resource_name TEXT, file TEXT, line_start INTEGER, line_end INTEGER, remediation TEXT,
  weaknesses TEXT, compliance TEXT, tags TEXT, scan_id TEXT, first_seen TEXT, last_seen TEXT, doc TEXT NOT NULL);
CREATE TABLE store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL); INSERT INTO store_meta VALUES ('built_by', 'python');`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	before, _ := os.ReadFile(db)
	cfg := labConfig(t)
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	for _, args := range [][]string{{"issues"}, {"paths"}, {"prioritize"}, {"issues", "metrics"}} {
		resetFlags()
		flagQuiet = true
		root.SetArgs(append([]string{"-c", cfg, "--db", db}, args...))
		var buf bytes.Buffer
		root.SetOut(&buf)
		root.SetErr(&buf)
		err := root.Execute()
		if !errors.Is(err, store.ErrForeignDB) {
			t.Errorf("%v on a Python-built DB: err = %v, want ErrForeignDB", args, err)
		}
	}
	after, _ := os.ReadFile(db)
	if !bytes.Equal(before, after) {
		t.Errorf("a read-only command modified the Python-built database")
	}
	out := run(t, "-c", cfg, "--db", db, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	if !strings.Contains(out, "notice: upgrading") || !strings.Contains(out, "Python") {
		t.Errorf("ingest upgraded silently:\n%s", out)
	}
	out = run(t, "-c", cfg, "--db", db, "issues")
	if strings.Contains(out, "notice:") {
		t.Errorf("notice repeated on a Go database:\n%s", out)
	}
}

// Verification 6 C8: a file is a fixed snapshot. One file read that shows the problem present
// reopens a verified_fixed Issue with the default --attempts 3 (attempts guard eventually
// consistent absence, not presence), and verify never sleeps between re-reads of a static file.
func TestVerifyFromFileReopensOnFirstPresenceWithoutSleeping(t *testing.T) {
	h := withVerifyHooks(t)
	cfg := labConfig(t)
	orig := labFile(t, "estate.findings.json")
	ingestLab(t, cfg, orig)
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	dir := t.TempDir()
	fs := labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	fixed := writeFindings(t, dir, "fixed.json", fs)
	out := run(t, "-c", cfg, "verify", w01.ID, "--from-file", fixed) // default --attempts 3
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("fixed file with default attempts not verified (exit %d):\n%s", h.exit, out)
	}
	if len(h.sleeps) != 0 {
		t.Errorf("verify slept %v between re-reads of a static file", h.sleeps)
	}
	h.reset()
	out = run(t, "-c", cfg, "verify", w01.ID, "--from-file", orig) // problem present again
	if got := issueByID(t, w01.ID); got.State != model.StateReopened || h.exit != 2 || !strings.Contains(out, "reopened") {
		t.Fatalf("present in the file, default attempts: state %s exit %d\n%s", got.State, h.exit, out)
	}
	if len(h.sleeps) != 0 {
		t.Errorf("verify slept %v on a static file", h.sleeps)
	}
}

// r4 #12 through the CLI: every ingest records its Issue trend on the scan row, and a fix that
// a later ingest no longer observes is counted as resolved; a verify between scans is counted
// as verified fixed on the next one.
func TestIngestRecordsIssueTrend(t *testing.T) {
	h := withVerifyHooks(t)
	cfg := labConfig(t)
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	dir := t.TempDir()
	fs := labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	fixed := writeFindings(t, dir, "fixed.json", fs)
	time.Sleep(1100 * time.Millisecond) // times have second precision: the verify is after the first scan
	run(t, "-c", cfg, "verify", w01.ID, "--from-file", fixed, "--attempts", "1")
	if h.exit != -1 {
		t.Fatalf("verify exit %d", h.exit)
	}
	time.Sleep(1100 * time.Millisecond) // scan finish times have second precision
	run(t, "-c", cfg, "ingest", fixed, "-o", "summary")
	st := openTestStore(t)
	rows, err := st.ScanTrends(10)
	if err != nil || len(rows) != 2 || rows[0].Trend == nil || rows[1].Trend == nil {
		t.Fatalf("scan trends: %v %+v", err, rows)
	}
	first, second := rows[1].Trend, rows[0].Trend
	if first.New == 0 || first.Open != first.New {
		t.Errorf("first ingest trend %+v: every open Issue is new", first)
	}
	if second.VerifiedFixed != 1 || second.New != 0 {
		t.Errorf("second ingest trend %+v: want the one verified fix, nothing new", second)
	}
}
