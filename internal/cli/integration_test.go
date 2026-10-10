package cli

// Integration pass 1 (CLI/API wiring of Tracks C, F and G plus the hardening verifier's CLI items).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// ingestTestdata ingests ../../testdata into a fresh database and returns its directory.
func ingestTestdata(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", testdataDir(t), "-o", "summary")
	return dir
}

// runErr is run() for commands that are expected to fail.
func runErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	resetFlags()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { out.ReadFrom(r); close(done) }() // drain concurrently: output can exceed the pipe buffer
	root.SetArgs(args)
	err := root.Execute()
	w.Close()
	os.Stdout = old
	<-done
	return out.String() + buf.String(), err
}

// runSelfExit runs the CLI in a child process (so os.Exit codes are observable) from dir.
func runSelfExit(t *testing.T, dir string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperCLIExit$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append(env, "NIMBUS_CLI_EXIT_ARGS="+strings.Join(args, "\x1f"))...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// TestHelperCLIExit is not a real test: runSelfExit uses it; it exits 1 on a command error
// exactly like cmd/cloud-posture/main.go.
func TestHelperCLIExit(t *testing.T) {
	a := os.Getenv("NIMBUS_CLI_EXIT_ARGS")
	if a == "" {
		t.Skip("helper")
	}
	root.SetArgs(strings.Split(a, "\x1f"))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMain(m *testing.M) {
	// No test in this package may reach the real KEV/EPSS feeds.
	os.Setenv("CLOUD_POSTURE_NO_NETWORK", "1")
	os.Exit(m.Run())
}

func loadConfigFile(t *testing.T, path string) (*config.Config, error) {
	t.Helper()
	old := flagConfig
	defer func() { flagConfig = old }()
	flagConfig = path
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	return c, nil
}

// ---------------------------------------------------------------- item 1: one score (Track F)

func TestPrioritizeJSONCarriesScoreVersionAndExplanation(t *testing.T) {
	dir := ingestTestdata(t)
	// ingest writes Go's ranking beside the DB (<db>.risk.json) for the Python layer.
	rj := filepath.Join(dir, "p.db.risk.json")
	var fromIngest []risk.Ranked
	if b, err := os.ReadFile(rj); err != nil || json.Unmarshal(b, &fromIngest) != nil || len(fromIngest) == 0 {
		t.Fatalf("ingest did not write %s (%v)", rj, err)
	}
	os.Remove(rj)
	out := run(t, "prioritize", "--json", "--top", "3")
	var ranked []map[string]any
	if err := json.Unmarshal([]byte(out), &ranked); err != nil || len(ranked) == 0 {
		t.Fatalf("prioritize --json: %v\n%s", err, out)
	}
	for _, r := range ranked {
		if r["score_version"] != risk.ScoreVersion {
			t.Errorf("score_version = %v, want %s", r["score_version"], risk.ScoreVersion)
		}
		ex, _ := r["explanation"].(map[string]any)
		if ex == nil || len(ex["factors"].([]any)) == 0 {
			t.Errorf("ranked entry without explanation factors: %v", r["explanation"])
		}
	}
	var fromPrioritize []risk.Ranked
	if b, err := os.ReadFile(rj); err != nil || json.Unmarshal(b, &fromPrioritize) != nil || len(fromPrioritize) == 0 {
		t.Fatalf("prioritize did not write %s (%v)", rj, err)
	}
	if fromPrioritize[0].Score != fromIngest[0].Score || fromPrioritize[0].Finding.ID != fromIngest[0].Finding.ID {
		t.Errorf("risk.json differs between ingest and prioritize: %v/%s vs %v/%s", fromIngest[0].Score, fromIngest[0].Finding.ID, fromPrioritize[0].Score, fromPrioritize[0].Finding.ID)
	}
	if fromPrioritize[0].ScoreVersion != risk.ScoreVersion || fromPrioritize[0].Explanation == nil {
		t.Errorf("risk.json entries must carry score_version and explanation")
	}
}

// V2 defect 10: risk.json is per database, so a second DB in the same directory does
// not overwrite the first one's ranking.
func TestRiskJSONIsPerDatabase(t *testing.T) {
	dir := ingestTestdata(t) // p.db
	first, err := os.ReadFile(filepath.Join(dir, "p.db.risk.json"))
	if err != nil || len(first) < 10 {
		t.Fatalf("p.db.risk.json: %v", err)
	}
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte(`[{"source":"native","check_id":"c","canonical_id":"X","title":"t","severity":"LOW","status":"PASS","provider":"aws","resource":{"id":"r"}}]`), 0o644)
	flagDB = filepath.Join(dir, "q.db")
	runErr(t, "ingest", empty, "--source", "native", "-o", "summary")
	if _, err := os.Stat(filepath.Join(dir, "q.db.risk.json")); err != nil {
		t.Fatalf("second DB must get its own risk file: %v", err)
	}
	again, _ := os.ReadFile(filepath.Join(dir, "p.db.risk.json"))
	if string(again) != string(first) {
		t.Fatalf("ingesting into q.db changed p.db's ranking")
	}
	if _, err := os.Stat(filepath.Join(dir, "risk.json")); err == nil {
		t.Errorf("a shared per-directory risk.json must no longer be written")
	}
}

func TestPrioritizeExplainAndBanner(t *testing.T) {
	ingestTestdata(t)
	out := run(t, "prioritize", "--top", "2")
	if !strings.Contains(out, "Medium ≥5") || strings.Contains(out, "≥4") {
		t.Errorf("banner must use the documented bands (docs/scoring.md):\n%s", out)
	}
	out = run(t, "prioritize", "--top", "1", "--explain")
	for _, want := range []string{"factor", "base", "exposure", "identity", "data_sensitivity", "criticality", "exploitability", "attack_path", "compensating_controls", "×"} {
		if !strings.Contains(out, want) {
			t.Errorf("--explain table missing %q:\n%s", want, out)
		}
	}
}

// The Python score merge (int(p)/10) is gone: whatever a Python layer prints, the ranking is Go's.
func TestPrioritizeBestIgnoresPythonScores(t *testing.T) {
	dir := ingestTestdata(t)
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fs, _ := st.Findings(store.Filter{})
	g, _ := loadGraph(st)
	want := risk.PrioritizeWith(fs, g, nil, risk.Options{Intel: intel.Snapshot()})
	var fake []map[string]any
	for _, r := range want {
		fake = append(fake, map[string]any{"finding_id": r.Finding.ID, "risk_score": 13, "reasons": []string{"python says so"}})
	}
	payload, _ := json.Marshal(fake)
	py := filepath.Join(dir, "fakepy")
	os.WriteFile(filepath.Join(dir, "payload.json"), payload, 0o644)
	os.WriteFile(py, []byte("#!/bin/sh\ncat "+filepath.Join(dir, "payload.json")+"\n"), 0o755)
	t.Setenv("CLOUD_POSTURE_PYTHON", py)
	got := prioritizeBest(context.Background(), nil, st, fs, g, nil, 0)
	if len(got) == 0 || len(got) != len(want) {
		t.Fatalf("ranking has %d rows, Go ranking %d", len(got), len(want))
	}
	// Compare against the Go ranking itself, not a sentinel value: a Go score may
	// legitimately equal the fake Python 13/10 (integration pass 3 housekeeping).
	for i, r := range got {
		if strings.Contains(strings.Join(r.Reasons, ";"), "python says so") {
			t.Fatalf("Python reasons were merged into the Go ranking: %v", r.Reasons)
		}
		if r.Finding.ID != want[i].Finding.ID || r.Score != want[i].Score || r.Band != want[i].Band {
			t.Fatalf("row %d = %s %.2f %s, Go ranking %s %.2f %s", i, r.Finding.ID, r.Score, r.Band, want[i].Finding.ID, want[i].Score, want[i].Band)
		}
		if r.ScoreVersion != risk.ScoreVersion {
			t.Fatalf("score_version %q", r.ScoreVersion)
		}
	}
}

// countingFeed is a TLS server that counts every inbound connection and every request (a
// keep-alive client can reuse a connection, so connections alone would miss requests).
func countingFeed(t *testing.T) (*httptest.Server, *int64) {
	var n int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		http.Error(w, "no", 500)
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&n, 1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestNoNetworkMakesZeroOutboundConnections(t *testing.T) {
	srv, hits := countingFeed(t)
	cache := t.TempDir()
	old := intelHook
	t.Cleanup(func() { intelHook = old; resetIntel() })
	intelHook = func(o *intel.Options) {
		o.KEVURL, o.EPSSURL, o.CacheDir = srv.URL+"/kev.json", srv.URL+"/epss.csv.gz", cache
		o.Client = srv.Client()
	}
	ingestTestdata(t) // TestMain sets CLOUD_POSTURE_NO_NETWORK=1 for the whole package

	// Control: with the network allowed, prioritize does contact the feed URL.
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "")
	resetIntel()
	run(t, "prioritize", "--json", "--top", "1")
	if atomic.LoadInt64(hits) == 0 {
		t.Fatal("control failed: the enricher never contacted the test feed, so the assertion below would prove nothing")
	}

	// --no-network flag.
	atomic.StoreInt64(hits, 0)
	resetIntel()
	out := run(t, "prioritize", "--json", "--top", "1", "--no-network")
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("--no-network made %d outbound connection(s)", n)
	}
	if !strings.Contains(out, risk.ScoreVersion) {
		t.Errorf("--no-network must still score (embedded snapshot):\n%s", out)
	}
	// CLOUD_POSTURE_NO_NETWORK=1.
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "1")
	resetIntel()
	run(t, "ingest", testdataDir(t), "-o", "summary")
	run(t, "prioritize", "--json", "--top", "1")
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("CLOUD_POSTURE_NO_NETWORK=1 made %d outbound connection(s)", n)
	}
	if root.PersistentFlags().Lookup("no-network") == nil {
		t.Error("--no-network must be a global flag")
	}
}

// ---------------------------------------------------------------- item 3: verifier items

func TestScanIDsUniqueWithinOneSecond(t *testing.T) {
	frozen := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	oldNow := scanClock
	t.Cleanup(func() { scanClock = oldNow })
	scanClock = func() time.Time { return frozen }
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := newScanID()
		if seen[id] {
			t.Fatalf("duplicate scan id %s after %d ids in the same second", id, i)
		}
		seen[id] = true
		if !strings.HasPrefix(id, "20261009T120000") {
			t.Fatalf("scan id %q must start with its UTC timestamp (sortable)", id)
		}
	}

	// Two stored scans in the same second: distinct rows, and the clean scan's gate sees only itself.
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	mk := func(scan string, sev model.Severity, status model.Status) model.Finding {
		f := model.Finding{Source: "native", CheckID: "c", CanonicalID: "X_C", Title: "c", Severity: sev, Status: status, Provider: "aws", Account: "1",
			Resource: model.Resource{ID: "r", Type: "aws_s3_bucket", Name: "r"}, ScanID: scan}
		f.Finalize(frozen)
		return f
	}
	id1, id2 := newScanID(), newScanID()
	if _, err := finishScan(context.Background(), nil, []model.Finding{mk(id1, model.Critical, model.Fail)}, graph.New(), nil, model.ScanSummary{ScanID: id1, StartedAt: frozen}, false); err != nil {
		t.Fatal(err)
	}
	res, err := finishScan(context.Background(), nil, []model.Finding{mk(id2, model.Critical, model.Pass)}, graph.New(), nil, model.ScanSummary{ScanID: id2, StartedAt: frozen}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := gateCount(res.Findings, "LOW"); n != 0 {
		t.Errorf("--fail-on LOW on the clean scan counts %d finding(s) of the earlier same-second scan", n)
	}
	st, _ := store.Open(flagDB)
	defer st.Close()
	var rows int
	st.DB().QueryRow("SELECT count(*) FROM scans").Scan(&rows)
	if rows != 2 {
		t.Errorf("scans table has %d row(s), want 2 (same-second scans overwrote each other)", rows)
	}
}

// End to end in child processes: a failing scan then a clean scan, back to back.
func TestFailOnScopeAcrossBackToBackScans(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfgPath, []byte("{}\n"), 0o644)
	bad := filepath.Join(dir, "bad.json")
	clean := filepath.Join(dir, "clean.json")
	os.WriteFile(bad, []byte(`[{"source":"native","check_id":"c1","canonical_id":"X_ONE","title":"one","severity":"CRITICAL","status":"FAIL","provider":"aws","account":"1","resource":{"id":"r1","type":"aws_s3_bucket","name":"r1"}}]`), 0o644)
	os.WriteFile(clean, []byte(`[{"source":"native","check_id":"c1","canonical_id":"X_ONE","title":"one","severity":"CRITICAL","status":"PASS","provider":"aws","account":"1","resource":{"id":"r1","type":"aws_s3_bucket","name":"r1"}}]`), 0o644)
	env := []string{"CLOUD_POSTURE_NO_NETWORK=1", "CLOUD_POSTURE_PYTHON=/nonexistent/python"}
	db := filepath.Join(dir, "p.db")
	out, code := runSelfExit(t, dir, env, "scan", "--config", cfgPath, "--db", db, "-q", "--from-dir", bad, "-o", "summary", "--fail-on", "LOW")
	if code != 2 {
		t.Fatalf("bad scan exit %d, want 2:\n%s", code, out)
	}
	out, code = runSelfExit(t, dir, env, "scan", "--config", cfgPath, "--db", db, "-q", "--from-dir", clean, "-o", "summary", "--fail-on", "LOW")
	if code != 0 {
		t.Fatalf("clean scan exit %d, want 0:\n%s", code, out)
	}
	st, _ := store.Open(db)
	defer st.Close()
	var rows int
	st.DB().QueryRow("SELECT count(DISTINCT id) FROM scans").Scan(&rows)
	if rows != 2 {
		t.Errorf("want 2 distinct scan rows, got %d", rows)
	}
}

func TestServeRejectsWhitespaceToken(t *testing.T) {
	flagQuiet = true
	flagDB = filepath.Join(t.TempDir(), "p.db")
	for _, args := range [][]string{
		{"serve", "--addr", "127.0.0.1:0", "--token", "   "},
		{"serve", "--addr", "0.0.0.0:0", "--token", " \t "},
	} {
		out, err := runErr(t, args...)
		if err == nil || !strings.Contains(err.Error(), "whitespace") {
			t.Errorf("%v: want a clear whitespace-token error, got %v\n%s", args, err, out)
		}
	}
	t.Setenv("CLOUD_POSTURE_TOKEN", "   ")
	if _, err := runErr(t, "serve", "--addr", "0.0.0.0:0"); err == nil || !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("whitespace CLOUD_POSTURE_TOKEN accepted: %v", err)
	}
}

func TestAlertFailsWhenEveryDeliveryFails(t *testing.T) {
	dir := ingestTestdata(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now: every delivery fails
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte("integrations:\n  webhook:\n    url: http://"+addr+"/hook\n"), 0o644)
	out, err := runErr(t, "alert", "--config", cfg, "--min-severity", "CRITICAL")
	flagConfig = ""
	if err == nil {
		t.Fatalf("alert exited 0 although every delivery failed:\n%s", out)
	}
	if !regexp.MustCompile(`(?m)^\s*(siem|webhook): sent 0 · skipped \d+ · failed [1-9]\d*`).MatchString(out) {
		t.Errorf("alert must print a per-sink summary:\n%s", out)
	}
}

func TestScanDiffJSON(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	before := writeProwler(t, dir, "before.ocsf.json", false)
	after := writeProwler(t, dir, "after.ocsf.json", true)
	run(t, "ingest", before, "--source", "prowler", "-o", "summary")
	dj := filepath.Join(dir, "diff.json")
	run(t, "ingest", after, "--source", "prowler", "-o", "summary", "--diff-json", dj)
	var d struct {
		ScanID   string `json:"scan_id"`
		Counts   map[string]int
		Resolved []struct {
			ID          string `json:"id"`
			CanonicalID string `json:"canonical_id"`
			Severity    string `json:"severity"`
		} `json:"resolved"`
	}
	b, err := os.ReadFile(dj)
	if err != nil || json.Unmarshal(b, &d) != nil {
		t.Fatalf("--diff-json not written: %v\n%s", err, b)
	}
	if d.ScanID == "" || d.Counts["resolved"] != 1 || len(d.Resolved) != 1 || d.Resolved[0].CanonicalID != "S3_PUBLIC_BUCKET" {
		t.Errorf("diff json: %s", b)
	}
	if scanCmd.Flags().Lookup("diff-json") == nil {
		t.Error("scan is missing --diff-json")
	}
}

// ---------------------------------------------------------------- item 4: CLI UX

func TestVersionPrintsBuildMetadata(t *testing.T) {
	ov, oc, od := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = ov, oc, od })
	SetVersion("1.2.3", "abc1234", "2026-10-09T00:00:00Z")
	out := run(t, "version")
	for _, want := range []string{"1.2.3", "abc1234", "2026-10-09T00:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q:\n%s", want, out)
		}
	}
}

func TestPathsDeadEndsChokeExplain(t *testing.T) {
	ingestTestdata(t)
	out := run(t, "paths", "--explain", "--limit", "1")
	if !strings.Contains(out, "because:") {
		t.Errorf("paths --explain must print per-hop because:\n%s", out)
	}
	out = run(t, "paths", "--limit", "1")
	if !strings.Contains(out, "Dead ends:") {
		t.Errorf("paths should summarise dead ends by default:\n%s", out)
	}
	out = run(t, "paths", "--limit", "1", "--no-dead-ends")
	if strings.Contains(out, "Dead ends") {
		t.Errorf("--no-dead-ends must hide the dead-end summary:\n%s", out)
	}
	out = run(t, "paths", "--format", "json", "--dead-ends")
	var de struct {
		DeadEnds struct {
			Count int      `json:"count"`
			IDs   []string `json:"ids"`
		} `json:"dead_ends"`
	}
	if err := json.Unmarshal([]byte(out), &de); err != nil || de.DeadEnds.Count != len(de.DeadEnds.IDs) {
		t.Errorf("paths --dead-ends --format json: %v\n%s", err, out)
	}
	out = run(t, "paths", "--format", "json", "--fixes")
	var an attackpath.Analysis
	if err := json.Unmarshal([]byte(out), &an); err != nil || len(an.ChokePoints) == 0 {
		t.Fatalf("no choke points in testdata analysis: %v", err)
	}
	cp := an.ChokePoints[0]
	out = run(t, "paths", "--choke", cp.NodeID)
	// --choke adds rule-chain paths through the node to the traversal count (V2 integration a),
	// so it closes at least what --fixes reports.
	m := regexp.MustCompile(`closes (\d+)`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, cp.PathIDs[0]) {
		t.Errorf("paths --choke must show closes N and the path ids:\n%s", out)
	} else if n, _ := strconv.Atoi(m[1]); n < cp.ClosesN {
		t.Errorf("paths --choke closes %d < traversal closes %d:\n%s", n, cp.ClosesN, out)
	}
	if _, err := runErr(t, "paths", "--choke", "no-such-node"); err == nil {
		t.Error("paths --choke with an unknown node must fail")
	}
}

func TestPlanShowsMinFixSetAndSimulation(t *testing.T) {
	ingestTestdata(t)
	out := run(t, "plan")
	for _, want := range []string{"min_fix_exact", "min_fix_verified", "resolves", "remaining score"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q:\n%s", want, out)
		}
	}
	out = run(t, "plan", "--json")
	var p struct {
		MinFixExact    bool `json:"min_fix_exact"`
		MinFixVerified bool `json:"min_fix_verified"`
		Steps          []struct {
			Fix            attackpath.Fix `json:"fix"`
			Resolves       int            `json:"resolves"`
			RemainingScore float64        `json:"remaining_score"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil || len(p.Steps) == 0 {
		t.Fatalf("plan --json: %v\n%s", err, out)
	}
	if len(p.Steps) > 5 {
		t.Errorf("plan shows %d steps, want at most 5", len(p.Steps))
	}
	st, _ := store.Open(flagDB)
	g, _ := loadGraph(st)
	st.Close()
	n, rem := attackpath.SimulateWith(g, traversalOptions(nil, g), []attackpath.Fix{p.Steps[0].Fix})
	if n != p.Steps[0].Resolves || fmt.Sprintf("%.2f", rem) != fmt.Sprintf("%.2f", p.Steps[0].RemainingScore) {
		t.Errorf("plan step 1 says resolves %d / remaining %.2f; re-traversal says %d / %.2f", p.Steps[0].Resolves, p.Steps[0].RemainingScore, n, rem)
	}
}

// ---------------------------------------------------------------- item 5: dashboard payload

func TestDashboardPayloadIncludesIssuesCoverageScans(t *testing.T) {
	ingestTestdata(t)
	res, st, err := loadResult(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	html, err := renderDashboard(res, "static", "")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`).FindSubmatch(html)
	if m == nil {
		t.Fatal("no data blob")
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(m[1], &d); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"issues", "coverage", "scans"} {
		if len(d[k]) == 0 || string(d[k]) == "null" {
			t.Errorf("dashboard data missing %q", k)
		}
	}
	var issues []model.Issue
	json.Unmarshal(d["issues"], &issues)
	if len(issues) == 0 {
		t.Error("dashboard issues empty after ingest")
	}
	var rk []risk.Ranked
	json.Unmarshal(d["risk"], &rk)
	if len(rk) == 0 || rk[0].Explanation == nil || len(rk[0].Explanation.Factors) == 0 {
		t.Error("dashboard risk entries must carry the explanation")
	}
}

// ---------------------------------------------------------------- items 6–8: Track C wiring

type fakeCollector struct {
	seen     *[]string
	deadline *time.Duration
}

func (f fakeCollector) Name() string     { return "fake-aws" }
func (f fakeCollector) Provider() string { return "aws" }
func (f fakeCollector) Collect(ctx context.Context, spec collector.AccountSpec, g *graph.Graph) (collector.Result, error) {
	*f.seen = spec.TrustedCIDRs
	if dl, ok := ctx.Deadline(); ok {
		*f.deadline = time.Until(dl)
	}
	return collector.Result{}, nil
}

func TestScanPassesAccountTimeoutAndTrustedCIDRs(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte("accounts:\n  prod:\n    provider: aws\nscan:\n  account_timeout: 7s\ntrusted_cidrs:\n  - 203.0.113.0/24\n"), 0o644)
	var seen []string
	var left time.Duration
	old := collectorHook
	t.Cleanup(func() { collectorHook = old; flagConfig = "" })
	collectorHook = func(o *collector.Options) {
		o.Collectors = map[string]collector.Collector{"aws": fakeCollector{&seen, &left}}
	}
	run(t, "scan", "--config", cfg, "--accounts", "prod", "--tools", "native", "-o", "summary")
	if len(seen) != 1 || seen[0] != "203.0.113.0/24" {
		t.Errorf("trusted_cidrs not passed to the collectors: %v", seen)
	}
	if left <= 0 || left > 7*time.Second {
		t.Errorf("scan.account_timeout 7s not applied: deadline in %v", left)
	}
}

func TestTypedCrownJewelsReplaceRawParse(t *testing.T) {
	dir := ingestTestdata(t)
	cfg := filepath.Join(dir, "cfg.yaml")
	// The legacy raw scan.crown_jewels block is no longer read; the typed top-level block is.
	os.WriteFile(cfg, []byte("crown_jewels:\n  - name: pii-exports\n    level: very_high\n    name_regex: customer-pii-exports\n"), 0o644)
	t.Cleanup(func() { flagConfig = "" })
	out := run(t, "prioritize", "--json", "--top", "0", "--config", cfg)
	var ranked []risk.Ranked
	if err := json.Unmarshal([]byte(out), &ranked); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range ranked {
		if r.Finding.Resource.Name != "customer-pii-exports" || r.Explanation == nil {
			continue
		}
		for _, f := range r.Explanation.Factors {
			if f.Name == "criticality" && strings.Contains(strings.Join(f.Evidence, " "), "crown_jewels rule pii-exports") {
				found = true
			}
		}
	}
	if !found {
		t.Error("typed crown_jewels rule did not reach the risk explanation")
	}
	// The traversal targets come from the same typed rules. Names avoid the built-in catalog
	// (*pii*, *prod*, …) so only the config rule can make the node a target.
	cfg2 := filepath.Join(dir, "cfg2.yaml")
	os.WriteFile(cfg2, []byte("crown_jewels:\n  - name: ledger\n    level: very_high\n    name_regex: ^ledger-store$\n"), 0o644)
	c, _ := loadConfigFile(t, cfg2)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::ledger-store", Name: "ledger-store", Type: "aws_s3_bucket"})
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::ledger-store-2", Name: "ledger-store-2", Type: "aws_s3_bucket"})
	opts := traversalOptions(c, g)
	pii, _ := g.Node("arn:aws:s3:::ledger-store")
	other, _ := g.Node("arn:aws:s3:::ledger-store-2") // its ID contains the jewel's ID: must not match
	if attackpath.Criticality(pii, opts.CrownJewels) != 4 {
		t.Error("very_high crown jewel must be a tier-0 traversal target")
	}
	if attackpath.Criticality(other, opts.CrownJewels) == 4 {
		t.Error("a node no rule matches must not become a tier-0 target")
	}
}

func TestConfigValidationErrorsSurface(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.yaml")
	const secret = "xoxb-literal-should-never-print"
	os.WriteFile(cfg, []byte("integrations:\n  slack:\n    token: "+secret+"\n"), 0o644)
	env := []string{"CLOUD_POSTURE_NO_NETWORK=1", "CLOUD_POSTURE_PYTHON=/nonexistent/python"}
	for _, args := range [][]string{
		{"scan", "--from-dir", dir},
		{"serve", "--addr", "127.0.0.1:0"},
		{"doctor"},
	} {
		full := append([]string{"--config", cfg, "--db", filepath.Join(dir, "p.db")}, args...)
		out, code := runSelfExit(t, dir, env, full...)
		if code == 0 {
			t.Errorf("%v exited 0 with an invalid config:\n%s", args, out)
		}
		if !strings.Contains(out, "integrations.slack.token") || !strings.Contains(out, "literal secret") {
			t.Errorf("%v: want the typed validation message:\n%s", args, out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("%v printed the secret value:\n%s", args, out)
		}
	}
}
