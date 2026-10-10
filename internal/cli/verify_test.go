package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// RM4 / IW2 acceptance: `cloud-posture verify <issue>` (Orca rescan-on-close, Prowler partial
// scans, XM Cyber remediation confirmation).

const (
	labPII     = "arn:aws:s3:::nimbus-lab-customer-pii"
	labWebRole = "arn:aws:iam::111111111111:role/nimbus-lab-web-instance-role"
)

// p01Issue / p02Issue are the lab path Issues' stored ids: keyed per database (store/idkey.go,
// MCP-1), so they are read through the test database's key.
func p01Issue(t *testing.T) string { return keyedPathIssue(t, labPII) }
func p02Issue(t *testing.T) string { return keyedPathIssue(t, labWebRole) }

func keyedPathIssue(t *testing.T, anchor string) string {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	return st.KeyID(model.PathIssueID(model.IssuePath, model.PathEntryInternet, anchor, model.PathRuleTraversal))
}

func labConfig(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "lab", "local", "cloud-posture.lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// writeConfig writes the lab config plus extra YAML into dir.
func writeConfig(t *testing.T, dir, extra string) string {
	t.Helper()
	data, err := os.ReadFile(labConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, append(data, []byte("\n"+extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func labCopy(t *testing.T) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(labFile(t, "estate.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fs []map[string]any
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatal(err)
	}
	return fs
}

func labFinding(fs []map[string]any, id string) map[string]any {
	for _, f := range fs {
		if f["id"] == id {
			return f
		}
	}
	return nil
}

func writeFindings(t *testing.T, dir, name string, fs []map[string]any) string {
	t.Helper()
	data, _ := json.Marshal(fs)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// setSGIngress replaces the lab web security group's (W02) ingress rules.
func setSGIngress(fs []map[string]any, cidr22, cidr3389 string) {
	attrs := labFinding(fs, "lab-W02")["resource"].(map[string]any)["attributes"].(map[string]any)
	attrs["ingress"] = []any{
		map[string]any{"cidr": cidr22, "from_port": 22, "to_port": 22, "protocol": "tcp"},
		map[string]any{"cidr": cidr3389, "from_port": 3389, "to_port": 3389, "protocol": "tcp"},
	}
}

type verifyHooks struct {
	mu     sync.Mutex
	sleeps []time.Duration
	exit   int // -1: verifyExit not called
}

// withVerifyHooks replaces the clock, sleep and exit of `verify`: sleeps advance the clock
// instantly, and the exit code is recorded instead of ending the test binary.
func withVerifyHooks(t *testing.T) *verifyHooks {
	t.Helper()
	h := &verifyHooks{exit: -1}
	// Real time plus the slept durations: monotonic with the scans the test runs, and sleeps
	// cost nothing.
	var offset time.Duration
	oldNow, oldSleep, oldExit := verifyNow, verifySleep, verifyExit
	verifyNow = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return time.Now().Add(offset) }
	verifySleep = func(_ context.Context, d time.Duration) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.sleeps = append(h.sleeps, d)
		offset += d
		return nil
	}
	verifyExit = func(code int) { h.mu.Lock(); h.exit = code; h.mu.Unlock() }
	t.Cleanup(func() { verifyNow, verifySleep, verifyExit = oldNow, oldSleep, oldExit })
	return h
}

func (h *verifyHooks) reset() { h.mu.Lock(); h.sleeps, h.exit = nil, -1; h.mu.Unlock() }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func issueByID(t *testing.T, id string) model.Issue {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	is, err := st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range is {
		if i.ID == id {
			return i
		}
	}
	t.Fatalf("Issue %s not stored", id)
	return model.Issue{}
}

func singleIssue(t *testing.T, canonical, resource string) model.Issue {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	is, _ := st.Issues(store.IssueFilter{Kind: model.IssueSingle})
	for _, i := range is {
		if i.CanonicalID == canonical && i.ResourceID == resource {
			return i
		}
	}
	t.Fatalf("no single Issue %s on %s", canonical, resource)
	return model.Issue{}
}

// issueRows is every Issue's (state, score, verified_at, ticket_state) except skip.
func issueRows(t *testing.T, skip ...string) map[string]string {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	is, _ := st.Issues(store.IssueFilter{})
	out := map[string]string{}
	for _, i := range is {
		if contains(skip, i.ID) {
			continue
		}
		out[i.ID] = fmt.Sprintf("%s|%.2f|%v|%s|%s", i.State, i.Score, i.VerifiedAt, i.TicketState, i.LastSeen)
	}
	return out
}

func ingestLab(t *testing.T, cfg string, file string) {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "-c", cfg, "ingest", file, "-o", "summary")
}

// Lab: the customer-pii bucket is made private (W01 → PASS). Its finding Issue is
// verified-fixed; the P01 path Issue is NOT, because the same internet → customer-pii Issue
// survives through the public export Lambda (W12) at 7.0 — verify names that hop. Making the
// Lambda URL private too (W12 → PASS) closes the path, and only then is P01 verified-fixed.
func TestVerifyLabPublicBucketFix(t *testing.T) {
	h := withVerifyHooks(t)
	cfg := labConfig(t)
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	if is := issueByID(t, p01Issue(t)); is.Score != 10 || !model.IsActive(is.State) {
		t.Fatalf("P01 path Issue before the fix: %.1f %s", is.Score, is.State)
	}
	dir := t.TempDir()
	fs := labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	bucketFixed := writeFindings(t, dir, "bucket-fixed.json", fs)

	before := issueRows(t, p01Issue(t))
	out := run(t, "-c", cfg, "verify", p01Issue(t), "--from-file", bucketFixed, "--attempts", "1")
	if h.exit != 2 || !strings.Contains(out, "still open") || !strings.Contains(out, "nimbus-lab-export") || !strings.Contains(out, "10.0 CRITICAL → 7.0 HIGH") {
		t.Fatalf("P01 with only the bucket fixed must stay open naming the Lambda hop and the score drop (exit %d):\n%s", h.exit, out)
	}
	if is := issueByID(t, p01Issue(t)); !model.IsActive(is.State) || is.VerifiedAt != nil {
		t.Fatalf("a failed verification changed P01: %s %v", is.State, is.VerifiedAt)
	}

	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	h.reset()
	out = run(t, "-c", cfg, "verify", w01.ID, "--from-file", bucketFixed, "--attempts", "1")
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("W01 finding Issue not verified (exit %d):\n%s", h.exit, out)
	}
	got := issueByID(t, w01.ID)
	if got.State != store.StateVerifiedFixed || got.VerifiedAt == nil || !strings.HasPrefix(got.VerifiedBy, "file:") {
		t.Fatalf("W01 Issue after verify: state %s verified_at %v by %q", got.State, got.VerifiedAt, got.VerifiedBy)
	}

	fs = labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	labFinding(fs, "lab-W12")["status"] = "PASS"
	bothFixed := writeFindings(t, dir, "bucket-and-lambda-fixed.json", fs)
	h.reset()
	out = run(t, "-c", cfg, "verify", p01Issue(t)[:12], "--from-file", bothFixed, "--attempts", "1")
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("P01 with bucket and Lambda fixed not verified (exit %d):\n%s", h.exit, out)
	}
	if is := issueByID(t, p01Issue(t)); is.State != store.StateVerifiedFixed || is.VerifiedAt == nil {
		t.Fatalf("P01 state %s", is.State)
	}
	after := issueRows(t, p01Issue(t), w01.ID)
	delete(before, w01.ID)
	for id, row := range before {
		if after[id] != row {
			t.Errorf("verify touched another Issue %s: %s → %s", id, row, after[id])
		}
	}
	st := openTestStore(t)
	h1, _ := st.PathIssueHistory(p01Issue(t))
	if len(h1) == 0 || h1[len(h1)-1].State != store.StateVerifiedFixed {
		t.Errorf("P01 history lacks verified_fixed: %+v", h1)
	}
	vs, _ := st.Verifications(p01Issue(t))
	if len(vs) != 2 || vs[0].Result != store.VerifyOpen || vs[1].Result != store.VerifyFixed {
		t.Errorf("P01 verification history = %+v", vs)
	}
}

// Lab partial fix: the web SG opens 22 and 3389 to the internet; 22 is narrowed to 10/8 but
// 3389 is left open. The P02 path Issue stays open and the reason names 3389 (not 22); the
// process exits 2. Closing 3389 too verifies it.
func TestVerifyLabPartialSGFixNames3389(t *testing.T) {
	h := withVerifyHooks(t)
	cfg := labConfig(t)
	dir := t.TempDir()
	fs := labCopy(t)
	setSGIngress(fs, "0.0.0.0/0", "0.0.0.0/0")
	base := writeFindings(t, dir, "base.json", fs)
	ingestLab(t, cfg, base)
	if is := issueByID(t, p02Issue(t)); !model.IsActive(is.State) {
		t.Fatalf("P02 not open after ingest: %s", is.State)
	}

	fs = labCopy(t)
	setSGIngress(fs, "10.0.0.0/8", "0.0.0.0/0")
	labFinding(fs, "lab-W03")["status"] = "PASS" // SSH no longer exposed on the instance
	partial := writeFindings(t, dir, "partial.json", fs)
	out := run(t, "-c", cfg, "verify", p02Issue(t), "--from-file", partial, "--attempts", "1", "--wait", "0")
	if h.exit != 2 || !strings.Contains(out, "port 3389 still open from 0.0.0.0/0") {
		t.Fatalf("partial fix: want open with 3389 named (exit %d):\n%s", h.exit, out)
	}
	if strings.Contains(out, "port 22 still open") {
		t.Errorf("the narrowed port 22 is reported as still open:\n%s", out)
	}
	// The real exit code, in a child process.
	childOut, code := runSelfExit(t, dir, nil, "-q", "--db", flagDB, "-c", cfg, "verify", p02Issue(t), "--from-file", partial, "--attempts", "1", "--wait", "0")
	if code != 2 {
		t.Errorf("still-open verify exit code = %d, want 2\n%s", code, childOut)
	}

	fs = labCopy(t)
	setSGIngress(fs, "10.0.0.0/8", "10.0.0.0/8")
	labFinding(fs, "lab-W02")["status"] = "PASS"
	labFinding(fs, "lab-W03")["status"] = "PASS"
	full := writeFindings(t, dir, "full.json", fs)
	h.reset()
	out = run(t, "-c", cfg, "verify", p02Issue(t), "--from-file", full, "--attempts", "1", "--json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &doc); err != nil || doc["result"] != store.VerifyFixed || h.exit != -1 {
		t.Fatalf("full SG fix --json: %v (exit %d)\n%s", err, h.exit, out)
	}
}

// seqTargeted is an eventually consistent fake: read i returns seq[i] ("old" = the stored,
// still-public state; "fixed"; "err" = a partial error), repeating the last entry.
type seqTargeted struct {
	mu    sync.Mutex
	seq   []string
	reads int
	old   model.Finding
	ids   [][]string
}

func (s *seqTargeted) Target(_ context.Context, spec core.AccountSpec, ids []string) (*core.TargetResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.seq[len(s.seq)-1]
	if s.reads < len(s.seq) {
		st = s.seq[s.reads]
	}
	s.reads++
	s.ids = append(s.ids, ids)
	r := &core.TargetResult{Observed: ids}
	f := s.old
	switch st {
	case "old":
		r.Findings = []model.Finding{f}
	case "fixed":
		f.Status = model.Pass
		r.Findings = []model.Finding{f}
	case "err":
		r.Errors = []error{core.NewCollectError("s3", errors.New("AccessDenied: GetPublicAccessBlock"))}
	}
	return r, nil
}

// withFakeTargeted ingests the lab, configures one AWS account and returns a fake whose reads
// follow seq, plus the W01 finding Issue it re-reads.
func withFakeTargeted(t *testing.T, seq ...string) (*seqTargeted, model.Issue, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "accounts:\n  lab:\n    provider: aws\n    regions: [us-east-1]\n")
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	old, err := st.Finding("lab-W01")
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	fake := &seqTargeted{seq: seq, old: *old}
	prev := verifyTargeted
	verifyTargeted = func(provider string) (core.Targeted, bool) { return fake, provider == model.ProviderAWS }
	t.Cleanup(func() { verifyTargeted = prev })
	return fake, singleIssue(t, "S3_PUBLIC_BUCKET", labPII), cfg
}

// Eventual consistency: the first two reads still return the public bucket. verify keeps
// reading with backoff and needs 3 consecutive confirmations; it neither verifies early nor
// reopens, and records one verification with 5 reads.
func TestVerifyEventualConsistencyNeedsConsecutiveConfirmations(t *testing.T) {
	h := withVerifyHooks(t)
	fake, is, cfg := withFakeTargeted(t, "old", "old", "fixed")
	out := run(t, "-c", cfg, "verify", is.ID, "--attempts", "3", "--interval", "10ms", "--wait", "1h")
	if h.exit != -1 || !strings.Contains(out, "verified-fixed") {
		t.Fatalf("not verified (exit %d):\n%s", h.exit, out)
	}
	if fake.reads != 5 {
		t.Errorf("reads = %d, want 5 (2 stale + 3 confirmations)", fake.reads)
	}
	want := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}
	if fmt.Sprint(h.sleeps) != fmt.Sprint(want) {
		t.Errorf("backoff sleeps = %v, want %v", h.sleeps, want)
	}
	if len(fake.ids) == 0 || len(fake.ids[0]) != 1 || fake.ids[0][0] != labPII {
		t.Errorf("targeted ids = %v, want only the bucket", fake.ids)
	}
	st := openTestStore(t)
	vs, _ := st.Verifications(is.ID)
	if len(vs) != 1 || vs[0].Result != store.VerifyFixed || vs[0].Reads != 5 || vs[0].Confirmations != 3 || vs[0].VerifiedBy != "rescan" {
		t.Fatalf("verification history = %+v", vs)
	}
	if got := issueByID(t, is.ID); got.State != store.StateVerifiedFixed {
		t.Errorf("state %s", got.State)
	}
}

// Stale reads only, inside a window that closes: the Issue stays open (not verified, not
// reopened), the reason names the still-failing finding, exit 2.
func TestVerifyStaleReadsInsideWindowStayOpen(t *testing.T) {
	h := withVerifyHooks(t)
	fake, is, cfg := withFakeTargeted(t, "old")
	// W7-POLISH flake hunt (verification 7: 1 read instead of 2 under -race, 10/10): the hook
	// clock is real time + slept durations, so a read slower than 15 ms pushed the second read
	// past the 25 ms window. Here the clock moves only by the slept durations, so the window
	// arithmetic is exact however slow a read is.
	base := time.Now()
	var clk sync.Mutex
	var off time.Duration
	verifyNow = func() time.Time { clk.Lock(); defer clk.Unlock(); return base.Add(off) }
	verifySleep = func(_ context.Context, d time.Duration) error { clk.Lock(); off += d; clk.Unlock(); return nil }
	out := run(t, "-c", cfg, "verify", is.ID, "--attempts", "3", "--interval", "10ms", "--wait", "25ms")
	if h.exit != 2 || !strings.Contains(out, "S3_PUBLIC_BUCKET") || !strings.Contains(out, "still FAIL") {
		t.Fatalf("want still open naming the finding (exit %d):\n%s", h.exit, out)
	}
	if fake.reads != 2 {
		t.Errorf("reads = %d, want 2 (t=0, t=10ms; the next would start after the 25ms window)", fake.reads)
	}
	if got := issueByID(t, is.ID); got.State != model.StateOpen || got.VerifiedAt != nil {
		t.Errorf("stale reads changed the Issue: %s", got.State)
	}
}

// Flapping and inconclusive reads reset the streak: fixed, old, fixed, err, fixed, fixed,
// fixed → verified only after the last three.
func TestVerifyFlappingAndInconclusiveResetStreak(t *testing.T) {
	h := withVerifyHooks(t)
	fake, is, cfg := withFakeTargeted(t, "fixed", "old", "fixed", "err", "fixed", "fixed", "fixed")
	out := run(t, "-c", cfg, "verify", is.ID, "--attempts", "3", "--interval", "1ms", "--wait", "1h")
	if h.exit != -1 || fake.reads != 7 || !strings.Contains(out, "inconclusive") {
		t.Fatalf("reads %d exit %d:\n%s", fake.reads, h.exit, out)
	}
}

// A verified Issue that is observed again for N consecutive reads is reopened with the
// evidence; a single stale read inside the window does not reopen it.
func TestVerifyReopensOnlyAfterConsecutivePresence(t *testing.T) {
	h := withVerifyHooks(t)
	fake, is, cfg := withFakeTargeted(t, "fixed")
	run(t, "-c", cfg, "verify", is.ID, "--attempts", "1")
	if got := issueByID(t, is.ID); got.State != store.StateVerifiedFixed {
		t.Fatalf("setup: %s", got.State)
	}
	fake.seq, fake.reads = []string{"old", "fixed"}, 0
	h.reset()
	run(t, "-c", cfg, "verify", is.ID, "--attempts", "2", "--interval", "1ms", "--wait", "1h")
	if got := issueByID(t, is.ID); got.State != store.StateVerifiedFixed {
		t.Fatalf("one stale read reopened a verified Issue: %s", got.State)
	}
	fake.seq, fake.reads = []string{"old"}, 0
	h.reset()
	out := run(t, "-c", cfg, "verify", is.ID, "--attempts", "2", "--interval", "1ms", "--wait", "1h")
	if got := issueByID(t, is.ID); got.State != model.StateReopened || h.exit != 2 || !strings.Contains(out, "reopened") {
		t.Fatalf("persistent presence: state %s exit %d\n%s", got.State, h.exit, out)
	}
}

// IW2: verified_fixed closes the Issue's one ticket through the configured sink (Jira mock);
// with no sink configured the ticket is left alone and the gap is printed.
func TestVerifyClosesTicketOnlyWhenVerified(t *testing.T) {
	h := withVerifyHooks(t)
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/transitions") {
			fmt.Fprint(w, `{"transitions":[{"id":"31","name":"Done","to":{"statusCategory":{"key":"done"}}},{"id":"11","name":"Reopen","to":{"statusCategory":{"key":"new"}}}]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("JIRA_EMAIL", "bot@example.com")
	t.Setenv("JIRA_API_TOKEN", "test-token")

	// No sink configured: the stale ticket stays open.
	fake, is, cfg := withFakeTargeted(t, "fixed")
	_ = fake
	st := openTestStore(t)
	if err := st.SetIssueTicket(is.ID, store.IssueTicket{Sink: "jira", Key: "SEC-7", URL: srv.URL + "/browse/SEC-7", State: "open"}); err != nil {
		t.Fatal(err)
	}
	out := run(t, "-c", cfg, "verify", is.ID, "--attempts", "1")
	if got := issueByID(t, is.ID); got.TicketState != "open" || !strings.Contains(out, "SEC-7") {
		t.Fatalf("no sink: ticket %s\n%s", got.TicketState, out)
	}

	// Jira configured: the next verification closes SEC-7 (transition to Done).
	cfgJira := writeConfig(t, t.TempDir(), "accounts:\n  lab:\n    provider: aws\n    regions: [us-east-1]\nintegrations:\n  jira:\n    url: "+srv.URL+"\n    project: SEC\n")
	h.reset()
	out = run(t, "-c", cfgJira, "verify", is.ID, "--attempts", "1")
	if got := issueByID(t, is.ID); got.TicketState != "closed" {
		t.Fatalf("ticket not closed on verified_fixed: %s\n%s", got.TicketState, out)
	}
	mu.Lock()
	joined := strings.Join(calls, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "POST /rest/api/3/issue/SEC-7/transitions") {
		t.Errorf("no Jira transition: %s", joined)
	}
}

// `ingest --diff` prints the path Issue rescore (customer-pii path 10.0 CRITICAL → 7.0 HIGH)
// and the Issues verified-fixed since the previous scan; --diff-json carries both.
func TestDiffPrintsPathRescoreAndVerifiedFixed(t *testing.T) {
	withVerifyHooks(t)
	cfg := labConfig(t)
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	dir := t.TempDir()
	fs := labCopy(t)
	labFinding(fs, "lab-W01")["status"] = "PASS"
	fixed := writeFindings(t, dir, "fixed.json", fs)
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	run(t, "-c", cfg, "verify", w01.ID, "--from-file", fixed, "--attempts", "1")

	djson := filepath.Join(dir, "diff.json")
	out := run(t, "-c", cfg, "ingest", fixed, "-o", "summary", "--diff", "--diff-json", djson)
	if !strings.Contains(out, "rescored") || !strings.Contains(out, p01Issue(t)) || !strings.Contains(out, "10.0 CRITICAL → 7.0 HIGH") {
		t.Fatalf("--diff lacks the P01 rescore:\n%s", out)
	}
	if !strings.Contains(out, "verified-fixed") || !strings.Contains(out, w01.ID) {
		t.Fatalf("--diff lacks the verified-fixed transition:\n%s", out)
	}
	data, _ := os.ReadFile(djson)
	var doc struct {
		PathIssues struct {
			Rescored []struct {
				ID       string  `json:"id"`
				OldScore float64 `json:"old_score"`
				NewScore float64 `json:"new_score"`
			} `json:"rescored"`
		} `json:"path_issues"`
		VerifiedFixed []struct {
			ID string `json:"id"`
		} `json:"verified_fixed"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PathIssues.Rescored) == 0 || doc.PathIssues.Rescored[0].OldScore != 10 || doc.PathIssues.Rescored[0].NewScore != 7 {
		t.Errorf("diff-json rescored = %+v", doc.PathIssues.Rescored)
	}
	if len(doc.VerifiedFixed) != 1 || doc.VerifiedFixed[0].ID != w01.ID {
		t.Errorf("diff-json verified_fixed = %+v", doc.VerifiedFixed)
	}
}
