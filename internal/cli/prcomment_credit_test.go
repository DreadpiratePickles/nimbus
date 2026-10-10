package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/pathdiff"
)

// Shortfall #14 (competitive delta 2026-10-09 r2): the PR comment credits fixes and offers
// one-click commits. Bars: Cortex Cloud's commit suggestion, Datadog's Terraform PR; the
// de-escalation credit is ours.

// planCommentUntrusted is planComment without the trusted range, so the fixture's SSH rule
// (203.0.113.0/24 before the revert) is a public, narrow entry: revert.plan.json then lowers the
// path 7.0 → 1.9 instead of closing it, and bad.plan.json escalates it 1.9 → 7.0.
func planCommentUntrusted(t *testing.T, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "none.db")
	t.Cleanup(func() { flagDB = "" })
	return run(t, append([]string{"pr-comment", "--live", "off"}, args...)...)
}

func catchExit(t *testing.T) *int {
	t.Helper()
	code := -1
	old := exitFn
	exitFn = func(c int) { code = c }
	t.Cleanup(func() { exitFn = old })
	return &code
}

func TestPlanCommentCreditsLoweredPaths(t *testing.T) {
	code := catchExit(t)
	out := planCommentUntrusted(t, "--plan-json", fixturePlan("revert.plan.json"), "--redact", "off", "--fail-on-opened")
	for _, want := range []string{"this PR opens 0 / escalates 0 / lowers 1 / closes 0 attack paths", "### Lowered (1)",
		"7.0 → 1.9 &#40;High → Low&#41;", "nimbus-lowers-paths: 1", "nimbus-escalates-paths: 0", "nimbus-closes-paths: 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("revert comment lacks %q:\n%s", want, out)
		}
	}
	if *code != -1 {
		t.Errorf("a lowering plan tripped --fail-on-opened (exit %d)", *code)
	}
}

func TestPlanCommentEscalationStillGates(t *testing.T) {
	code := catchExit(t)
	out := planCommentUntrusted(t, "--plan-json", fixturePlan("bad.plan.json"), "--redact", "on", "--fail-on-opened")
	for _, want := range []string{"opens 0 / escalates 1 / lowers 0 / closes 0", "nimbus-escalates-paths: 1", "nimbus-lowers-paths: 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("bad comment lacks %q:\n%s", want, out)
		}
	}
	if *code != exitOpened {
		t.Errorf("escalation: exit %d, want %d", *code, exitOpened)
	}
	*code = -1
	planCommentUntrusted(t, "--plan-json", fixturePlan("bad.plan.json"), "--fail-on-opened", "--opened-only")
	if *code != -1 {
		t.Errorf("--opened-only: escalation tripped the gate (exit %d)", *code)
	}
}

func TestPRCommentHelpDocumentsGateFlags(t *testing.T) {
	out := run(t, "pr-comment", "--help")
	for _, want := range []string{"--opened-only", "--fail-on-opened", "--iac", "suggestion"} {
		if !strings.Contains(out, want) {
			t.Errorf("pr-comment --help lacks %q", want)
		}
	}
}

// suggestionFixture copies testdata/action-fixture with the SSH source written as a literal
// 0.0.0.0/0 (a deterministic patch target). declare adds variables.tf declaring allowed_cidrs,
// so the patch is one hunk; without it the patcher must also append a variable block (two
// hunks), which stays a CLI fix hint.
func suggestionFixture(t *testing.T, declare bool) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "action-fixture")
	dir := t.TempDir()
	for _, f := range []string{"main.tf", filepath.Join("modules", "web", "main.tf")} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o755)
		os.WriteFile(filepath.Join(dir, f), []byte(strings.Replace(string(b), "[var.ssh_cidr]", `["0.0.0.0/0"]`, 1)), 0o644)
	}
	if declare {
		os.WriteFile(filepath.Join(dir, "modules", "web", "variables.tf"), []byte("variable \"allowed_cidrs\" {\n  type = list(string)\n}\n"), 0o644)
	}
	return dir
}

var suggestionBlock = regexp.MustCompile("(?s)(`{3,})suggestion\n(.*?)\n(`{3,})\n")

func TestPlanCommentSuggestsSingleHunkFix(t *testing.T) {
	iacDir := suggestionFixture(t, true)
	out := planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--redact", "on", "--iac", iacDir)
	m := suggestionBlock.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no suggestion block:\n%s", out)
	}
	if !strings.Contains(out, "modules/web/main.tf line 15") {
		t.Errorf("suggestion not anchored to modules/web/main.tf line 15:\n%s", out)
	}
	if body := m[2]; !strings.Contains(body, "cidr_blocks") || !strings.Contains(body, "var.allowed_cidrs") || strings.Contains(body, "0.0.0.0/0") || strings.Count(body, "\n") != 0 {
		t.Errorf("suggestion body %q, want the one rewritten cidr_blocks line", body)
	}
	if !strings.Contains(out, "nimbus-opens-paths: 1") {
		t.Errorf("counts changed:\n%s", out)
	}
}

// Shortfall #6 (delta r3): the most common plan-time fix (a literal 0.0.0.0/0 with no declared
// variable) patches two hunks: the rule and an appended variable block. Each hunk is its own
// suggestion, labelled "part i of 2" with a confidence label, and committing both yields a file
// that parses and no longer has the finding (bar: Checkov / Prisma one-click commit).
func TestPlanCommentSuggestsEachHunk(t *testing.T) {
	iacDir := suggestionFixture(t, false)
	out := planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--redact", "off", "--iac", iacDir)
	ms := suggestionBlock.FindAllStringSubmatch(out, -1)
	if len(ms) != 2 {
		t.Fatalf("got %d suggestion blocks, want 2 (rule + variable block):\n%s", len(ms), out)
	}
	for _, want := range []string{"modules/web/main.tf line 15", "part 1 of 2", "part 2 of 2", "confidence **medium**", "declares variable allowed&#95;cidrs", "### Suggested changes (2)"} {
		if !strings.Contains(strings.ReplaceAll(out, "allowed_cidrs", "allowed&#95;cidrs"), want) {
			t.Errorf("comment lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(ms[0][2], "var.allowed_cidrs") || !strings.Contains(ms[1][2], `variable "allowed_cidrs"`) {
		t.Errorf("blocks %q / %q", ms[0][2], ms[1][2])
	}
	// committing both suggestions (bottom-up) gives a file that parses and fixes the finding
	f := filepath.Join(iacDir, "modules", "web", "main.tf")
	b, _ := os.ReadFile(f)
	lines := strings.Split(string(b), "\n")
	re := regexp.MustCompile(`modules/web/main\.tf lines? (\d+)(?:–(\d+))?`)
	locs := re.FindAllStringSubmatch(out, -1)
	if len(locs) != 2 {
		t.Fatalf("anchors %v", locs)
	}
	for k := 1; k >= 0; k-- {
		var start, end int
		fmt.Sscan(locs[k][1], &start)
		end = start
		if locs[k][2] != "" {
			fmt.Sscan(locs[k][2], &end)
		}
		nl := append(append(append([]string{}, lines[:start-1]...), strings.Split(ms[k][2], "\n")...), lines[end:]...)
		lines = nl
	}
	patched := strings.Join(lines, "\n")
	if !patchParses("main.tf", patched) {
		t.Fatalf("committed suggestions do not parse:\n%s", patched)
	}
	if strings.Contains(patched, "0.0.0.0/0") {
		t.Errorf("world-open source still present after both suggestions")
	}
	// the committed fixture (var.ssh_cidr): no deterministic patch, no suggestion, the CLI hint stays
	out = planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--iac", filepath.Join("..", "..", "testdata", "action-fixture"))
	if strings.Contains(out, "suggestion\n") || !strings.Contains(out, "cloud-posture fix --finding EC2_SG_OPEN_SSH") {
		t.Errorf("variable-sourced rule: want the CLI hint, no suggestion:\n%s", out)
	}
}

// Never a suggestion the re-scan cannot parse.
func TestPatchParsesRefusesBrokenHCL(t *testing.T) {
	if !patchParses("main.tf", "resource \"a\" \"b\" {\n  x = 1\n}\n") {
		t.Error("valid HCL refused")
	}
	if patchParses("main.tf", "resource \"a\" \"b\" {\n  x = [1\n") {
		t.Error("unparseable HCL accepted")
	}
}

// Shortfall #6: a fixture plan that opens one path, lowers another and closes a third. The
// comment shows "closes 1" and the opened path still gets its one-click suggestions.
func TestPlanCommentClosesFixtureWithSuggestion(t *testing.T) {
	code := catchExit(t)
	out := planComment(t, "--plan-json", fixturePlan("closes.plan.json"), "--redact", "off", "--iac", suggestionFixture(t, false), "--fail-on-opened", "--opened-only")
	for _, want := range []string{"this PR opens 1 / escalates 0 / lowers 1 / closes 1 attack paths", "### Closed (1)", "legacy-host", "### Lowered (1)",
		"7.0 → 1.9 &#40;High → Low&#41;", "nimbus-closes-paths: 1", "nimbus-lowers-paths: 1", "### Suggested changes (2)"} {
		if !strings.Contains(out, want) {
			t.Errorf("closes comment lacks %q:\n%s", want, out)
		}
	}
	if !suggestionBlock.MatchString(out) {
		t.Errorf("no suggestion block:\n%s", out)
	}
	if *code != exitOpened {
		t.Errorf("opened path: exit %d, want %d", *code, exitOpened)
	}
}

func TestSuggestionFenceCannotBreakOut(t *testing.T) {
	r := hostileResult(1)
	hostile := []string{"  cidr_blocks = [\"10.0.0.0/8\"] # ```", "```", "## injected heading", "````suggestion", "@acme/security-team <!-- nimbus-plan-diff -->", "`````"}
	body := renderPlanComment(r, commentOptions{MaxPaths: 10, Suggestions: []planSuggestion{{IssueID: "id", File: "main.tf\n## evil](x)", Start: 3, End: 4,
		Lines: hostile, Canonical: "EC2_SG_OPEN_SSH", Explanation: "evil](javascript:x) @acme", Confidence: 0.8}}})
	// the block must open and close with one fence longer than any backtick run inside it, and
	// everything after the close must be ours (footer intact).
	i := strings.Index(body, "suggestion\n")
	if i < 0 {
		t.Fatalf("no suggestion block:\n%s", body)
	}
	open := body[strings.LastIndex(body[:i], "\n")+1 : i]
	if len(open) < 6 || strings.Trim(open, "`") != "" {
		t.Fatalf("opening fence %q not longer than the 5-backtick run in the content", open)
	}
	rest := body[i+len("suggestion\n"):]
	end := strings.Index(rest, "\n"+open+"\n")
	if end < 0 || rest[:end] != strings.Join(hostile, "\n") {
		t.Fatalf("content not enclosed verbatim:\n%s", body)
	}
	for _, line := range strings.Split(rest[:end], "\n") {
		if t2 := strings.TrimLeft(line, " "); strings.HasPrefix(t2, open) {
			t.Errorf("content line %q can close the fence", line)
		}
	}
	for _, bad := range []string{"\n## evil", "](x)", "](javascript", "@acme/security-team <", "@acme\n"} {
		if strings.Contains(strings.Replace(body, rest[:end], "", 1), bad) {
			t.Errorf("unescaped %q outside the block:\n%s", bad, body)
		}
	}
	if !strings.HasSuffix(body, "nimbus-closes-paths: 0\n") {
		t.Errorf("footer not last:\n%s", body)
	}
}

// With --repo/--pr, each suggestion is also posted once as a pull-request review comment on its
// lines (where GitHub shows "Commit suggestion"); a re-run does not post it again.
func TestPlanCommentPostsReviewSuggestionOnce(t *testing.T) {
	var mu sync.Mutex
	var posted []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls/7/comments"):
			var out []map[string]any
			for _, p := range posted {
				out = append(out, map[string]any{"body": p["body"], "user": map[string]any{"login": "github-actions[bot]"}})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls/7/comments"):
			var p map[string]any
			b, _ := io.ReadAll(r.Body)
			json.Unmarshal(b, &p)
			posted = append(posted, p)
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		case strings.Contains(r.URL.Path, "/issues/"):
			if r.Method == http.MethodGet {
				w.Write([]byte("[]"))
			} else {
				w.WriteHeader(201)
				w.Write([]byte("{}"))
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	iacDir := suggestionFixture(t, true)
	ev := filepath.Join(t.TempDir(), "event.json")
	os.WriteFile(ev, []byte(`{"repository":{"private":true},"pull_request":{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}}`), 0o600)
	t.Setenv("GITHUB_EVENT_PATH", ev)
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "test-token")
	plan := mustAbs(t, fixturePlan("bad.plan.json"))
	t.Chdir(iacDir)
	for i := 0; i < 2; i++ {
		planComment(t, "--plan-json", plan, "--iac", ".", "--repo", "o/r", "--pr", "7", "--redact", "on")
	}
	if len(posted) != 1 {
		t.Fatalf("posted %d review comments, want 1 (idempotent): %v", len(posted), posted)
	}
	p := posted[0]
	if p["path"] != "modules/web/main.tf" || p["line"] != float64(15) || p["side"] != "RIGHT" || p["commit_id"] != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("review comment anchor %v", p)
	}
	if b, _ := p["body"].(string); !suggestionBlock.MatchString(b) || !strings.Contains(b, "var.allowed_cidrs") {
		t.Errorf("review comment body %q", b)
	}
}

func mustAbs(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var _ = model.ConfidenceHint
var _ = pathdiff.ModeLive

// Verify-4 D5 through the CLI: bad.plan.json with the SSH rule already open on both sides plus a
// second public instance (create) in front of the same admin role opens 1 path and exits 3.
func TestPlanCommentSecondPublicHostTripsGate(t *testing.T) {
	b, err := os.ReadFile(fixturePlan("bad.plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	json.Unmarshal(b, &raw)
	rcs := raw["resource_changes"].([]any)
	var h2 map[string]any
	for _, rc := range rcs {
		m := rc.(map[string]any)
		ch := m["change"].(map[string]any)
		if m["type"] == "aws_security_group" {
			ch["before"], ch["actions"] = ch["after"], []any{"no-op"}
		}
		if m["type"] == "aws_instance" {
			c, _ := json.Marshal(m)
			json.Unmarshal(c, &h2)
		}
	}
	h2["address"], h2["name"] = "module.web.aws_instance.host2", "host2"
	ch := h2["change"].(map[string]any)
	after := ch["after"].(map[string]any)
	after["arn"], after["id"], after["public_ip"] = nil, nil, "198.51.100.77"
	ch["before"], ch["actions"] = nil, []any{"create"}
	raw["resource_changes"] = append(rcs, h2)
	p := filepath.Join(t.TempDir(), "second-host.plan.json")
	out, _ := json.Marshal(raw)
	os.WriteFile(p, out, 0o600)
	code := catchExit(t)
	got := planCommentUntrusted(t, "--plan-json", p, "--redact", "off", "--fail-on-opened", "--opened-only")
	if !strings.Contains(got, "this PR opens 1 / escalates 0 / lowers 0 / closes 0") || !strings.Contains(got, "nimbus-opens-paths: 1") {
		t.Errorf("second public host comment:\n%s", got)
	}
	if *code != exitOpened {
		t.Errorf("second public host: exit %d, want %d", *code, exitOpened)
	}
}

// fakeGitHub records review comments and sticky comment bodies; stickyStatus forces the sticky
// POST/PATCH status (0: 201, or 422 when the body is over GitHub's 65,536 characters).
type fakeGitHub struct {
	mu           sync.Mutex
	posted       []map[string]any
	sticky       []string
	stickyStatus int
}

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		var p map[string]any
		json.Unmarshal(b, &p)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls/7/comments"):
			var out []map[string]any
			for _, p := range f.posted {
				out = append(out, map[string]any{"body": p["body"], "user": map[string]any{"login": "github-actions[bot]"}})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls/7/comments"):
			f.posted = append(f.posted, p)
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		case strings.Contains(r.URL.Path, "/issues/"):
			if r.Method == http.MethodGet {
				w.Write([]byte("[]"))
				return
			}
			body, _ := p["body"].(string)
			f.sticky = append(f.sticky, body)
			st := f.stickyStatus
			if st == 0 && len([]rune(body)) > 65536 {
				st = 422
			}
			if st >= 300 {
				w.WriteHeader(st)
				w.Write([]byte(`{"message":"Validation Failed"}`))
				return
			}
			w.WriteHeader(201)
			w.Write([]byte("{}"))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func prEnv(t *testing.T, srv *httptest.Server) {
	ev := filepath.Join(t.TempDir(), "event.json")
	os.WriteFile(ev, []byte(`{"repository":{"private":true},"pull_request":{"head":{"sha":"0123456789abcdef0123456789abcdef01234567"}}}`), 0o600)
	t.Setenv("GITHUB_EVENT_PATH", ev)
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "test-token")
}

// Each hunk of a multi-hunk fix is its own review comment anchored to that hunk's lines.
func TestPlanCommentPostsOneReviewCommentPerHunk(t *testing.T) {
	gh := &fakeGitHub{}
	prEnv(t, gh.server(t))
	iacDir := suggestionFixture(t, false)
	plan := mustAbs(t, fixturePlan("bad.plan.json"))
	t.Chdir(iacDir)
	for i := 0; i < 2; i++ {
		planComment(t, "--plan-json", plan, "--iac", ".", "--repo", "o/r", "--pr", "7", "--redact", "on", "--bot-login", "github-actions[bot]")
	}
	if len(gh.posted) != 2 {
		t.Fatalf("posted %d review comments, want 2 (one per hunk, idempotent)", len(gh.posted))
	}
	lines := map[float64]bool{}
	for _, p := range gh.posted {
		lines[p["line"].(float64)] = true
		if b, _ := p["body"].(string); !suggestionBlock.MatchString(b) || !strings.Contains(b, "part ") || !strings.Contains(b, "confidence **") {
			t.Errorf("review comment body %q", b)
		}
	}
	if !lines[15] || len(lines) != 2 {
		t.Errorf("anchors %v, want line 15 and the appended block's anchor", lines)
	}
}

// Verify-5 H1: a suggestion inflated past GitHub's comment limit (a 70,000-character trailing
// comment on the rewritten line) must not drop the plan-diff comment: the suggestion is
// refused (the CLI hint stays) and the comment is posted.
func TestOversizeSuggestionNeverDropsTheComment(t *testing.T) {
	gh := &fakeGitHub{}
	prEnv(t, gh.server(t))
	dir := suggestionFixture(t, true)
	mf := filepath.Join(dir, "modules", "web", "main.tf")
	b, _ := os.ReadFile(mf)
	os.WriteFile(mf, []byte(strings.Replace(string(b), `cidr_blocks = ["0.0.0.0/0"]`, `cidr_blocks = ["0.0.0.0/0"] # `+strings.Repeat("a", 70000), 1)), 0o644)
	plan := mustAbs(t, fixturePlan("bad.plan.json"))
	t.Chdir(dir)
	code := catchExit(t)
	planComment(t, "--plan-json", plan, "--iac", ".", "--repo", "o/r", "--pr", "7", "--redact", "off", "--bot-login", "github-actions[bot]")
	if len(gh.sticky) != 1 || len([]rune(gh.sticky[0])) > 65536 {
		t.Fatalf("sticky bodies %d (len %d), want one under the limit", len(gh.sticky), len(gh.sticky[0]))
	}
	if !strings.Contains(gh.sticky[0], "opens 1") || strings.Contains(gh.sticky[0], "aaaaaaaaaa") {
		t.Errorf("sticky body: %.400s", gh.sticky[0])
	}
	if *code != -1 {
		t.Errorf("exit %d", *code)
	}
}

// Verify-5 H1: when GitHub still refuses the comment (422: not a fork's read-only token), the
// step fails instead of exiting 0 behind a warning that blames the fork token.
func TestStickyRejectionFailsTheStep(t *testing.T) {
	gh := &fakeGitHub{stickyStatus: 422}
	prEnv(t, gh.server(t))
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "none.db")
	t.Cleanup(func() { flagDB = "" })
	_, err := runErr(t, "pr-comment", "--live", "off", "--plan-json", fixturePlan("bad.plan.json"), "--repo", "o/r", "--pr", "7", "--bot-login", "github-actions[bot]")
	if err == nil || !strings.Contains(err.Error(), "422") {
		t.Fatalf("422 on the sticky comment: err %v, want a failure naming 422", err)
	}
	// a fork's read-only token (403) stays a warning: the gate result is not hidden
	gh.stickyStatus = 403
	if _, err := runErr(t, "pr-comment", "--live", "off", "--plan-json", fixturePlan("bad.plan.json"), "--repo", "o/r", "--pr", "7", "--bot-login", "github-actions[bot]"); err != nil {
		t.Errorf("403 (fork token): err %v, want a warning only", err)
	}
}

// The rendered body never exceeds the budget: past it, suggestions are dropped with a visible
// note, then path lists are trimmed; the footer always survives.
func TestPlanCommentBodyBudget(t *testing.T) {
	r := hostileResult(400)
	var sugs []planSuggestion
	for i := 0; i < 40; i++ {
		sugs = append(sugs, planSuggestion{IssueID: fmt.Sprint(i), File: "main.tf", Start: i*10 + 1, End: i*10 + 1, Lines: []string{strings.Repeat("x", 400), strings.Repeat("y", 400)}, Canonical: "EC2_SG_OPEN_SSH", Confidence: 0.8})
	}
	body := renderPlanComment(r, commentOptions{MaxPaths: 400, Suggestions: sugs})
	if n := len([]rune(body)); n > commentMaxChars {
		t.Fatalf("body %d chars > %d", n, commentMaxChars)
	}
	if !strings.Contains(body, "note: ") || !strings.HasSuffix(body, "nimbus-closes-paths: 0\n") {
		t.Errorf("trimmed body lacks the note or the footer:\n%.600s…%s", body, body[len(body)-200:])
	}
}
