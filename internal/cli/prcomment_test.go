package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/pathdiff"
)

func fixturePlan(name string) string {
	return filepath.Join("..", "..", "testdata", "action-fixture", "plans", name)
}

// planComment runs `pr-comment --plan-json` without a DB (plan-only) and returns stdout.
func planComment(t *testing.T, args ...string) string {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "none.db")
	t.Cleanup(func() { flagDB = "" })
	return run(t, append([]string{"pr-comment", "--live", "off", "--trusted-cidr", "203.0.113.0/24"}, args...)...)
}

func TestPRCommentPlanDiffFixture(t *testing.T) {
	out := planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--redact", "off")
	for _, want := range []string{"opens 1", "closes 0", "fixture-host-role", "exposed+admin", "sg_open_port",
		"cloud-posture fix --finding EC2_SG_OPEN_SSH", "nimbus-opens-paths: 1", "nimbus-closes-paths: 0", "hint", "0.0.0.0/0"} {
		if !strings.Contains(out, want) {
			t.Errorf("bad plan comment lacks %q:\n%s", want, out)
		}
	}
	rev := planComment(t, "--plan-json", fixturePlan("revert.plan.json"), "--redact", "off")
	for _, want := range []string{"opens 0", "closes 1", "nimbus-closes-paths: 1", "nimbus-opens-paths: 0"} {
		if !strings.Contains(rev, want) {
			t.Errorf("revert comment lacks %q:\n%s", want, rev)
		}
	}
}

func TestPRCommentRedacted(t *testing.T) {
	out := planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--redact", "on")
	for _, leak := range []string{"fixture-host", "arn:", "123456789012", "i-0fixture", "sg-0fixture", "198.51.100"} {
		if strings.Contains(out, leak) {
			t.Errorf("redacted comment leaks %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"opens 1", "aws_iam_role", "aws_instance", "exposes", "nimbus-opens-paths: 1", "redacted"} {
		if !strings.Contains(out, want) {
			t.Errorf("redacted comment lacks %q:\n%s", want, out)
		}
	}
}

func TestRedactAutoFollowsRepoVisibility(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "event.json")
	for _, c := range []struct {
		private bool
		want    bool
	}{{false, true}, {true, false}} {
		b, _ := json.Marshal(map[string]any{"repository": map[string]any{"private": c.private}})
		os.WriteFile(ev, b, 0o600)
		t.Setenv("GITHUB_EVENT_PATH", ev)
		if got := redactFor("auto"); got != c.want {
			t.Errorf("private=%v: redact %v, want %v", c.private, got, c.want)
		}
	}
	t.Setenv("GITHUB_EVENT_PATH", filepath.Join(dir, "missing.json"))
	if !redactFor("auto") {
		t.Error("unknown visibility must redact")
	}
}

func hostileResult(n int) pathdiff.Result {
	evil := "evil](javascript:alert(1)) <img src=x onerror=1> @acme/security-team `x` | col\n## injected heading <!-- nimbus-plan-diff --> *bold* _u_"
	r := pathdiff.Result{Mode: pathdiff.ModeLive, Confidence: model.ConfidenceInferred, ConfidenceNote: "note"}
	for i := 0; i < n; i++ {
		r.Opened = append(r.Opened, pathdiff.PathRef{IssueID: "id", Entry: "internet", Anchor: "arn:aws:iam::1:role/" + evil, AnchorName: evil, AnchorType: "aws_iam_role",
			Score: float64(9 - i), Band: "High", Hops: []pathdiff.HopRef{{ID: "x", Name: evil, Type: "aws_instance", Relation: "exposes", Changed: true}, {ID: "y", Name: evil, Type: "aws_iam_role", Relation: "runs_as"}},
			ChangedHop: 0, Why: evil, ChangedBy: "module.web." + evil, FixTemplate: "sg_open_port", FixCommand: "cloud-posture fix --finding EC2_SG_OPEN_SSH --generate-terraform"})
	}
	return r
}

func TestPlanCommentEscapesCloudStrings(t *testing.T) {
	body := renderPlanComment(hostileResult(1), commentOptions{MaxPaths: 10})
	for _, bad := range []string{"](javascript", "<img", "@acme", "\n## injected", "<!-- nimbus-plan-diff", "| col", "`x`"} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped %q in:\n%s", bad, body)
		}
	}
	if !strings.Contains(body, "nimbus-opens-paths: 1") {
		t.Errorf("footer missing:\n%s", body)
	}
}

func TestPlanCommentMaxPaths(t *testing.T) {
	body := renderPlanComment(hostileResult(5), commentOptions{MaxPaths: 2})
	if n := strings.Count(body, "score "); n != 2 {
		t.Errorf("listed %d paths, want 2:\n%s", n, body)
	}
	if !strings.Contains(body, "3 more") || !strings.Contains(body, "opens 5") || !strings.Contains(body, "nimbus-opens-paths: 5") {
		t.Errorf("cap summary / counts missing:\n%s", body)
	}
}

func TestPRCommentSARIFAndFailOnOpened(t *testing.T) {
	dir := t.TempDir()
	sarif := filepath.Join(dir, "paths.sarif")
	code := -1
	old := exitFn
	exitFn = func(c int) { code = c }
	defer func() { exitFn = old }()
	planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--sarif", sarif, "--fail-on-opened", "--redact", "on")
	if code != exitOpened {
		t.Errorf("--fail-on-opened exit %d, want %d", code, exitOpened)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	b, err := os.ReadFile(sarif)
	if err != nil || json.Unmarshal(b, &doc) != nil || doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("sarif: %v %s", err, b)
	}
	if r := doc.Runs[0].Results[0]; r.RuleID != "NIMBUS_PATH_OPENED" || r.Level != "error" || strings.Contains(r.Message.Text, "fixture-host") {
		t.Errorf("sarif result %+v", r)
	}
	code = -1
	planComment(t, "--plan-json", fixturePlan("revert.plan.json"), "--fail-on-opened")
	if code != -1 {
		t.Errorf("closing plan exited %d", code)
	}
}

func TestPRCommentRejectsHostilePlan(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "deep.json")
	os.WriteFile(p, []byte(`{"resource_changes":`+strings.Repeat("[", 70000)+strings.Repeat("]", 70000)+`}`), 0o600)
	flagDB = filepath.Join(dir, "none.db")
	defer func() { flagDB = "" }()
	resetFlags()
	root.SetArgs([]string{"pr-comment", "--plan-json", p, "--live", "off"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("70k-nested plan: %v", err)
	}
}
