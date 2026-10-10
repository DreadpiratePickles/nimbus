package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W6-POLISH item 2 (r4 #4, E6/E7/N6/N9): one title builder for path Issues, one tie order, the
// Issue headline on `plan`, `scan --iac` and `who-can` agreeing with the store.

// selfLoop matches the "X → X" title shape the r4 walk saw ("nimbus-lab-vendor-access →
// nimbus-lab-vendor-access → Privilege escalation to …").
var selfLoop = regexp.MustCompile(`(?:^|\s)(\S+) → (\S+)(?:\s|$)`)

func hasSelfLoop(s string) bool {
	for _, m := range selfLoop.FindAllStringSubmatch(s, -1) {
		if m[1] == m[2] {
			return true
		}
	}
	return false
}

// pathRowRe is one path row of `paths` text output: " 1. [CRITICAL 10.0] <title>…".
var pathRowRe = regexp.MustCompile(`(?m)^\s*\d+\. \[([A-Z]+) ([0-9.]+)\] (.+)$`)

func w6IngestLab(t *testing.T) (cfg string) {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg = labConfig(t)
	run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	return cfg
}

func storedPathIssues(t *testing.T) []model.Issue {
	t.Helper()
	st := openTestStore(t)
	all, err := st.Issues(store.IssueFilter{OpenOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Issue
	for _, is := range all {
		if is.Kind == model.IssuePath {
			out = append(out, is)
		}
	}
	return out
}

func TestPathTitlesAreTheIssueTitlesEverywhereOnLab(t *testing.T) {
	cfg := w6IngestLab(t)
	issues := storedPathIssues(t)
	h, err := openTestStore(t).Headline()
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != h.PathIssues || h.PathIssues < 19 {
		t.Fatalf("lab: %d open path Issues, headline %d (want ≥ 19)", len(issues), h.PathIssues)
	}

	// `paths`: one row per path Issue, titled exactly as the Issue, in the Issue order.
	out := run(t, "-c", cfg, "paths", "--no-dead-ends")
	rows := pathRowRe.FindAllStringSubmatch(out, -1)
	if len(rows) != len(issues) {
		t.Fatalf("paths printed %d rows, store has %d path Issues:\n%s", len(rows), len(issues), out)
	}
	for i, r := range rows {
		if hasSelfLoop(r[3]) {
			t.Errorf("E7: paths row %d is titled %q", i+1, r[3])
		}
		if !strings.HasPrefix(r[3], issues[i].Title) {
			t.Errorf("paths row %d %q: want the Issue title %q (Issue order: score, then rule, then anchor)", i+1, r[3], issues[i].Title)
		}
		if r[2] != fmt.Sprintf("%.1f", issues[i].Score) {
			t.Errorf("paths row %d score %s, Issue %.1f", i+1, r[2], issues[i].Score)
		}
	}

	// r4 E12: every row names its Issue id (the demo's next command is `issues show <id>`).
	for _, is := range issues {
		if !strings.Contains(out, "Issue "+is.ID+" · cloud-posture issues show") {
			t.Errorf("E12: paths does not print Issue %s (%s)", is.ID, is.Title)
		}
	}

	// `plan`: headline counts Issues (not variants); no X → X anywhere.
	plan := run(t, "-c", cfg, "plan", "--top", "20")
	if want := fmt.Sprintf("%d attack path Issues (%d hop variants", h.PathIssues, h.PathVariants); !strings.Contains(plan, want) {
		t.Errorf("E6: plan headline must count path Issues:\n%s", firstLines(plan, 3))
	}
	if strings.Contains(plan, fmt.Sprintf("Plan: %d attack path(s)", h.PathVariants)) {
		t.Errorf("E6: plan still counts hop variants as attack paths")
	}
	for _, ln := range strings.Split(plan, "\n") {
		if hasSelfLoop(ln) {
			t.Errorf("E7: plan line %q", ln)
		}
	}

	// Dashboard payload: path group names are the Issue titles, in the Issue order.
	res, st2, err := loadResult(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st2.Close()
	html, err := renderDashboard(res, "static", "")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`).FindSubmatch(html)
	var d struct {
		PathGroups []struct {
			IssueID string `json:"issue_id"`
			Name    string `json:"name"`
		} `json:"path_groups"`
		PathTitles map[string]string `json:"path_titles"`
	}
	if m == nil || json.Unmarshal(m[1], &d) != nil {
		t.Fatal("no dashboard payload")
	}
	if len(d.PathGroups) != len(issues) {
		t.Fatalf("dashboard path groups %d, Issues %d", len(d.PathGroups), len(issues))
	}
	for i, g := range d.PathGroups {
		if g.IssueID != issues[i].ID || g.Name != issues[i].Title {
			t.Errorf("dashboard group %d = %s %q, want %s %q", i, g.IssueID, g.Name, issues[i].ID, issues[i].Title)
		}
	}
	if len(d.PathTitles) == 0 {
		t.Error("dashboard payload has no path_titles (every hop variant's Issue title)")
	}
	for id, title := range d.PathTitles {
		if hasSelfLoop(title) {
			t.Errorf("dashboard path %s title %q", id, title)
		}
	}
}

func firstLines(s string, n int) string {
	l := strings.SplitN(s, "\n", n+1)
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}

// N6: who-can by bare name resolves the same node as by ARN and lists anonymous (internet) first.
func TestWhoCanByNameMatchesARNOnLab(t *testing.T) {
	cfg := w6IngestLab(t)
	byARN := run(t, "-c", cfg, "who-can", "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii", "--json")
	byName := run(t, "-c", cfg, "who-can", "s3:GetObject", "nimbus-lab-customer-pii", "--json")
	var a, n []struct {
		Principal string `json:"principal"`
		Holder    string `json:"holder"`
	}
	if err := json.Unmarshal([]byte(byARN), &a); err != nil {
		t.Fatalf("%v\n%s", err, byARN)
	}
	if err := json.Unmarshal([]byte(byName), &n); err != nil {
		t.Fatalf("%v\n%s", err, byName)
	}
	// 23 since W7-ENGINE r5 #15: the lab's S31 admin roles (partner-sync, org-admin) can read too.
	if len(a) != 23 || len(n) != len(a) {
		t.Fatalf("who-can by ARN %d, by name %d (want 23 both)", len(a), len(n))
	}
	for i := range a {
		if a[i].Principal != n[i].Principal {
			t.Errorf("row %d: by ARN %q, by name %q", i, a[i].Principal, n[i].Principal)
		}
	}
	if !strings.Contains(n[0].Principal, "anonymous") {
		t.Errorf("by name: first principal %q, want anonymous (internet)", n[0].Principal)
	}
	text := run(t, "-c", cfg, "who-can", "s3:GetObject", "nimbus-lab-customer-pii")
	if !strings.Contains(text, "23 principal(s) can s3:GetObject on nimbus-lab-customer-pii (arn:aws:s3:::nimbus-lab-customer-pii)") {
		t.Errorf("who-can by name must say which resource it resolved:\n%s", firstLines(text, 3))
	}
	// Deterministic: the same call twice prints the same list.
	if again := run(t, "-c", cfg, "who-can", "s3:GetObject", "nimbus-lab-customer-pii"); again != text {
		t.Error("who-can order is not deterministic")
	}
	// An ambiguous or unknown name is an error, not an empty answer about a non-node.
	if _, err := runErr(t, "-c", cfg, "who-can", "s3:GetObject", "no-such-bucket-anywhere"); err == nil {
		t.Error("who-can on a name no node has must fail with a hint")
	}
}

// N9 + N8: `scan --iac` prints the store's Issue headline and labels the top-ranked finding's
// score as a finding risk score (no "0 critical" beside "Top risk: 9.8 Critical"); its run
// files go beside the database, never into the working directory.
func TestScanIaCHeadlineAndRunDir(t *testing.T) {
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	flagDB = filepath.Join(dbDir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	t.Setenv("PATH", "") // native IaC scan only: deterministic without trivy/checkov
	tf, _ := filepath.Abs(filepath.Join("..", "..", "lab", "terraform", "aws"))
	cwd := filepath.Join(dir, "cwd")
	os.MkdirAll(cwd, 0o755)
	t.Chdir(cwd)
	out, _ := runErr(t, "scan", "--iac", tf)
	if _, err := os.Stat(filepath.Join(cwd, ".cloud-posture")); err == nil {
		t.Errorf("N8: scan --iac created .cloud-posture in the working directory")
	}
	if _, err := os.Stat(filepath.Join(dbDir, "runs")); err != nil {
		t.Errorf("N8: run files must go beside the database (%s/runs): %v", dbDir, err)
	}
	st := openTestStore(t)
	h, err := st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	if got := parseHeadline(t, "scan --iac", out); got != headlineNums(h) {
		t.Errorf("scan --iac headline %v, store %v", got, headlineNums(h))
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "Top risk:") {
			t.Errorf("N9: unlabelled top risk line %q", ln)
		}
		if strings.HasPrefix(ln, "Top-ranked finding:") {
			if !strings.Contains(ln, "risk score") || !strings.Contains(ln, "severity") {
				t.Errorf("N9: top finding line must name its risk score and severity: %q", ln)
			}
			if h.Critical == 0 && strings.Contains(ln, "Critical") {
				t.Errorf("N9: %q beside 0 critical Issues", ln)
			}
		}
	}
}
