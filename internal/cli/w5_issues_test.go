package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// headlineRe parses store.Headline.Text() wherever a surface prints it.
var headlineRe = regexp.MustCompile(`(\d+) open Issues?: (\d+) attack path Issues? \((\d+) hop variants?\) \+ (\d+) finding Issues?; (\d+) critical \((\d+) path, (\d+) finding\)`)

func parseHeadline(t *testing.T, surface, out string) [7]int {
	t.Helper()
	m := headlineRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%s prints no Issue headline:\n%s", surface, out)
	}
	var n [7]int
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	return n
}

func headlineNums(h *store.Headline) [7]int {
	return [7]int{h.Issues, h.PathIssues, h.PathVariants, h.FindingIssues, h.Critical, h.PathCritical, h.FindingCritical}
}

// W5-ISSUES item 2 (r3 #4, E4/E6/E9/E10/E14): every surface reports the same Issue numbers on
// the lab — ingest, ingest --diff, `issues`, GET /api/summary and the dashboard payload — and
// "critical" means the Issue's severity everywhere.
func TestHeadlineConsistentAcrossSurfacesOnLab(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := labConfig(t)
	ingestOut := run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	st := openTestStore(t)
	h, err := st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	want := headlineNums(h)
	// W7-ENGINE (r5 #3): the lab's verified dev-sam PassRole rule match folds into its traversal
	// twin as also_matches_rule (W6 made it a 20th path Issue / 23rd hop variant, a duplicate):
	// 19 / 22. W7-ENGINE r5 #15 then adds the lab's P21 (foreign aws:PrincipalOrgID trust to an
	// admin role, a real external entry): 20 path Issues / 23 hop variants.
	if h.PathIssues != 20 || h.PathVariants != 23 {
		t.Fatalf("lab headline %+v: want 20 path Issues from 23 hop variants", h)
	}
	if got := parseHeadline(t, "ingest", ingestOut); got != want {
		t.Errorf("ingest %v, store %v", got, want)
	}
	if !strings.Contains(ingestOut, "Ingest complete") || strings.Contains(ingestOut, "Scan complete") {
		t.Errorf("E4: ingest must say Ingest complete:\n%s", ingestOut)
	}
	if strings.Contains(ingestOut, "(22 attack paths)") {
		t.Errorf("E6: variants must not be called attack paths:\n%s", ingestOut)
	}
	if !strings.Contains(ingestOut, flagDB) {
		t.Errorf("E5: ingest must say where it wrote the database:\n%s", ingestOut)
	}
	diffOut := run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary", "--diff")
	if got := parseHeadline(t, "ingest --diff", diffOut[strings.Index(diffOut, "Diff vs"):]); got != want {
		t.Errorf("ingest --diff %v, store %v", got, want)
	}

	// W6-POLISH (r4 #4): `paths` and `plan` count the same path Issues and hop variants, and
	// who-can by bare name answers what it answers by ARN (anonymous first).
	pathsOut := run(t, "-c", cfg, "paths", "--no-dead-ends")
	if want := strconv.Itoa(h.PathIssues) + " attack path Issue(s) from " + strconv.Itoa(h.PathVariants) + " hop variant(s)"; !strings.Contains(pathsOut, want) {
		t.Errorf("paths header lacks %q:\n%s", want, firstLines(pathsOut, 2))
	}
	planOut := run(t, "-c", cfg, "plan")
	if want := "Plan: " + strconv.Itoa(h.PathIssues) + " attack path Issues (" + strconv.Itoa(h.PathVariants) + " hop variants"; !strings.Contains(planOut, want) {
		t.Errorf("plan headline lacks %q:\n%s", want, firstLines(planOut, 2))
	}
	wcARN := run(t, "-c", cfg, "who-can", "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii")
	wcName := run(t, "-c", cfg, "who-can", "s3:GetObject", "nimbus-lab-customer-pii")
	if a, n := firstLines(wcARN, 1), firstLines(wcName, 1); !strings.HasPrefix(n, strings.TrimSuffix(strings.SplitN(a, " on ", 2)[0], ":")) {
		t.Errorf("who-can by name %q, by ARN %q", n, a)
	}
	if !strings.Contains(firstLines(wcName, 2), "anonymous (internet)") {
		t.Errorf("who-can by name must list anonymous (internet) first:\n%s", firstLines(wcName, 3))
	}

	// `issues`: header counts the open Issues ("N of M"), path Issues first, best score on top.
	issuesOut := run(t, "-c", cfg, "issues", "--limit", "3")
	if !strings.Contains(issuesOut, "3 of "+strconv.Itoa(h.Issues)+" open Issues") {
		t.Errorf("E9: issues header:\n%s", issuesOut)
	}
	if got := parseHeadline(t, "issues", issuesOut); got != want {
		t.Errorf("issues %v, store %v", got, want)
	}
	all, _ := st.Issues(store.IssueFilter{OpenOnly: true})
	if all[0].Kind != model.IssuePath || all[0].Score != 10 {
		t.Errorf("E10: first Issue %s %.1f %s", all[0].Kind, all[0].Score, all[0].Title)
	}
	seenFinding := false
	for _, is := range all {
		if is.Kind != model.IssuePath {
			seenFinding = true
		} else if seenFinding {
			t.Fatalf("path Issue %s listed after a finding Issue", is.ID)
		}
		if strings.Contains(is.Title, "nimbus-lab-ops-jane → nimbus-lab-ops-jane") {
			t.Errorf("E7: title %q", is.Title)
		}
	}
	var jane bool
	for _, is := range all {
		if is.Title == "credential compromise of nimbus-lab-ops-jane → AdministratorAccess" {
			jane = true
		}
	}
	if !jane {
		t.Errorf("E7: no credential-entry title for ops-jane")
	}

	// GET /api/summary.
	srv := server.New(st, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/summary")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var sum struct {
		Headline store.Headline `json:"headline"`
	}
	if err := json.Unmarshal(b, &sum); err != nil {
		t.Fatal(err)
	}
	if got := headlineNums(&sum.Headline); got != want {
		t.Errorf("/api/summary %v, store %v", got, want)
	}

	// Dashboard payload: the headline the risk panel prints, and the Issue list it counts from.
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
		Headline   store.Headline `json:"headline"`
		Issues     []model.Issue  `json:"issues"`
		PathGroups []struct {
			IssueID  string `json:"issue_id"`
			Severity string `json:"severity"`
		} `json:"path_groups"`
	}
	if m == nil || json.Unmarshal(m[1], &d) != nil {
		t.Fatal("no dashboard payload")
	}
	if got := headlineNums(&d.Headline); got != want {
		t.Errorf("dashboard headline %v, store %v", got, want)
	}
	open, crit := 0, 0
	for _, is := range d.Issues {
		if model.IsActive(is.State) {
			open++
			if is.Severity == model.Critical {
				crit++
			}
		}
	}
	if open != h.Issues || crit != h.Critical {
		t.Errorf("dashboard issue list: %d open / %d critical, headline %d / %d", open, crit, h.Issues, h.Critical)
	}
	pcrit := 0
	ids := map[string]bool{}
	for _, is := range all {
		ids[is.ID] = true
	}
	for _, g := range d.PathGroups {
		if g.Severity == string(model.Critical) {
			pcrit++
		}
		if !ids[g.IssueID] {
			t.Errorf("dashboard path group %s is not a stored Issue id", g.IssueID)
		}
	}
	if len(d.PathGroups) != h.PathIssues || pcrit != h.PathCritical {
		t.Errorf("dashboard path groups %d (%d critical), headline %d (%d)", len(d.PathGroups), pcrit, h.PathIssues, h.PathCritical)
	}
}

// W5-ISSUES item 1 on the CLI: mark-pending, the state filters and the metrics lines.
func TestIssuesMarkPendingAndClosureMetrics(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := labConfig(t)
	run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	st := openTestStore(t)
	paths, _ := st.Issues(store.IssueFilter{Kind: model.IssuePath, OpenOnly: true})
	id := paths[0].ID
	out := run(t, "-c", cfg, "issues", "mark-pending", id[:12], "--by", "pr:https://github.com/acme/infra/pull/7")
	if !strings.Contains(out, "pending_verification") {
		t.Fatalf("mark-pending: %s", out)
	}
	out = run(t, "-c", cfg, "issues", "--state", "pending")
	if !strings.Contains(out, id) || !strings.Contains(out, "pending_verification") {
		t.Fatalf("--state pending: %s", out)
	}
	out = run(t, "-c", cfg, "issues", "metrics")
	for _, want := range []string{"verified fixed", "resolved (not verified)", "pending verification 1", "regressions after verify"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lacks %q:\n%s", want, out)
		}
	}
}

// Verification 5 C5: native ingest of `{}` or `[{}]` stores nothing and exits 2.
func TestIngestNativeEmptyRecordsExit2(t *testing.T) {
	for name, body := range map[string]string{"obj.json": "{}", "arr.json": "[{}]", "arr2.json": "[{},{}]"} {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		os.MkdirAll(home, 0o755)
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		db := filepath.Join(dir, "p.db")
		out, code := runSelfExit(t, dir, append(iacEnv(t), "HOME="+home), "ingest", p, "--source", "native", "--db", db, "-o", "summary")
		if code != 2 || !strings.Contains(out, "nothing to ingest") {
			t.Errorf("%s: exit %d, want 2:\n%s", name, code, out)
		}
		if _, err := os.Stat(db); err == nil {
			s, err := store.Open(db)
			if err == nil {
				fs, _ := s.Findings(store.Filter{})
				s.Close()
				if len(fs) != 0 {
					t.Errorf("%s: stored %d findings", name, len(fs))
				}
			}
		}
	}
}
