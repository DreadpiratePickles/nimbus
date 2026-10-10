package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// governedDB ingests testdata with a governance config: a kubernetes rule (1-day SLA), an AWS
// account owner (matched through role_arn), CODEOWNERS under the IaC root for IaC findings and
// a default owner. Extra YAML is appended to the config. Returns the db dir and config path.
func governedDB(t *testing.T, extra string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, ".github"), 0o755)
	os.WriteFile(filepath.Join(repo, ".github", "CODEOWNERS"), []byte("# owners\n*.tf @acme/everyone\ninfra/ @acme/platform\n"), 0o644)
	cfg := filepath.Join(dir, "cfg.yaml")
	y := `accounts:
  prod:
    provider: aws
    role_arn: arn:aws:iam::123456789012:role/ReadOnly
    owner: aws-team@example.com
scan:
  iac_paths: [` + repo + `]
governance:
  rules:
    - id: k8s
      match: {provider: kubernetes}
      owner: k8s-team@example.com
      sla_days: {critical: 1, high: 1, medium: 1, low: 1}
      grace_days: 1
  defaults:
    owner: secops@example.com
` + extra
	os.WriteFile(cfg, []byte(y), 0o644)
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	t.Cleanup(func() { flagConfig = "" })
	run(t, "ingest", testdataDir(t), "--config", cfg, "-o", "summary")
	return dir, cfg
}

func issuesJSON(t *testing.T, args ...string) []model.Issue {
	t.Helper()
	var is []model.Issue
	out := run(t, append([]string{"issues", "--json"}, args...)...)
	if err := json.Unmarshal([]byte(out), &is); err != nil {
		t.Fatalf("issues --json: %v\n%s", err, out)
	}
	return is
}

// backdateKubernetes moves the kubernetes findings' history and first_seen to 2026-01-01 so the
// next resolution gives them a due date in the past (k8s rule: 1-day SLA).
func backdateKubernetes(t *testing.T, cfg string) {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"UPDATE finding_history SET at = '2026-01-01T00:00:00Z' WHERE fingerprint IN (SELECT id FROM findings WHERE provider = 'kubernetes')",
		"UPDATE findings SET first_seen = '2026-01-01T00:00:00Z' WHERE provider = 'kubernetes'",
		"UPDATE issues SET first_seen = '2026-01-01T00:00:00Z' WHERE provider = 'kubernetes' AND kind <> 'path'",
	} {
		if _, err := st.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	run(t, "prioritize", "--config", cfg, "--json") // re-resolves every Issue
}

// Integration pass 4 items 1–3, 6: every Issue is resolved and persisted on ingest; overdue /
// owner filters; issues metrics; prioritize carries the governance due date, never the
// retired risk band date.
func TestGovernanceWiredEndToEnd(t *testing.T) {
	_, cfg := governedDB(t, "")
	all := issuesJSON(t, "--state", "all", "--config", cfg)
	if len(all) == 0 {
		t.Fatal("no Issues")
	}
	seen := map[string]bool{}
	for _, is := range all {
		if is.OwnerSource == "" || is.OwnerWhy == "" {
			t.Errorf("%s (%s/%s) not resolved: %+v", is.ID, is.Provider, is.Account, is)
			continue
		}
		if is.Severity != model.Info && is.DueAt == nil {
			t.Errorf("%s %s: no due date", is.ID, is.Severity)
		}
		want := ""
		switch {
		case is.Provider == "kubernetes":
			want = "k8s-team@example.com"
		case is.Account == "123456789012":
			want = "aws-team@example.com"
		case is.Account == "iac" && is.Kind != model.IssuePath && strings.HasPrefix(is.ResourceID, "aws_"):
			want = "@acme/platform" // CODEOWNERS under the IaC root, last match wins (infra/)
		case is.Provider == "azure":
			want = "secops@example.com"
		}
		if is.OwnerSource == "tag" {
			want = "" // a resource owner/team tag wins over the account owner (docs/governance.md)
		}
		if want != "" && is.Owner != want {
			t.Errorf("%s %s/%s %s: owner %q (%s: %s), want %q", is.ID, is.Provider, is.Account, is.ResourceID, is.Owner, is.OwnerSource, is.OwnerWhy, want)
		}
		seen[is.OwnerSource] = true
	}
	for _, src := range []string{"rule", "tag", "account", "codeowners", "default"} {
		if !seen[src] {
			t.Errorf("no Issue resolved through %s (sources seen %v)", src, seen)
		}
	}
	if od := issuesJSON(t, "--overdue", "--config", cfg); len(od) != 0 {
		t.Fatalf("fresh ingest has %d overdue Issues", len(od))
	}

	backdateKubernetes(t, cfg)
	od := issuesJSON(t, "--overdue", "--config", cfg)
	if len(od) == 0 {
		t.Fatal("no overdue Issues after backdating kubernetes (1-day SLA)")
	}
	for _, is := range od {
		if is.Provider != "kubernetes" || !is.Overdue || is.Owner != "k8s-team@example.com" || is.DueAt == nil || !is.DueAt.Equal(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("overdue Issue %+v: want kubernetes, k8s-team, due 2026-01-02", is)
		}
	}
	mine := issuesJSON(t, "--owner", "K8S-team@example.com", "--config", cfg)
	if len(mine) < len(od) {
		t.Errorf("--owner k8s-team: %d Issues, fewer than its %d overdue ones", len(mine), len(od))
	}
	txt := run(t, "issues", "--overdue", "--config", cfg)
	if !strings.Contains(txt, "OVERDUE") || !strings.Contains(txt, "k8s-team@example.com") || !strings.Contains(txt, "due 2026-01-02") {
		t.Errorf("issues --overdue text lacks owner / due / OVERDUE:\n%s", txt)
	}

	// issues metrics: MTTR by severity, on-time rate, overdue by owner.
	m := run(t, "issues", "metrics", "--config", cfg)
	for _, want := range []string{"MTTR", "on-time", "overdue by owner", "k8s-team@example.com"} {
		if !strings.Contains(m, want) {
			t.Errorf("issues metrics lacks %q:\n%s", want, m)
		}
	}
	var mj struct {
		Open           int            `json:"open"`
		OpenPastDue    int            `json:"open_past_due"`
		OverdueByOwner map[string]int `json:"overdue_by_owner"`
		OpenByOwner    map[string]int `json:"open_by_owner"`
		MTTRHours      map[string]float64
	}
	if err := json.Unmarshal([]byte(run(t, "issues", "metrics", "--json", "--config", cfg)), &mj); err != nil {
		t.Fatal(err)
	}
	if mj.OverdueByOwner["k8s-team@example.com"] != len(od) || mj.OpenPastDue != len(od) || mj.Open == 0 {
		t.Errorf("metrics %+v, want %d overdue for k8s-team", mj, len(od))
	}

	// One due date everywhere: prioritize shows the Issue's governance due date; the retired
	// risk band date (first_seen + 7/30/90/180 days) appears nowhere.
	byFinding := map[string]model.Issue{}
	for _, is := range issuesJSON(t, "--state", "all", "--config", cfg) {
		for _, f := range is.FindingIDs {
			if is.Kind == model.IssueSingle {
				byFinding[f] = is
			}
		}
	}
	var ranked []risk.Ranked
	pj := run(t, "prioritize", "--top", "0", "--json", "--config", cfg)
	if err := json.Unmarshal([]byte(pj), &ranked); err != nil {
		t.Fatal(err)
	}
	pt := run(t, "prioritize", "--top", "0", "--config", cfg)
	retired := map[string]bool{}
	checked := 0
	for _, r := range ranked {
		is, ok := byFinding[r.Finding.ID]
		if !ok {
			continue
		}
		checked++
		if is.DueAt == nil || !r.DueAt.Equal(*is.DueAt) || r.Owner != is.Owner || r.SLADays != is.SLADays {
			t.Errorf("prioritize %s: owner %q sla %d due %v; Issue %s says %q %d %v", r.Finding.ID, r.Owner, r.SLADays, r.DueAt, is.ID, is.Owner, is.SLADays, is.DueAt)
		}
		if r.Finding.Provider == "kubernetes" {
			for _, d := range []int{7, 30, 90, 180} {
				retired[r.Finding.FirstSeen.Add(time.Duration(d)*24*time.Hour).Format("2006-01-02")] = true
			}
		}
	}
	if checked == 0 || len(retired) == 0 {
		t.Fatalf("nothing checked (%d ranked, %d retired dates)", checked, len(retired))
	}
	// prioritize --json was compared row by row above; the text rows of the k8s-owned findings
	// show only the governance date, and their Issue page never shows a retired date.
	k8sRows := 0
	for _, ln := range strings.Split(pt, "\n") {
		if strings.Contains(ln, "owner: k8s-team@example.com") {
			k8sRows++
			if !strings.Contains(ln, "due 2026-01-02 OVERDUE") {
				t.Errorf("prioritize row lacks the governance due date: %s", ln)
			}
			for d := range retired {
				if strings.Contains(ln, d) {
					t.Errorf("prioritize row shows the retired risk due date %s: %s", d, ln)
				}
			}
		}
	}
	if k8sRows == 0 {
		t.Errorf("no prioritize row owned by k8s-team:\n%s", pt)
	}
	show := run(t, "issues", "show", od[0].ID, "--config", cfg)
	for d := range retired {
		if strings.Contains(show, d) {
			t.Errorf("issues show shows the retired risk due date %s", d)
		}
	}
	for _, want := range []string{"k8s-team@example.com", "rule k8s", "due 2026-01-02", "OVERDUE", "grace until 2026-01-03"} {
		if !strings.Contains(show, want) {
			t.Errorf("issues show lacks %q:\n%s", want, show)
		}
	}
}

// A rule edit applies on the next run (re-resolve every run).
func TestGovernanceReResolvesOnEveryRun(t *testing.T) {
	dir, _ := governedDB(t, "")
	cfg2 := filepath.Join(dir, "cfg2.yaml")
	os.WriteFile(cfg2, []byte("governance:\n  defaults:\n    owner: new-owner@example.com\n"), 0o644)
	run(t, "prioritize", "--config", cfg2, "--json")
	for _, is := range issuesJSON(t, "--state", "all", "--config", cfg2) {
		if is.Owner != "new-owner@example.com" && is.OwnerSource != "tag" && is.OwnerSource != "codeowners" {
			t.Errorf("%s still owned by %q (%s) after the rules changed", is.ID, is.Owner, is.OwnerSource)
		}
	}
}

type slackFake struct {
	mu    sync.Mutex
	posts []string
}

func (s *slackFake) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.posts) }

// Item 4: alert --digest builds per-owner digests, sends them to Slack, records them in
// <db dir>/digest-ledger.json, and an unchanged second run sends nothing.
func TestAlertDigestSlackDedup(t *testing.T) {
	fake := &slackFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<20)
		n, _ := r.Body.Read(b)
		fake.mu.Lock()
		fake.posts = append(fake.posts, string(b[:n]))
		fake.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	t.Setenv("NIMBUS_TEST_SLACK", srv.URL+"/hook")
	dir, cfg := governedDB(t, "  digest:\n    sink: slack\nintegrations:\n  slack:\n    url_env: NIMBUS_TEST_SLACK\n")

	out := run(t, "alert", "--digest", "--dry-run", "--config", cfg)
	if fake.count() != 0 || !strings.Contains(out, "k8s-team@example.com") || !strings.Contains(out, "would send") {
		t.Fatalf("dry run posted %d or lacks the digest text:\n%s", fake.count(), out)
	}
	out = run(t, "alert", "--digest", "--config", cfg)
	sent := fake.count()
	if sent < 3 {
		t.Fatalf("digest sent %d Slack messages, want one per owner (≥ 3):\n%s", sent, out)
	}
	if !strings.Contains(fake.posts[0], `"blocks"`) {
		t.Errorf("not a Block Kit payload: %s", fake.posts[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "digest-ledger.json")); err != nil {
		t.Errorf("ledger not at <db dir>/digest-ledger.json: %v", err)
	}
	out = run(t, "alert", "--digest", "--config", cfg)
	if fake.count() != sent {
		t.Fatalf("second unchanged digest run sent %d more messages:\n%s", fake.count()-sent, out)
	}
	if !strings.Contains(out, "skipped") {
		t.Errorf("second run does not report skipped digests:\n%s", out)
	}
	// --digest-sink stdout overrides the configured sink and prints the text body.
	out = run(t, "alert", "--digest", "--digest-sink", "stdout", "--since", "720h", "--config", cfg)
	if fake.count() != sent || !strings.Contains(out, "Governance digest for k8s-team@example.com") || !strings.Contains(out, "OPEN CRITICAL") {
		t.Errorf("stdout digest:\n%s", out)
	}
}

type jiraFake struct {
	mu      sync.Mutex
	creates int
	n       int
}

// Item 5 through the CLI: alert --to jira opens one ticket per Issue (not per finding), records
// it on the Issue, is idempotent on the next run, and the Issue page shows the ticket.
func TestAlertJiraOneTicketPerIssueCLI(t *testing.T) {
	fake := &jiraFake{}
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/rest/api/3/search"):
			w.Write([]byte(`{"issues":[]}`))
		case r.URL.Path == "/rest/api/3/user/search":
			w.Write([]byte(`[]`))
		case r.URL.Path == "/rest/api/3/issue" && r.Method == http.MethodPost:
			fake.creates++
			fake.n++
			b := make([]byte, 1<<20)
			n, _ := r.Body.Read(b)
			bodies = append(bodies, string(b[:n]))
			w.WriteHeader(201)
			w.Write([]byte(`{"key":"SEC-` + itoa(fake.n) + `"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("NIMBUS_TEST_JIRA_TOKEN", "tok")
	_, cfg := governedDB(t, "integrations:\n  jira:\n    url: "+srv.URL+"\n    email: bot@example.com\n    token_env: NIMBUS_TEST_JIRA_TOKEN\n    project: SEC\n")
	crit := issuesJSON(t, "--severity", "critical", "--config", cfg)
	var findings int
	for _, is := range crit {
		if is.Severity == model.Critical {
			findings += len(is.FindingIDs)
		}
	}
	run(t, "alert", "--to", "jira", "--min-severity", "CRITICAL", "--config", cfg)
	wantTickets := 0
	for _, is := range crit {
		if is.Severity == model.Critical {
			wantTickets++
		}
	}
	if fake.creates != wantTickets {
		t.Fatalf("created %d Jira tickets for %d critical Issues (%d findings), want one per Issue", fake.creates, wantTickets, findings)
	}
	for _, b := range bodies {
		if !regexp.MustCompile(`"duedate":"\d{4}-\d{2}-\d{2}"`).MatchString(b) {
			t.Errorf("ticket without a governance due date: %s", b[:min(300, len(b))])
		}
	}
	run(t, "alert", "--to", "jira", "--min-severity", "CRITICAL", "--config", cfg)
	if fake.creates != wantTickets {
		t.Fatalf("second alert run created %d more tickets", fake.creates-wantTickets)
	}
	after := issuesJSON(t, "--severity", "critical", "--config", cfg)
	var withTicket *model.Issue
	for i := range after {
		if after[i].TicketKey != "" {
			withTicket = &after[i]
		}
	}
	if withTicket == nil {
		t.Fatal("no Issue records its ticket")
	}
	show := run(t, "issues", "show", withTicket.ID, "--config", cfg)
	if !strings.Contains(show, "ticket:    jira "+withTicket.TicketKey) || !strings.Contains(show, withTicket.TicketURL) {
		t.Errorf("issues show lacks the Issue ticket %s:\n%s", withTicket.TicketKey, show)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
