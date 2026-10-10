package server

// Integration pass 4: governance over the API — owner / overdue filters, the governance fields
// in every Issue JSON, GET /api/governance/metrics, the Issue page owner/ticket and the single
// due date on /api/risk/top.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func governIssues(t *testing.T, s *Server) (overdueID string) {
	t.Helper()
	is, err := s.st.Issues(store.IssueFilter{})
	if err != nil || len(is) == 0 {
		t.Fatalf("issues: %v", err)
	}
	past := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	future := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	var rows []store.IssueGovernance
	for _, i := range is {
		row := store.IssueGovernance{ID: i.ID, Owner: "secops@example.com", Source: "default", Why: "default owner", SLADays: 30, DueAt: &future}
		if model.IsActive(i.State) && overdueID == "" && i.Kind == model.IssueSingle {
			g := past.Add(72 * time.Hour)
			row = store.IssueGovernance{ID: i.ID, Owner: "@acme/platform", Source: "codeowners", RuleID: "tf", Why: "rule tf: CODEOWNERS line 2", SLADays: 7, DueAt: &past, GraceUntil: &g}
			overdueID = i.ID
		}
		rows = append(rows, row)
	}
	if err := s.st.SetIssueGovernance(rows); err != nil {
		t.Fatal(err)
	}
	if overdueID == "" {
		t.Fatal("no open single Issue to make overdue")
	}
	return overdueID
}

func govGet(t *testing.T, ts *httptest.Server, path string, v any) int {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v != nil && resp.StatusCode == 200 {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return resp.StatusCode
}

func TestGovernanceAPI(t *testing.T) {
	s, _ := seedLifecycle(t)
	od := governIssues(t, s)
	s.st.SetIssueTicket(od, store.IssueTicket{Sink: "jira", Key: "SEC-9", URL: "https://jira.example.com/browse/SEC-9", State: "open"})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	var all []model.Issue
	govGet(t, ts, "/api/issues?state=all", &all)
	for _, i := range all {
		if i.Owner == "" || i.OwnerSource == "" || i.DueAt == nil {
			t.Errorf("Issue JSON lacks governance fields: %+v", i)
		}
	}
	var over []model.Issue
	if c := govGet(t, ts, "/api/issues?overdue=1", &over); c != 200 || len(over) != 1 || over[0].ID != od || !over[0].Overdue {
		t.Fatalf("overdue=1: %d %+v", c, over)
	}
	var mine []model.Issue
	govGet(t, ts, "/api/issues?state=all&owner=%40acme%2Fplatform", &mine)
	if len(mine) != 1 || mine[0].ID != od || mine[0].OwnerSource != "codeowners" || mine[0].OwnerWhy == "" || mine[0].GraceUntil == nil {
		t.Fatalf("owner=@acme/platform: %+v", mine)
	}
	if c := govGet(t, ts, "/api/issues?overdue=maybe", nil); c != 400 {
		t.Errorf("overdue=maybe: %d, want 400", c)
	}

	var m GovernanceMetrics
	if c := govGet(t, ts, "/api/governance/metrics", &m); c != 200 {
		t.Fatalf("metrics: %d", c)
	}
	if m.OpenPastDue != 1 || m.OverdueByOwner["@acme/platform"] != 1 || m.OpenByOwner["secops@example.com"] == 0 || len(m.Owners) < 2 || m.Owners[0].Owner != "@acme/platform" {
		t.Errorf("metrics = %+v", m)
	}
	if _, ok := m.ResolvedBySeverity["LOW"]; !ok {
		t.Errorf("resolved LOW Issue (logging) missing from MTTR inputs: %+v", m.ResolvedBySeverity)
	}

	var pg IssuePage
	govGet(t, ts, "/api/issues/"+od, &pg)
	if pg.Owner.Owner != "@acme/platform" || pg.Owner.Source != "codeowners" || pg.Owner.Rule != "tf" || pg.Owner.Why == "" || !pg.Owner.Overdue ||
		pg.Owner.DueAt == nil || pg.Owner.GraceUntil == nil || !pg.Owner.PastGrace {
		t.Errorf("issue page owner = %+v", pg.Owner)
	}
	if pg.Ticket == nil || pg.Ticket.Ref != "SEC-9" || pg.Ticket.Channel != "jira" {
		t.Errorf("issue page ticket = %+v", pg.Ticket)
	}

	// /api/risk/top: due_at / owner are the Issue's governance values, never a band SLA.
	var ranked []struct {
		Finding model.Finding `json:"finding"`
		Owner   string        `json:"owner"`
		SLADays int           `json:"sla_days"`
		DueAt   time.Time     `json:"due_at"`
	}
	govGet(t, ts, "/api/risk/top", &ranked)
	byFinding := map[string]model.Issue{}
	for _, i := range all {
		for _, f := range i.FindingIDs {
			if i.Kind == model.IssueSingle {
				byFinding[f] = i
			}
		}
	}
	n := 0
	for _, r := range ranked {
		if is, ok := byFinding[r.Finding.ID]; ok {
			n++
			if r.Owner != is.Owner || r.SLADays != is.SLADays || !r.DueAt.Equal(*is.DueAt) {
				t.Errorf("risk/top %s: %q %d %v; Issue %q %d %v", r.Finding.ID, r.Owner, r.SLADays, r.DueAt, is.Owner, is.SLADays, is.DueAt)
			}
		}
	}
	if n == 0 {
		t.Error("risk/top checked nothing")
	}
}
