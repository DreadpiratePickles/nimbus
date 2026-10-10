package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W7-VERIFY r5 #11: the Issue page carries the Issue's score journey (points + the one-line text
// sparkline `issues show` prints), and GET /api/issues/{id}/history?scores=1 carries the per-scan
// scores next to the transitions (the plain form stays the transitions array).
func TestIssuePageAndHistoryCarryScores(t *testing.T) {
	s, _ := seedLifecycle(t)
	issues, err := s.st.Issues(store.IssueFilter{})
	if err != nil || len(issues) == 0 {
		t.Fatal(err)
	}
	id := issues[0].ID
	t1 := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for i, sc := range []float64{9.5, 6.0} {
		scan := "w7-" + string(rune('a'+i))
		s.st.StageIssueScores(scan, map[string]store.IssueScore{id: {Score: sc}})
		if err := s.st.SaveScan(model.ScanSummary{ScanID: scan, StartedAt: t1.AddDate(0, 0, i), FinishedAt: t1.AddDate(0, 0, i)}); err != nil {
			t.Fatal(err)
		}
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	code, body := get(t, ts, "/api/issues/"+url.PathEscape(id))
	if code != 200 {
		t.Fatalf("issue page: %d %s", code, body)
	}
	var pg struct {
		ScoreHistory struct {
			Points []store.IssueScorePoint `json:"points"`
			Line   string                  `json:"line"`
		} `json:"score_history"`
	}
	if err := json.Unmarshal([]byte(body), &pg); err != nil {
		t.Fatal(err)
	}
	if len(pg.ScoreHistory.Points) != 2 || pg.ScoreHistory.Points[0].Score != 9.5 || !strings.Contains(pg.ScoreHistory.Line, "9.5 → 6.0") {
		t.Fatalf("score_history = %+v", pg.ScoreHistory)
	}

	code, body = get(t, ts, "/api/issues/"+url.PathEscape(id)+"/history?scores=1")
	var h struct {
		IssueID     string                        `json:"issue_id"`
		Transitions []store.PathIssueHistoryEntry `json:"transitions"`
		Scores      []store.IssueScorePoint       `json:"scores"`
		Line        string                        `json:"line"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &h) != nil || len(h.Scores) != 2 || h.Line == "" || h.Transitions == nil {
		t.Fatalf("history?scores=1: %d %s", code, body)
	}
	code, body = get(t, ts, "/api/issues/"+url.PathEscape(id)+"/history?scores=1&since=2026-10-21")
	if json.Unmarshal([]byte(body), &h) != nil || len(h.Scores) != 1 {
		t.Fatalf("history since: %d %s", code, body)
	}
	if code, _ = get(t, ts, "/api/issues/"+url.PathEscape(id)+"/history?scores=1&since=bogus"); code != 400 {
		t.Errorf("a bad since must be 400, got %d", code)
	}
	var plain []store.PathIssueHistoryEntry
	if code, body = get(t, ts, "/api/issues/"+url.PathEscape(id)+"/history"); code != 200 || json.Unmarshal([]byte(body), &plain) != nil {
		t.Fatalf("plain history stays an array: %d %s", code, body)
	}
}
