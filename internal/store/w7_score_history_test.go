package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY r5 #11 (bar: Upwind Score Journey, Vanta hourly cadence): every saved scan records
// each scored active Issue's score and band in issue_score_history(issue_id, scan_id, at, score,
// band); a lookback window aggregates it per scan, one Issue's journey reads it back, and the
// history span states the cadence.

func openTempPath(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.db")
	st, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, p
}

func saveScanAt(t *testing.T, st *Store, id string, at time.Time, scores map[string]IssueScore) {
	t.Helper()
	st.StageIssueScores(id, scores)
	if err := st.SaveScan(model.ScanSummary{ScanID: id, StartedAt: at.Add(-time.Minute), FinishedAt: at}); err != nil {
		t.Fatal(err)
	}
}

func TestIssueScoreHistoryMigrationAndJourney(t *testing.T) {
	st, _ := openTempPath(t)
	if !st.TableExists("issue_score_history") {
		t.Fatal("migration did not create issue_score_history")
	}
	for _, c := range []string{"issue_id", "scan_id", "at", "score", "band"} {
		var n int
		if err := st.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('issue_score_history') WHERE name = ?", c).Scan(&n); err != nil || n != 1 {
			t.Errorf("issue_score_history lacks %s (%v)", c, err)
		}
	}
	day := func(d int) time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, d) }
	saveScanAt(t, st, "s1", day(0), map[string]IssueScore{"p1": {Score: 10, Band: "Critical"}, "f1": {Score: 6.4, Band: "Medium"}})
	saveScanAt(t, st, "s2", day(40), map[string]IssueScore{"p1": {Score: 7, Band: "High"}, "f1": {Score: 6.4, Band: "Medium"}, "f2": {Score: 9.1}})
	saveScanAt(t, st, "s3", day(80), map[string]IssueScore{"p1": {Score: 7, Band: "High"}})
	// A scan with nothing staged records nothing (and does not reuse the last stage).
	saveScanAt(t, st, "s4", day(81), nil)

	j, err := st.IssueScoreHistory("p1", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(j) != 3 || j[0].Score != 10 || j[1].Score != 7 || j[2].ScanID != "s3" || j[0].Band != "Critical" {
		t.Fatalf("p1 journey = %+v", j)
	}
	if f2, _ := st.IssueScoreHistory("f2", time.Time{}); len(f2) != 1 || f2[0].Band != "Critical" {
		t.Errorf("an empty band is derived from the score: %+v", f2)
	}
	if recent, _ := st.IssueScoreHistory("p1", day(30)); len(recent) != 2 {
		t.Errorf("since filter: %+v", recent)
	}
	if line := ScoreJourneyLine(j); line == "" || !containsAll(line, "10.0", "7.0", "3 scans", "2026-07-01") {
		t.Errorf("journey line = %q", line)
	}

	rows, err := st.ScoreTrend(day(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].ScanID != "s2" || rows[0].Issues != 3 || rows[0].Critical != 1 || rows[0].Max != 9.1 {
		t.Fatalf("trend since day 30 = %+v", rows)
	}
	if rows[1].ScanID != "s3" || rows[1].Issues != 1 || rows[1].Sum != 7 {
		t.Errorf("s3 row = %+v", rows[1])
	}
	if rows[2].ScanID != "s4" || rows[2].Issues != 0 {
		t.Errorf("a scan without scores is still a point (0 Issues): %+v", rows[2])
	}
	sp, err := st.ScoreHistorySpan()
	if err != nil || sp.Scans != 4 || !sp.First.Equal(day(0)) || !sp.Last.Equal(day(81)) {
		t.Fatalf("span = %+v %v", sp, err)
	}
	if txt := sp.Text(); !containsAll(txt, "history since 2026-07-01", "4 scans") {
		t.Errorf("cadence = %q", txt)
	}
}

// The per-scan points never read as path score changes (LatestPathScoreChanges feeds the
// "10.0 CRITICAL → 7.0 HIGH" line of scan --diff).
func TestScorePointsAreNotScoreChanges(t *testing.T) {
	st, _ := openTempPath(t)
	at := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.db.Exec(`INSERT INTO issues (id, canonical_id, resource_id, severity, state, finding_ids, sources, confidence, kind, last_seen, score, band)
	  VALUES ('p1', 'PATH', 'r', 'CRITICAL', 'open', '[]', '[]', 1, 'path', ?, 10, 'Critical')`, at.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`UPDATE issues SET score = 7, band = 'High' WHERE id = 'p1'`); err != nil {
		t.Fatal(err)
	}
	saveScanAt(t, st, "s1", at, map[string]IssueScore{"p1": {Score: 7, Band: "High"}})
	ch, err := st.LatestPathScoreChanges()
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := ch["p1"]; !ok || c.OldScore != 10 || c.NewScore != 7 || c.NewBand != "High" {
		t.Fatalf("score change = %+v (ok %v)", c, ok)
	}
}

func TestIssueScoreHistoryBackfillsPathHistory(t *testing.T) {
	st, p := openTempPath(t)
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	if _, err := st.db.Exec(`DELETE FROM issue_score_history; DELETE FROM schema_migrations WHERE version >= 12;
	  INSERT INTO path_issue_history (issue_id, state, at, scan_id, score) VALUES ('px', 'open', ?, 'old-scan', 8.5), ('px', 'resolved', ?, NULL, NULL)`, at, at); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	j, err := st2.IssueScoreHistory("px", time.Time{})
	if err != nil || len(j) != 1 || j[0].Score != 8.5 || j[0].ScanID != "old-scan" || j[0].Band != "High" {
		t.Fatalf("backfilled journey = %+v %v", j, err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
