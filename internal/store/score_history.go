package store

// Per-Issue score history (W7-VERIFY, r5 #11; bar: Upwind "Score Journey", Vanta's stated test
// cadence). Every saved scan records the score and band of each scored active Issue in
// issue_score_history; `issues trend --since 90d` aggregates a lookback window per scan, `issues
// show`, GET /api/issues/{id} (score_history) and the dashboard Issue pane print one Issue's
// journey as a text sparkline, and the history span states the cadence ("history since <date>,
// N scans").
//
// The scores are staged by the scan (StageIssueScores, after the Issue rebuild, where the CLI
// holds the ranked findings and the path analysis) and written by SaveScan at the scan's finish
// time, so a point is always tied to a stored scan.

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// issue_score_history already exists (migration 8) as the path-Issue score *change* log written
// by a trigger (old_score/old_band → new_score/new_band, scan_id NULL). Migration 12 adds the
// per-scan point columns: a point row is (issue_id, scan_id, at, score, band) with the change
// columns NULL; the change-log readers skip rows with a scan_id and the point readers read only
// them. One table keeps the id-key migration (idkey.go) covering both.
var scoreHistoryColumns = []struct{ name, ddl string }{
	{"scan_id", "ALTER TABLE issue_score_history ADD COLUMN scan_id TEXT"},
	{"score", "ALTER TABLE issue_score_history ADD COLUMN score REAL"},
	{"band", "ALTER TABLE issue_score_history ADD COLUMN band TEXT"},
}

// migrateIssueScoreHistory is migration 12: the point columns, a unique (issue_id, scan_id) index
// over point rows, and a backfill from the scored, scan-tied rows of path_issue_history (path
// Issues already carried their score at each transition).
func migrateIssueScoreHistory(tx *sql.Tx) error {
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS issue_score_history (issue_id TEXT NOT NULL, at TEXT NOT NULL,
	  old_score REAL, old_band TEXT, new_score REAL, new_band TEXT)`); err != nil {
		return err
	}
	for _, c := range scoreHistoryColumns {
		ok, err := hasColumn(tx, "issue_score_history", c.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_issue_score_points ON issue_score_history(issue_id, scan_id) WHERE scan_id IS NOT NULL;
	  CREATE INDEX IF NOT EXISTS idx_issue_score_history_at ON issue_score_history(at)`); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO issue_score_history (issue_id, scan_id, at, score, band)
	  SELECT issue_id, scan_id, MAX(at), score, NULL FROM path_issue_history
	  WHERE scan_id IS NOT NULL AND scan_id != '' AND score IS NOT NULL GROUP BY issue_id, scan_id`)
	return err
}

// IssueScore is one Issue's score and band at a scan.
type IssueScore struct {
	Score float64 `json:"score"`
	Band  string  `json:"band"`
}

// IssueScorePoint is one stored point of an Issue's score journey.
type IssueScorePoint struct {
	ScanID string    `json:"scan_id"`
	At     time.Time `json:"at"`
	Score  float64   `json:"score"`
	Band   string    `json:"band"`
}

// StageIssueScores holds the scores of scanID's active Issues until SaveScan(scanID) writes them.
// A later stage replaces an earlier one; SaveScan of another scan id writes nothing.
func (s *Store) StageIssueScores(scanID string, scores map[string]IssueScore) {
	s.trend.mu.Lock()
	defer s.trend.mu.Unlock()
	s.trend.scoreScan, s.trend.scores = scanID, scores
}

// recordScores writes the staged scores of scanID at the scan's finish time (SaveScan).
func (s *Store) recordScores(scanID string, at time.Time) error {
	s.trend.mu.Lock()
	scores := s.trend.scores
	if s.trend.scoreScan != scanID {
		scores = nil
	} else {
		s.trend.scoreScan, s.trend.scores = "", nil
	}
	s.trend.mu.Unlock()
	if len(scores) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT OR REPLACE INTO issue_score_history (issue_id, scan_id, at, score, band) VALUES (?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	ts := at.UTC().Format(time.RFC3339)
	for id, sc := range scores {
		band := sc.Band
		if band == "" {
			band = model.ScoreBand(sc.Score)
		}
		if _, err := stmt.Exec(id, scanID, ts, sc.Score, band); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// IssueScoreHistory is one Issue's score journey since `since` (zero: all), oldest first.
func (s *Store) IssueScoreHistory(issueID string, since time.Time) ([]IssueScorePoint, error) {
	q := "SELECT scan_id, at, COALESCE(score,0), COALESCE(band,'') FROM issue_score_history WHERE issue_id = ? AND scan_id IS NOT NULL"
	args := []any{issueID}
	if !since.IsZero() {
		q += " AND at >= ?"
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	rows, err := s.db.Query(q+" ORDER BY at, scan_id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IssueScorePoint
	for rows.Next() {
		var p IssueScorePoint
		var at string
		if err := rows.Scan(&p.ScanID, &at, &p.Score, &p.Band); err != nil {
			return nil, err
		}
		p.At, _ = time.Parse(time.RFC3339, at)
		if p.Band == "" {
			p.Band = model.ScoreBand(p.Score)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ScoreTrendRow is one scan in a lookback window: how many scored Issues were active and their
// score distribution.
type ScoreTrendRow struct {
	ScanID   string    `json:"scan_id"`
	At       time.Time `json:"at"`
	Issues   int       `json:"issues"`
	Critical int       `json:"critical"`
	High     int       `json:"high"`
	Medium   int       `json:"medium"`
	Low      int       `json:"low"`
	Max      float64   `json:"max_score"`
	Sum      float64   `json:"score_sum"`
}

// ScoreTrend aggregates issue_score_history per stored scan finished at or after since (zero:
// all), oldest first. A scan that recorded no score is a point with 0 Issues.
func (s *Store) ScoreTrend(since time.Time) ([]ScoreTrendRow, error) {
	q := "SELECT id, COALESCE(finished_at,'') FROM scans"
	var args []any
	if !since.IsZero() {
		q += " WHERE finished_at >= ?"
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	rows, err := s.db.Query(q+" ORDER BY finished_at, id", args...)
	if err != nil {
		return nil, err
	}
	var out []ScoreTrendRow
	idx := map[string]int{}
	for rows.Next() {
		var r ScoreTrendRow
		var at string
		if err := rows.Scan(&r.ScanID, &at); err != nil {
			rows.Close()
			return nil, err
		}
		r.At, _ = time.Parse(time.RFC3339, at)
		idx[r.ScanID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	q = "SELECT scan_id, COALESCE(score,0), COALESCE(band,'') FROM issue_score_history WHERE scan_id IS NOT NULL"
	if !since.IsZero() {
		q += " AND at >= ?"
	}
	pts, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer pts.Close()
	for pts.Next() {
		var scan, band string
		var score float64
		if err := pts.Scan(&scan, &score, &band); err != nil {
			return nil, err
		}
		i, ok := idx[scan]
		if !ok {
			continue
		}
		r := &out[i]
		r.Issues++
		r.Sum += score
		if score > r.Max {
			r.Max = score
		}
		if band == "" {
			band = model.ScoreBand(score)
		}
		switch strings.ToLower(band) {
		case "critical":
			r.Critical++
		case "high":
			r.High++
		case "medium":
			r.Medium++
		default:
			r.Low++
		}
	}
	for i := range out {
		out[i].Sum = float64(int(out[i].Sum*10+0.5)) / 10
	}
	return out, pts.Err()
}

// HistorySpan is how far back the stored scan history reaches: the cadence statement.
type HistorySpan struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Scans int       `json:"scans"`
	// MedianGap is the median time between consecutive scans (0 with fewer than 2).
	MedianGap time.Duration `json:"median_gap_ns"`
}

// ScoreHistorySpan reads the span of the stored scans.
func (s *Store) ScoreHistorySpan() (HistorySpan, error) {
	rows, err := s.db.Query("SELECT finished_at FROM scans WHERE finished_at IS NOT NULL AND finished_at != '' ORDER BY finished_at")
	if err != nil {
		return HistorySpan{}, err
	}
	defer rows.Close()
	var ts []time.Time
	for rows.Next() {
		var at string
		if err := rows.Scan(&at); err != nil {
			return HistorySpan{}, err
		}
		if t, err := time.Parse(time.RFC3339, at); err == nil {
			ts = append(ts, t.UTC())
		}
	}
	sp := HistorySpan{Scans: len(ts)}
	if len(ts) == 0 {
		return sp, rows.Err()
	}
	sp.First, sp.Last = ts[0], ts[len(ts)-1]
	if len(ts) > 1 {
		gaps := make([]time.Duration, 0, len(ts)-1)
		for i := 1; i < len(ts); i++ {
			gaps = append(gaps, ts[i].Sub(ts[i-1]))
		}
		sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
		sp.MedianGap = gaps[len(gaps)/2]
	}
	return sp, rows.Err()
}

// Text is the cadence statement: "history since 2026-07-01, 4 scans (median gap 1.0 days)".
func (sp HistorySpan) Text() string {
	if sp.Scans == 0 {
		return "no scan history yet (run cloud-posture scan or ingest)"
	}
	t := fmt.Sprintf("history since %s, %d scan%s", sp.First.Format("2006-01-02"), sp.Scans, pluralS(sp.Scans))
	if sp.MedianGap > 0 {
		t += fmt.Sprintf(" (median gap %s, last %s)", humanGap(sp.MedianGap), sp.Last.Format("2006-01-02"))
	}
	return t
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func humanGap(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%.0f hours", d.Hours())
	default:
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
}

var sparkRunes = []rune("▁▂▃▄▅▆▇█")

// Sparkline renders scores on the absolute 0–10 scale (so two Issues' lines compare).
func Sparkline(scores []float64) string {
	var b strings.Builder
	for _, s := range scores {
		i := int(s/10*float64(len(sparkRunes)-1) + 0.5)
		if i < 0 {
			i = 0
		}
		if i >= len(sparkRunes) {
			i = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[i])
	}
	return b.String()
}

// ScoreJourneyLine is the one-line score journey `issues show`, the Issue page and the dashboard
// print: "▇▅▅ 10.0 → 7.0 → 7.0 (3 scans since 2026-07-01; now 7.0 High)". Long journeys show
// the sparkline in full and only the first, the changes and the last score in numbers.
func ScoreJourneyLine(pts []IssueScorePoint) string {
	if len(pts) == 0 {
		return ""
	}
	scores := make([]float64, len(pts))
	for i, p := range pts {
		scores[i] = p.Score
	}
	var nums []string
	for i, p := range pts {
		if i == 0 || i == len(pts)-1 || p.Score != pts[i-1].Score {
			if len(nums) == 0 || i == len(pts)-1 || nums[len(nums)-1] != fmt.Sprintf("%.1f", p.Score) {
				nums = append(nums, fmt.Sprintf("%.1f", p.Score))
			}
		}
	}
	last := pts[len(pts)-1]
	return fmt.Sprintf("%s %s (%d scan%s since %s; now %.1f %s)", Sparkline(scores), strings.Join(nums, " → "), len(pts), pluralS(len(pts)),
		pts[0].At.UTC().Format("2006-01-02"), last.Score, last.Band)
}

// ParseSince reads a lookback: "90d", "12w", "6m" (months), "1y", a Go duration ("36h"), a date
// (YYYY-MM-DD), RFC 3339, or "all" / "" (zero time: everything).
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "all" {
		return time.Time{}, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339, strings.ToUpper(s)); err == nil {
		return t.UTC(), nil
	}
	if n := len(s); n >= 2 {
		var k int
		if _, err := fmt.Sscanf(s[:n-1], "%d", &k); err == nil && k > 0 && fmt.Sprint(k) == s[:n-1] {
			switch s[n-1] {
			case 'd':
				return now.AddDate(0, 0, -k), nil
			case 'w':
				return now.AddDate(0, 0, -7*k), nil
			case 'm':
				return now.AddDate(0, -k, 0), nil
			case 'y':
				return now.AddDate(-k, 0, 0), nil
			}
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("since %q: use Nd, Nw, Nm (months), Ny, a duration (36h), YYYY-MM-DD, RFC 3339 or all", s)
}
