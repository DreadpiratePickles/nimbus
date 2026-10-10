package store

// Per-scan Issue trend (W6-VERIFY, r4 #12; bar: Wiz trend / MTTR over time). Each stored scan
// carries how many Issues it opened, resolved, reopened, saw regress after a verified fix, and
// how many were verified fixed since the previous scan, plus the open count and the verified
// share at the end of the scan. /api/scans, the dashboard trend panel and `scan --diff` read it.
//
// The counts are a snapshot diff: ApplyScan records every Issue's state before the scan's
// rebuilds, SaveScan compares with the states after them. Verifications (cloud-posture verify)
// between the previous scan and this one count as verified_fixed of this scan.

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// ScanTrend is one scan's Issue lifecycle counts.
type ScanTrend struct {
	New           int     `json:"new"`
	Resolved      int     `json:"resolved"`
	Reopened      int     `json:"reopened"`
	VerifiedFixed int     `json:"verified_fixed"`
	Regressed     int     `json:"regressed"`
	Open          int     `json:"open"`           // active Issues after the scan
	VerifiedShare float64 `json:"verified_share"` // ClosureMetrics.VerifiedShare after the scan
}

// Text is the one-line form `scan --diff` prints.
func (t *ScanTrend) Text() string {
	if t == nil {
		return "Issue trend unavailable"
	}
	return fmt.Sprintf("Issues this scan: %d new, %d resolved, %d reopened, %d verified fixed, %d regressed after verify; %d open, %.0f%% of closures verified",
		t.New, t.Resolved, t.Reopened, t.VerifiedFixed, t.Regressed, t.Open, t.VerifiedShare*100)
}

// ScanTrendRow is one stored scan with its trend (nil when the scan predates migration 11 or
// was saved by another writer).
type ScanTrendRow struct {
	ScanID     string     `json:"scan_id"`
	StartedAt  string     `json:"started_at"`
	FinishedAt string     `json:"finished_at"`
	Trend      *ScanTrend `json:"issue_trend"`
}

var trendColumns = []string{"issues_new", "issues_resolved", "issues_reopened", "issues_verified_fixed", "issues_regressed", "issues_open", "issues_verified_share"}

// migrateScanTrend is migration 11: the trend columns on scans (NULL = not recorded).
func migrateScanTrend(tx *sql.Tx) error {
	for i, c := range trendColumns {
		ok, err := hasColumn(tx, "scans", c)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		typ := "INTEGER"
		if i == len(trendColumns)-1 {
			typ = "REAL"
		}
		if _, err := tx.Exec("ALTER TABLE scans ADD COLUMN " + c + " " + typ); err != nil {
			return err
		}
	}
	return nil
}

type trendSnapshot struct {
	scanID string
	states map[string]string
	diff   *Diff
}

type trendState struct {
	mu   sync.Mutex
	snap *trendSnapshot
	// scores staged for scoreScan (score_history.go), written by SaveScan.
	scoreScan string
	scores    map[string]IssueScore
}

func (s *Store) issueStates() (map[string]string, error) {
	rows, err := s.db.Query("SELECT id, state FROM issues")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// snapshotForTrend is called by ApplyScan before the scan changes anything.
func (s *Store) snapshotForTrend(scanID string, d *Diff) {
	states, err := s.issueStates()
	if err != nil {
		return
	}
	s.trend.mu.Lock()
	s.trend.snap = &trendSnapshot{scanID: scanID, states: states, diff: d}
	s.trend.mu.Unlock()
}

func active(state string) bool {
	return model.IsActive(state) || state == model.StatePendingVerification
}

// recordTrend computes and stores the trend of scanID (SaveScan); no snapshot → nothing.
func (s *Store) recordTrend(scanID string, finished time.Time) error {
	s.trend.mu.Lock()
	snap := s.trend.snap
	if snap != nil && snap.scanID == scanID {
		s.trend.snap = nil
	}
	s.trend.mu.Unlock()
	if snap == nil || snap.scanID != scanID {
		return nil
	}
	now, err := s.issueStates()
	if err != nil {
		return err
	}
	t := &ScanTrend{}
	for id, st := range now {
		prior, had := snap.states[id]
		switch {
		case active(st):
			t.Open++
			switch {
			case !had:
				t.New++
			case prior == model.StateVerifiedFixed:
				t.Regressed++
			case prior == model.StateResolved:
				t.Reopened++
			}
		case st == model.StateResolved && had && active(prior):
			t.Resolved++
		}
	}
	prev, err := s.PreviousScanFinished(scanID)
	if err != nil {
		return err
	}
	vs, err := s.VerificationsBetween(prev, finished, VerifyFixed)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if !seen[v.IssueID] && (prev.IsZero() || v.At.After(prev)) {
			seen[v.IssueID] = true
			t.VerifiedFixed++
		}
	}
	// Regressions caught by `verify` between the scans (verified_fixed → reopened by a re-read)
	// count as regressed after verify of this scan; the scan itself sees an already-reopened
	// Issue (Verification 7 defect 8).
	if rs, err := s.VerificationsBetween(prev, finished, VerifyReopened); err == nil {
		counted := map[string]bool{}
		for id, st := range now {
			if active(st) && snap.states[id] == model.StateVerifiedFixed {
				counted[id] = true // already counted above
			}
		}
		for _, v := range rs {
			if counted[v.IssueID] || !(prev.IsZero() || v.At.After(prev)) {
				continue
			}
			var flag int
			if s.db.QueryRow("SELECT COALESCE(regressed_after_verify,0) FROM issues WHERE id = ?", v.IssueID).Scan(&flag) == nil && flag == 1 && active(now[v.IssueID]) {
				counted[v.IssueID] = true
				t.Regressed++
			}
		}
	}
	if m, err := s.ClosureMetrics(); err == nil {
		t.VerifiedShare = m.VerifiedShare
	}
	if _, err := s.db.Exec(`UPDATE scans SET issues_new = ?, issues_resolved = ?, issues_reopened = ?, issues_verified_fixed = ?,
	  issues_regressed = ?, issues_open = ?, issues_verified_share = ? WHERE id = ?`,
		t.New, t.Resolved, t.Reopened, t.VerifiedFixed, t.Regressed, t.Open, t.VerifiedShare, scanID); err != nil {
		return err
	}
	if snap.diff != nil {
		snap.diff.Issues = t
	}
	return nil
}

// ScanTrends lists stored scans newest first (limit <= 0 → 100) with their Issue trend.
func (s *Store) ScanTrends(limit int) ([]ScanTrendRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(started_at,''), COALESCE(finished_at,''), issues_new, issues_resolved, issues_reopened,
	  issues_verified_fixed, issues_regressed, issues_open, issues_verified_share FROM scans ORDER BY started_at DESC, finished_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanTrendRow{}
	for rows.Next() {
		var r ScanTrendRow
		var n, rs, ro, vf, rg, op sql.NullInt64
		var share sql.NullFloat64
		if err := rows.Scan(&r.ScanID, &r.StartedAt, &r.FinishedAt, &n, &rs, &ro, &vf, &rg, &op, &share); err != nil {
			return nil, err
		}
		if n.Valid {
			r.Trend = &ScanTrend{New: int(n.Int64), Resolved: int(rs.Int64), Reopened: int(ro.Int64), VerifiedFixed: int(vf.Int64),
				Regressed: int(rg.Int64), Open: int(op.Int64), VerifiedShare: share.Float64}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScanTrendOf is one scan's trend (nil when not recorded).
func (s *Store) ScanTrendOf(scanID string) (*ScanTrend, error) {
	rows, err := s.ScanTrends(1000)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ScanID == scanID {
			return r.Trend, nil
		}
	}
	return nil, nil
}
