package store

// Scan and finding history for the compliance evidence period (W7-VERIFY r5 #9): which scans
// finished inside an audit period, and when each finding was failing (finding_history:
// open / reopened start a failing interval, resolved ends it).

import (
	"strings"
	"time"
)

// FailInterval is one span a finding was failing; To is zero while it still is.
type FailInterval struct {
	From, To time.Time
}

// ScanTimes lists the finish times of the stored scans with from ≤ finished ≤ to, oldest first.
func (s *Store) ScanTimes(from, to time.Time) ([]time.Time, error) {
	rows, err := s.db.Query("SELECT finished_at FROM scans WHERE finished_at >= ? AND finished_at <= ? ORDER BY finished_at",
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var at string
		if err := rows.Scan(&at); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, at); err == nil {
			out = append(out, t.UTC())
		}
	}
	return out, rows.Err()
}

// FindingFailIntervals returns the failing intervals of the given findings (all findings with
// history when ids is empty).
func (s *Store) FindingFailIntervals(ids []string) (map[string][]FailInterval, error) {
	q := "SELECT fingerprint, state, at FROM finding_history"
	var args []any
	if len(ids) > 0 {
		q += " WHERE fingerprint IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	rows, err := s.db.Query(q+" ORDER BY fingerprint, at, rowid", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]FailInterval{}
	for rows.Next() {
		var fp, state, at string
		if err := rows.Scan(&fp, &state, &at); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			continue
		}
		iv := out[fp]
		open := len(iv) > 0 && iv[len(iv)-1].To.IsZero()
		switch state {
		case "open", "reopened":
			if !open {
				out[fp] = append(iv, FailInterval{From: t.UTC()})
			}
		case "resolved":
			if open {
				iv[len(iv)-1].To = t.UTC()
			}
		}
	}
	return out, rows.Err()
}
