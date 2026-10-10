package store

import (
	"fmt"
	"time"
)

const coverageSchema = `
CREATE TABLE IF NOT EXISTS coverage (
  scan_id TEXT NOT NULL,
  provider TEXT,
  account TEXT,
  api TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','denied','skipped','error','timeout')),
  reason TEXT,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_coverage_scan ON coverage(scan_id, provider, account);
`

// Coverage statuses.
const (
	CoverageOK      = "ok"
	CoverageDenied  = "denied"
	CoverageSkipped = "skipped"
	CoverageError   = "error"
	CoverageTimeout = "timeout"
)

// CoverageEntry is one API call, collector or tool run and whether it actually ran.
type CoverageEntry struct {
	ScanID   string    `json:"scan_id"`
	Provider string    `json:"provider"`
	Account  string    `json:"account"`
	API      string    `json:"api"`
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

// CollectErrorLike is the hook for collector errors (Track C's core.CollectError):
// anything that can report provider, account, API, a classified reason
// (access_denied, timeout, canceled, rate_limited, not_found, unsupported_provider,
// error) and the message can be recorded with RecordCollectErrors.
type CollectErrorLike interface {
	CoverageFields() (provider, account, api, reason, message string)
}

// CoverageStatusForReason maps a collector error reason to a coverage status.
func CoverageStatusForReason(reason string) string {
	switch reason {
	case "access_denied":
		return CoverageDenied
	case "timeout", "canceled":
		return CoverageTimeout
	case "unsupported_provider", "not_installed", "skipped":
		return CoverageSkipped
	}
	return CoverageError
}

func validCoverageStatus(s string) bool {
	switch s {
	case CoverageOK, CoverageDenied, CoverageSkipped, CoverageError, CoverageTimeout:
		return true
	}
	return false
}

// RecordCoverage appends coverage rows for a scan (one transaction; any invalid status
// rejects the whole batch).
func (s *Store) RecordCoverage(scanID string, at time.Time, entries []CoverageEntry) error {
	for _, e := range entries {
		if !validCoverageStatus(e.Status) {
			return fmt.Errorf("coverage %s/%s %s: invalid status %q", e.Provider, e.Account, e.API, e.Status)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	atS := at.UTC().Format(time.RFC3339)
	for _, e := range entries {
		ts := atS
		if !e.At.IsZero() {
			ts = e.At.UTC().Format(time.RFC3339)
		}
		if _, err := tx.Exec("INSERT INTO coverage (scan_id, provider, account, api, status, reason, at) VALUES (?,?,?,?,?,?,?)",
			scanID, e.Provider, e.Account, e.API, e.Status, e.Reason, ts); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RecordCollectErrors records collector errors through the CollectErrorLike hook.
func (s *Store) RecordCollectErrors(scanID string, at time.Time, errs []CollectErrorLike) error {
	entries := make([]CoverageEntry, 0, len(errs))
	for _, e := range errs {
		p, a, api, reason, msg := e.CoverageFields()
		r := reason
		if msg != "" {
			r = reason + ": " + msg
		}
		entries = append(entries, CoverageEntry{Provider: p, Account: a, API: api, Status: CoverageStatusForReason(reason), Reason: r})
	}
	return s.RecordCoverage(scanID, at, entries)
}

// Coverage returns the coverage rows of one scan ("" = latest scan with coverage).
func (s *Store) Coverage(scanID string) ([]CoverageEntry, error) {
	if scanID == "" {
		_ = s.db.QueryRow("SELECT scan_id FROM coverage ORDER BY at DESC, rowid DESC LIMIT 1").Scan(&scanID)
	}
	rows, err := s.db.Query("SELECT scan_id, COALESCE(provider,''), COALESCE(account,''), api, status, COALESCE(reason,''), at FROM coverage WHERE scan_id = ? ORDER BY provider, account, api", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CoverageEntry
	for rows.Next() {
		var e CoverageEntry
		var at string
		if err := rows.Scan(&e.ScanID, &e.Provider, &e.Account, &e.API, &e.Status, &e.Reason, &at); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, e)
	}
	return out, rows.Err()
}
