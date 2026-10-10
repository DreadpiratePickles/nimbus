package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verified closure that survives (W5-ISSUES item 1, r3 #3, Verification 5 C2).
//
// State machine applied by RebuildIssuesWithVerdict and RebuildPathIssuesScoped:
//
//	prior state            problem observed               problem absent
//	(new)                  open                           -
//	open / reopened        unchanged                      resolved
//	pending_verification   open (the fix did not take)    resolved
//	verified_fixed         reopened + regressed flag      verified_fixed (kept)
//	resolved               reopened                       resolved
//	suppressed             suppressed (reopened after     resolved
//	                       expires_at)
//
// `verify` moves open / reopened / pending_verification / resolved to verified_fixed
// (RecordVerification); `issues mark-pending` (or a fix-PR merge) moves an active Issue to
// pending_verification (MarkPendingVerification). A suppressed Issue keeps its suppression
// whatever verify concludes.

func migrateIssueClosure(tx *sql.Tx) error {
	for _, c := range []struct{ table, name, ddl string }{
		{"issues", "pending_at", "ALTER TABLE issues ADD COLUMN pending_at TEXT"},
		{"issues", "pending_by", "ALTER TABLE issues ADD COLUMN pending_by TEXT"},
		{"issues", "regressed_after_verify", "ALTER TABLE issues ADD COLUMN regressed_after_verify INTEGER NOT NULL DEFAULT 0"},
		{"path_issue_history", "regressed_after_verify", "ALTER TABLE path_issue_history ADD COLUMN regressed_after_verify INTEGER NOT NULL DEFAULT 0"},
		{"path_issue_history", "detail", "ALTER TABLE path_issue_history ADD COLUMN detail TEXT"},
	} {
		ok, err := hasColumn(tx, c.table, c.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// nextState is the rebuild transition for one stored Issue (see the table above). present is
// whether the rebuild observed the problem; expiresAt is the suppression expiry. It returns the
// new state, whether this is a regression after verification, and whether the state changed.
func nextState(prior string, present bool, expiresAt string, now time.Time) (state string, regressed bool) {
	if present {
		switch prior {
		case model.StateResolved:
			return model.StateReopened, false
		case model.StateVerifiedFixed:
			return model.StateReopened, true
		case model.StatePendingVerification:
			return model.StateOpen, false
		case model.StateSuppressed:
			if suppressionExpired(expiresAt, now) {
				return model.StateReopened, false
			}
			return prior, false
		case "":
			return model.StateOpen, false
		}
		return prior, false
	}
	switch prior {
	case model.StateVerifiedFixed, model.StateResolved:
		return prior, false
	}
	return model.StateResolved, false
}

// ErrNotPendable is returned by MarkPendingVerification for an Issue that is not active.
var ErrNotPendable = errors.New("store: only an open or reopened Issue can be marked pending verification")

// MaxPendingBy bounds the free-text source of a pending mark (a PR URL, "cli:alice").
const MaxPendingBy = 512

// MarkPendingVerification moves an open / reopened Issue to pending_verification: a fix was
// merged or applied (by names it: "pr:<url>", "cli", "ticket:<key>") and the next scan or
// `verify` settles it. The transition is recorded in path_issue_history (any kind).
func (s *Store) MarkPendingVerification(id, by string, now time.Time) error {
	by = strings.TrimSpace(by)
	if len(by) > MaxPendingBy {
		return fmt.Errorf("store: pending source longer than %d bytes", MaxPendingBy)
	}
	at := now.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	var score sql.NullFloat64
	var key sql.NullString
	if err := tx.QueryRow("SELECT state, score, secondary_key FROM issues WHERE id = ?", id).Scan(&state, &score, &key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrIssueNotFound, id)
		}
		return err
	}
	if state == model.StatePendingVerification {
		return nil
	}
	if !model.IsActive(state) {
		return fmt.Errorf("%w (state %s)", ErrNotPendable, state)
	}
	if _, err := tx.Exec("UPDATE issues SET state = ?, pending_at = ?, pending_by = NULLIF(?,'') WHERE id = ?", model.StatePendingVerification, at, by, id); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key, detail) VALUES (?,?,?,NULL,?,?,NULLIF(?,''))",
		id, model.StatePendingVerification, at, score, key, by); err != nil {
		return err
	}
	return tx.Commit()
}

// ClosureMetrics are the verified-vs-resolved numbers `issues metrics` reports.
type ClosureMetrics struct {
	VerifiedFixed       int `json:"verified_fixed"`       // Issues currently verified_fixed
	Resolved            int `json:"resolved"`             // Issues currently resolved by absence (not verified)
	PendingVerification int `json:"pending_verification"` // Issues awaiting verification
	// RegressionsAfterVerify counts reopen transitions of an Issue that had been verified_fixed
	// (history rows); RegressedOpen the Issues currently open with the flag.
	RegressionsAfterVerify int `json:"regressions_after_verify"`
	RegressedOpen          int `json:"regressed_open"`
	// VerifiedShare is VerifiedFixed / (VerifiedFixed + Resolved); 0 when both are 0.
	VerifiedShare float64 `json:"verified_share"`
}

// ClosureMetrics counts closure states over every Issue kind.
func (s *Store) ClosureMetrics() (*ClosureMetrics, error) {
	m := &ClosureMetrics{}
	rows, err := s.db.Query("SELECT state, COALESCE(regressed_after_verify,0) FROM issues")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var state string
		var reg bool
		if err := rows.Scan(&state, &reg); err != nil {
			rows.Close()
			return nil, err
		}
		switch state {
		case model.StateVerifiedFixed:
			m.VerifiedFixed++
		case model.StateResolved:
			m.Resolved++
		case model.StatePendingVerification:
			m.PendingVerification++
		}
		if reg && model.IsActive(state) {
			m.RegressedOpen++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM path_issue_history WHERE regressed_after_verify = 1").Scan(&m.RegressionsAfterVerify); err != nil {
		return nil, err
	}
	if n := m.VerifiedFixed + m.Resolved; n > 0 {
		m.VerifiedShare = float64(m.VerifiedFixed) / float64(n)
	}
	return m, nil
}
