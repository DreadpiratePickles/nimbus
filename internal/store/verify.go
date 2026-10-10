package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verified remediation (plan v3 RM4 / IW2, `cloud-posture verify`): an Issue is closed as
// verified_fixed only after a targeted re-collect plus re-traversal confirmed it gone N reads
// in a row. Every verification run (fixed, still open, reopened) is a row of
// issue_verifications; a verified path Issue also gets a path_issue_history transition.

// StateVerifiedFixed is the Issue state after a confirmed fix (model.StateVerifiedFixed); it is
// not active (model.IsActive) and survives rebuilds until the problem reappears.
const StateVerifiedFixed = model.StateVerifiedFixed

// Verification results.
const (
	VerifyFixed    = StateVerifiedFixed // N consecutive confirmations: the Issue is verified_fixed
	VerifyOpen     = "open"             // still observed (or not confirmed inside the window): unchanged
	VerifyReopened = model.StateReopened
	// VerifyUnverified: the read held no positive evidence about the Issue (a --from-file export
	// that never mentions its resource or never evaluates its check): nothing changes on the
	// Issue or its ticket (Verification 5 V1/C7).
	VerifyUnverified = "unverified"
)

const verificationSchema = `
CREATE TABLE IF NOT EXISTS issue_verifications (
  issue_id TEXT NOT NULL,
  at TEXT NOT NULL,
  result TEXT NOT NULL,
  verified_by TEXT,
  reads INTEGER NOT NULL DEFAULT 0,
  confirmations INTEGER NOT NULL DEFAULT 0,
  required INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  evidence TEXT              -- JSON array: one line per read
);
CREATE INDEX IF NOT EXISTS idx_issue_verifications ON issue_verifications(issue_id, at);
CREATE INDEX IF NOT EXISTS idx_issue_verifications_at ON issue_verifications(at, result);
CREATE TABLE IF NOT EXISTS issue_score_history (
  issue_id TEXT NOT NULL,
  at TEXT NOT NULL,          -- the rebuild's last_seen
  old_score REAL,
  old_band TEXT,
  new_score REAL,
  new_band TEXT
);
CREATE INDEX IF NOT EXISTS idx_issue_score_history ON issue_score_history(issue_id, at);
CREATE TRIGGER IF NOT EXISTS trg_path_issue_score_history AFTER UPDATE OF score, band ON issues
WHEN NEW.kind = 'path' AND (OLD.score IS NOT NEW.score OR COALESCE(OLD.band,'') <> COALESCE(NEW.band,''))
BEGIN
  INSERT INTO issue_score_history (issue_id, at, old_score, old_band, new_score, new_band)
  VALUES (NEW.id, COALESCE(NEW.last_seen, strftime('%Y-%m-%dT%H:%M:%SZ','now')), OLD.score, OLD.band, NEW.score, NEW.band);
END;
`

// migrateIssueVerification is migration 8: verified_at / verified_by on issues (present since
// migration 6; added here when missing), the verification history, and the path-Issue
// score/band change history (a trigger, so the path-Issue rebuild records every rescore
// without knowing about it; `scan --diff` prints "10.0 CRITICAL → 7.0 HIGH" from it).
func migrateIssueVerification(tx *sql.Tx) error {
	for _, c := range []struct{ name, ddl string }{
		{"verified_at", "ALTER TABLE issues ADD COLUMN verified_at TEXT"},
		{"verified_by", "ALTER TABLE issues ADD COLUMN verified_by TEXT"},
	} {
		ok, err := hasColumn(tx, "issues", c.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(verificationSchema)
	return err
}

// Verification is one `verify` run on one Issue.
type Verification struct {
	IssueID       string    `json:"issue_id"`
	Result        string    `json:"result"` // VerifyFixed | VerifyOpen | VerifyReopened | VerifyUnverified
	At            time.Time `json:"at"`
	VerifiedBy    string    `json:"verified_by,omitempty"` // rescan | file:<name>
	Reads         int       `json:"reads"`
	Confirmations int       `json:"confirmations"` // consecutive confirmations at the end of the run
	Required      int       `json:"required"`
	Reason        string    `json:"reason,omitempty"`
	Evidence      []string  `json:"evidence,omitempty"`
}

// RecordVerification appends v to the history and applies its transition to that one Issue:
// VerifyFixed sets state verified_fixed, verified_at, verified_by (and resolved_at when
// unset); VerifyReopened sets state reopened; VerifyOpen and VerifyUnverified change nothing on the Issue. No other
// Issue row is read or written. ErrIssueNotFound for an unknown id.
func (s *Store) RecordVerification(v Verification) error {
	at := v.At.UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind, state string
	var score sql.NullFloat64
	var key sql.NullString
	if err := tx.QueryRow("SELECT kind, state, score, secondary_key FROM issues WHERE id = ?", v.IssueID).Scan(&kind, &state, &score, &key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrIssueNotFound, v.IssueID)
		}
		return err
	}
	switch v.Result {
	case VerifyFixed, VerifyReopened, VerifyOpen, VerifyUnverified:
	default:
		return fmt.Errorf("store: unknown verification result %q", v.Result)
	}
	// A suppression is an accepted-risk decision with its own expiry: verify records its run but
	// never removes it (Verification 5 C8).
	transition := (v.Result == VerifyFixed || v.Result == VerifyReopened) && state != model.StateSuppressed
	regressed := v.Result == VerifyReopened && state == StateVerifiedFixed
	if transition {
		switch v.Result {
		case VerifyFixed:
			if _, err := tx.Exec(`UPDATE issues SET state = ?, verified_at = ?, verified_by = NULLIF(?,''), resolved_at = COALESCE(resolved_at, ?),
			  regressed_after_verify = 0, pending_at = NULL, pending_by = NULL WHERE id = ?`,
				StateVerifiedFixed, at, v.VerifiedBy, at, v.IssueID); err != nil {
				return err
			}
		case VerifyReopened:
			// A verified fix observed again is a regression after verify (Verification 7 defect 8),
			// exactly as when a scan reopens it.
			if _, err := tx.Exec(`UPDATE issues SET state = ?, resolved_at = NULL, pending_at = NULL, pending_by = NULL,
			  regressed_after_verify = CASE WHEN ? THEN 1 ELSE COALESCE(regressed_after_verify,0) END WHERE id = ?`,
				model.StateReopened, regressed, v.IssueID); err != nil {
				return err
			}
		}
	}
	// Every kind records the Issue-level transition (governance metrics read it).
	if transition {
		_ = kind
		if _, err := tx.Exec("INSERT INTO path_issue_history (issue_id, state, at, scan_id, score, secondary_key, regressed_after_verify) VALUES (?,?,?,NULL,?,?,?)",
			v.IssueID, v.Result, at, score, key, regressed); err != nil {
			return err
		}
	}
	ev, _ := json.Marshal(v.Evidence)
	if _, err := tx.Exec(`INSERT INTO issue_verifications (issue_id, at, result, verified_by, reads, confirmations, required, reason, evidence)
	  VALUES (?,?,?,?,?,?,?,?,?)`, v.IssueID, at, v.Result, v.VerifiedBy, v.Reads, v.Confirmations, v.Required, v.Reason, string(ev)); err != nil {
		return err
	}
	return tx.Commit()
}

func scanVerifications(rows *sql.Rows) ([]Verification, error) {
	defer rows.Close()
	var out []Verification
	for rows.Next() {
		var v Verification
		var at string
		var by, reason, ev sql.NullString
		if err := rows.Scan(&v.IssueID, &at, &v.Result, &by, &v.Reads, &v.Confirmations, &v.Required, &reason, &ev); err != nil {
			return nil, err
		}
		v.At, _ = time.Parse(time.RFC3339, at)
		v.VerifiedBy, v.Reason = by.String, reason.String
		if ev.String != "" {
			_ = json.Unmarshal([]byte(ev.String), &v.Evidence)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

const verificationCols = "issue_id, at, result, verified_by, reads, confirmations, required, reason, evidence"

// Verifications lists one Issue's verification runs, oldest first.
func (s *Store) Verifications(issueID string) ([]Verification, error) {
	rows, err := s.db.Query("SELECT "+verificationCols+" FROM issue_verifications WHERE issue_id = ? ORDER BY at, rowid", issueID)
	if err != nil {
		return nil, err
	}
	return scanVerifications(rows)
}

// VerificationsBetween lists runs with from ≤ at ≤ to (oldest first; second precision, so a
// run in the same second as from is included), optionally only the given results.
func (s *Store) VerificationsBetween(from, to time.Time, results ...string) ([]Verification, error) {
	q := "SELECT " + verificationCols + " FROM issue_verifications WHERE at >= ? AND at <= ?"
	args := []any{from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)}
	if len(results) > 0 {
		q += " AND result IN (" + strings.TrimSuffix(strings.Repeat("?,", len(results)), ",") + ")"
		for _, r := range results {
			args = append(args, r)
		}
	}
	rows, err := s.db.Query(q+" ORDER BY at, rowid", args...)
	if err != nil {
		return nil, err
	}
	return scanVerifications(rows)
}

// PreviousScanFinished is the finish time of the latest stored scan other than scanID (zero
// when there is none): the start of the window `scan --diff` reports verifications for.
func (s *Store) PreviousScanFinished(scanID string) (time.Time, error) {
	var at sql.NullString
	if err := s.db.QueryRow("SELECT MAX(finished_at) FROM scans WHERE id <> ?", scanID).Scan(&at); err != nil {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339, at.String)
	return t, nil
}

// ScoreChange is one path Issue's score / band change in a rebuild.
type ScoreChange struct {
	IssueID  string    `json:"issue_id"`
	At       time.Time `json:"at"`
	OldScore float64   `json:"old_score"`
	OldBand  string    `json:"old_band"`
	NewScore float64   `json:"new_score"`
	NewBand  string    `json:"new_band"`
}

// LatestPathScoreChanges returns, per path Issue, the score / band change made by the rebuild
// that last saw it (history rows stamped with the Issue's current last_seen). Issues whose
// latest rebuild left the score alone are absent. Several changes in one rebuild collapse to
// first-old → last-new; a change back to the same score and band is dropped.
func (s *Store) LatestPathScoreChanges() (map[string]ScoreChange, error) {
	rows, err := s.db.Query(`SELECT h.issue_id, h.at, h.old_score, COALESCE(h.old_band,''), h.new_score, COALESCE(h.new_band,'')
	  FROM issue_score_history h JOIN issues i ON i.id = h.issue_id AND h.at = i.last_seen
	  WHERE i.kind = 'path' AND h.scan_id IS NULL ORDER BY h.rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ScoreChange{}
	for rows.Next() {
		var c ScoreChange
		var at string
		var oldS, newS sql.NullFloat64
		if err := rows.Scan(&c.IssueID, &at, &oldS, &c.OldBand, &newS, &c.NewBand); err != nil {
			return nil, err
		}
		c.At, _ = time.Parse(time.RFC3339, at)
		c.OldScore, c.NewScore = oldS.Float64, newS.Float64
		if prev, ok := out[c.IssueID]; ok {
			c.OldScore, c.OldBand = prev.OldScore, prev.OldBand
		}
		out[c.IssueID] = c
	}
	for id, c := range out {
		if c.OldScore == c.NewScore && c.OldBand == c.NewBand {
			delete(out, id)
		}
	}
	return out, rows.Err()
}
