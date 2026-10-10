package store

import (
	"fmt"
	"strings"
	"time"
)

// unassignedOwner is the owner filter value for Issues without an owner (governance.Unassigned).
const unassignedOwner = "(unassigned)"

// IssueGovernance is one Issue's resolved governance assignment (migration 7 columns).
type IssueGovernance struct {
	ID         string
	Owner      string
	Source     string // rule | tag | codeowners | account | default | unassigned
	RuleID     string
	Why        string
	SLADays    int
	DueAt      *time.Time // nil = no SLA
	GraceUntil *time.Time
}

// SetIssueGovernance writes the assignments in one transaction, replacing whatever an
// earlier resolution stored (rules may have changed). Unknown ids are ignored: the Issue
// set is owned by the rebuilds.
func (s *Store) SetIssueGovernance(rows []IssueGovernance) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	up, err := tx.Prepare(`UPDATE issues SET owner = NULLIF(?,''), owner_source = NULLIF(?,''), owner_rule = NULLIF(?,''), owner_why = NULLIF(?,''),
	  sla_days = ?, due_at = ?, grace_until = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer up.Close()
	for _, r := range rows {
		if _, err := up.Exec(strings.TrimSpace(r.Owner), r.Source, r.RuleID, r.Why, r.SLADays, nullTime(r.DueAt), nullTime(r.GraceUntil), r.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// IssueTicket is the one external ticket of an Issue.
type IssueTicket struct {
	Sink  string // jira | github
	Key   string // SEC-12, or the GitHub issue number
	URL   string
	State string // open | closed
}

// SetIssueTicket records (or updates) the ticket of one Issue; ErrIssueNotFound for an
// unknown id.
func (s *Store) SetIssueTicket(id string, t IssueTicket) error {
	res, err := s.db.Exec(`UPDATE issues SET ticket_sink = NULLIF(?,''), ticket_key = NULLIF(?,''), ticket_url = NULLIF(?,''), ticket_state = NULLIF(?,'') WHERE id = ?`,
		t.Sink, t.Key, t.URL, t.State, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrIssueNotFound, id)
	}
	return nil
}
