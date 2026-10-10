package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	_ "modernc.org/sqlite"
)

// buildV6 is buildV5 upgraded by migrations 1..6 only: a database exactly as the previous
// release left it.
func buildV6(t *testing.T) string {
	t.Helper()
	path := buildV5(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, m := range migrations {
		if m.Version > 6 {
			break
		}
		if _, err := applyMigration(db, m); err != nil {
			t.Fatalf("migration %d: %v", m.Version, err)
		}
	}
	var v int
	db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&v)
	if v != 6 {
		t.Fatalf("v6 fixture at version %d", v)
	}
	return path
}

// Integration pass 4 item 1: migration 7 adds the governance and ticket columns to issues
// on a v6 database without changing any existing row.
func TestMigration7OnV6Database(t *testing.T) {
	path := buildV6(t)
	raw, _ := sql.Open("sqlite", path)
	nBefore, sumBefore := issuesDigest(t, raw)
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open v6 db: %v", err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() || v < 7 {
		t.Fatalf("schema version %d (latest %d), want ≥ 7", v, LatestSchemaVersion())
	}
	if n, sum := issuesDigest(t, st.DB()); n != nBefore || sum != sumBefore {
		t.Fatalf("issues changed by migration 7")
	}
	assertV7Shape(t, st)
	// Existing rows have no governance yet: every new column is NULL / empty.
	is, err := st.Issues(IssueFilter{})
	if err != nil || len(is) != 3 {
		t.Fatalf("issues: %d %v", len(is), err)
	}
	for _, i := range is {
		if i.Owner != "" || i.OwnerSource != "" || i.DueAt != nil || i.GraceUntil != nil || i.TicketKey != "" || i.Overdue {
			t.Errorf("%s: governance fields set on a migrated row: %+v", i.ID, i)
		}
	}
	// Re-applying migration 7 (crash before it was recorded) is a no-op.
	st.DB().Exec("DELETE FROM schema_migrations WHERE version = 7")
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-apply migration 7: %v", err)
	}
	defer st2.Close()
	assertV7Shape(t, st2)
}

func TestMigration7OnFreshDatabase(t *testing.T) { assertV7Shape(t, openTemp(t)) }

func assertV7Shape(t *testing.T, st *Store) {
	t.Helper()
	tx, err := st.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, c := range []string{"owner", "owner_source", "owner_rule", "due_at", "grace_until", "owner_why", "sla_days",
		"ticket_sink", "ticket_key", "ticket_url", "ticket_state"} {
		if ok, err := hasColumn(tx, "issues", c); err != nil || !ok {
			t.Errorf("issues.%s missing (%v)", c, err)
		}
	}
}

func govIssues(t *testing.T) (*Store, []model.Issue) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, err = st.DB().Exec(`INSERT INTO issues (id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, finding_ids, sources, confidence, kind)
	  VALUES ('i1','S3_PUBLIC','b1','aws','1','CRITICAL','open','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','[]','[]',0.7,'single'),
	         ('i2','S3_PUBLIC','b2','aws','1','HIGH','reopened','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','[]','[]',0.7,'single'),
	         ('i3','S3_PUBLIC','b3','aws','1','HIGH','resolved','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','[]','[]',0.7,'single')`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.DB().Exec(`INSERT INTO issues (id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, finding_ids, sources, confidence, kind, reason, expires_at)
	  VALUES ('i4','S3_PUBLIC','b4','aws','1','HIGH','suppressed','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','[]','[]',0.7,'single','waf','2099-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	is, _ := st.Issues(IssueFilter{})
	return st, is
}

// Governance columns round-trip, re-resolution overwrites, and the overdue / owner filters
// select open (not suppressed, not resolved) Issues past due_at.
func TestIssueGovernancePersistAndFilter(t *testing.T) {
	st, _ := govIssues(t)
	due := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	grace := due.Add(72 * time.Hour)
	later := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	var rows []IssueGovernance
	for _, id := range []string{"i1", "i2", "i3", "i4"} {
		rows = append(rows, IssueGovernance{ID: id, Owner: "@acme/platform", Source: "codeowners", RuleID: "terraform", Why: "rule terraform: CODEOWNERS line 2",
			SLADays: 7, DueAt: &due, GraceUntil: &grace})
	}
	rows[1].Owner, rows[1].DueAt = "secops@example.com", &later
	if err := st.SetIssueGovernance(rows); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	all, err := st.Issues(IssueFilter{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Issue{}
	for _, i := range all {
		by[i.ID] = i
	}
	i1 := by["i1"]
	if i1.Owner != "@acme/platform" || i1.OwnerSource != "codeowners" || i1.OwnerRule != "terraform" || i1.OwnerWhy == "" || i1.SLADays != 7 ||
		i1.DueAt == nil || !i1.DueAt.Equal(due) || i1.GraceUntil == nil || !i1.GraceUntil.Equal(grace) || !i1.Overdue {
		t.Errorf("i1 = %+v", i1)
	}
	if by["i2"].Overdue || by["i3"].Overdue || by["i4"].Overdue {
		t.Errorf("only open Issues past due are overdue: i2 %v (due later) i3 %v (resolved) i4 %v (suppressed)", by["i2"].Overdue, by["i3"].Overdue, by["i4"].Overdue)
	}
	od, _ := st.Issues(IssueFilter{Now: now, OverdueOnly: true})
	if len(od) != 1 || od[0].ID != "i1" {
		t.Errorf("overdue filter: %v", ids(od))
	}
	ow, _ := st.Issues(IssueFilter{Owner: "SECOPS@example.com"})
	if len(ow) != 1 || ow[0].ID != "i2" {
		t.Errorf("owner filter (case-insensitive): %v", ids(ow))
	}
	un, _ := st.Issues(IssueFilter{Owner: "(unassigned)"})
	if len(un) != 0 {
		t.Errorf("unassigned filter: %v", ids(un))
	}
	// Re-resolution replaces; a nil due date clears it (no SLA).
	if err := st.SetIssueGovernance([]IssueGovernance{{ID: "i1", Source: "unassigned", Why: "unassigned; no SLA for severity INFO"}}); err != nil {
		t.Fatal(err)
	}
	i1s, _ := st.Issues(IssueFilter{Now: now})
	for _, i := range i1s {
		if i.ID == "i1" && (i.Owner != "" || i.DueAt != nil || i.Overdue || i.OwnerSource != "unassigned") {
			t.Errorf("re-resolved i1 = %+v", i)
		}
	}
	un, _ = st.Issues(IssueFilter{Owner: "(unassigned)"})
	if len(un) != 1 || un[0].ID != "i1" {
		t.Errorf("unassigned filter after re-resolve: %v", ids(un))
	}
	// Rebuilds keep governance columns (they are owned by the governance step).
	if err := st.RebuildIssues(now); err != nil {
		t.Fatal(err)
	}
}

func TestIssueTicketPersist(t *testing.T) {
	st, _ := govIssues(t)
	if err := st.SetIssueTicket("i1", IssueTicket{Sink: "jira", Key: "SEC-1", URL: "https://jira/browse/SEC-1", State: "open"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIssueTicket("nope", IssueTicket{Sink: "jira", Key: "SEC-2"}); err == nil {
		t.Error("ticket on an unknown Issue accepted")
	}
	is, _ := st.Issues(IssueFilter{})
	for _, i := range is {
		if i.ID == "i1" && (i.TicketSink != "jira" || i.TicketKey != "SEC-1" || i.TicketURL != "https://jira/browse/SEC-1" || i.TicketState != "open") {
			t.Errorf("ticket = %+v", i)
		}
	}
}

func ids(is []model.Issue) []string {
	var out []string
	for _, i := range is {
		out = append(out, i.ID)
	}
	return out
}
