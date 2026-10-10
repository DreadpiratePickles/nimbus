package store

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// otherRows hashes every issues row except skip (column order fixed by SELECT *).
func otherRows(t *testing.T, db *sql.DB, skip string) string {
	t.Helper()
	rows, err := db.Query("SELECT * FROM issues WHERE id <> ? ORDER BY id", skip)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var b strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%v\n", vals)
	}
	return b.String()
}

// RM4 schema: migration 8 adds the verification history, the score-change history and keeps
// verified_at / verified_by on issues.
func TestMigration8VerificationSchema(t *testing.T) {
	st := openTemp(t)
	if LatestSchemaVersion() < 8 {
		t.Fatalf("latest schema version %d, want >= 8", LatestSchemaVersion())
	}
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() {
		t.Fatalf("fresh db at version %d", v)
	}
	for _, tbl := range []string{"issue_verifications", "issue_score_history"} {
		if !st.TableExists(tbl) {
			t.Errorf("table %s missing", tbl)
		}
	}
	var n int
	st.DB().QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='trg_path_issue_score_history'").Scan(&n)
	if n != 1 {
		t.Errorf("score-history trigger missing")
	}
	tx, _ := st.DB().Begin()
	defer tx.Rollback()
	for _, c := range []string{"verified_at", "verified_by"} {
		if ok, _ := hasColumn(tx, "issues", c); !ok {
			t.Errorf("issues.%s missing", c)
		}
	}
	// Idempotent: re-applying the step on a migrated database is a no-op.
	if err := migrateIssueVerification(tx); err != nil {
		t.Errorf("migration 8 not idempotent: %v", err)
	}
}

func TestRecordVerificationTouchesOnlyThatIssue(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	st := openTemp(t)
	if _, err := st.RebuildPathIssues("s1", labAnalysis(t), t0); err != nil {
		t.Fatal(err)
	}
	ids := pathIssueIDs(t, st)
	if len(ids) < 2 {
		t.Fatalf("need two path Issues, have %d", len(ids))
	}
	fixed, open := ids[0], ids[1]
	before := otherRows(t, st.DB(), fixed)
	at := t0.Add(2 * time.Hour)
	if err := st.RecordVerification(Verification{IssueID: fixed, Result: VerifyFixed, At: at, VerifiedBy: "rescan", Reads: 3, Confirmations: 3, Required: 3,
		Reason: "no surviving path", Evidence: []string{"read 1: gone"}}); err != nil {
		t.Fatal(err)
	}
	if after := otherRows(t, st.DB(), fixed); after != before {
		t.Fatalf("verification of %s changed other Issues' rows", fixed)
	}
	is := issueByID(t, st, fixed)
	if is.State != StateVerifiedFixed || is.VerifiedAt == nil || !is.VerifiedAt.Equal(at) || is.VerifiedBy != "rescan" || is.ResolvedAt == nil {
		t.Fatalf("verified Issue = state %s verified_at %v by %q resolved %v", is.State, is.VerifiedAt, is.VerifiedBy, is.ResolvedAt)
	}
	if model.IsActive(is.State) {
		t.Errorf("verified_fixed must not count as active")
	}
	h, _ := st.PathIssueHistory(fixed)
	if len(h) == 0 || h[len(h)-1].State != StateVerifiedFixed {
		t.Errorf("path history lacks the verified_fixed transition: %+v", h)
	}
	if err := st.RecordVerification(Verification{IssueID: open, Result: VerifyOpen, At: at, VerifiedBy: "rescan", Reads: 1, Required: 3, Reason: "port 3389 still open from 0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	if got := issueByID(t, st, open); got.State != model.StateOpen || got.VerifiedAt != nil {
		t.Errorf("a failed verification changed the Issue: %s %v", got.State, got.VerifiedAt)
	}
	vs, err := st.Verifications(open)
	if err != nil || len(vs) != 1 || vs[0].Result != VerifyOpen || !strings.Contains(vs[0].Reason, "3389") || vs[0].Required != 3 {
		t.Fatalf("verification history = %+v (%v)", vs, err)
	}
	all, _ := st.VerificationsBetween(t0, at.Add(time.Second), VerifyFixed)
	if len(all) != 1 || all[0].IssueID != fixed || len(all[0].Evidence) != 1 {
		t.Errorf("VerificationsBetween(fixed) = %+v", all)
	}
	if err := st.RecordVerification(Verification{IssueID: "nope", Result: VerifyFixed, At: at}); err == nil {
		t.Errorf("unknown Issue accepted")
	}
}

func TestPathScoreChangesRecordedByRebuild(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	st := openTemp(t)
	a1 := labAnalysis(t)
	if _, err := st.RebuildPathIssues("s1", a1, t0); err != nil {
		t.Fatal(err)
	}
	ids := pathIssueIDs(t, st)
	target := issueByID(t, st, ids[0])
	a2 := labAnalysis(t)
	for i, p := range a2.Paths {
		if st.PathIssueIDOf(p) == target.ID {
			a2.Paths[i].Score = 3.0
		}
	}
	t1 := t0.Add(time.Hour)
	if _, err := st.RebuildPathIssues("s2", a2, t1); err != nil {
		t.Fatal(err)
	}
	ch, err := st.LatestPathScoreChanges()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := ch[target.ID]
	if !ok || c.OldScore != target.Score || c.NewScore != 3.0 || c.OldBand != target.Band || c.NewBand != model.ScoreBand(3.0) {
		t.Fatalf("score change for %s = %+v (ok %v), was %.1f %s", target.ID, c, ok, target.Score, target.Band)
	}
	if len(ch) != 1 {
		t.Errorf("unchanged Issues reported as rescored: %v", ch)
	}
}

func issueByID(t *testing.T, st *Store, id string) model.Issue {
	t.Helper()
	is, err := st.Issues(IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range is {
		if i.ID == id {
			return i
		}
	}
	t.Fatalf("issue %s not found", id)
	return model.Issue{}
}

// Migration 8 on a v7 database leaves every existing issues row unchanged.
func TestMigration8OnV7Database(t *testing.T) {
	path := buildV6(t)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyMigration(raw, migrations[6]); err != nil || migrations[6].Version != 7 {
		t.Fatalf("migration 7: %v", err)
	}
	nBefore, sumBefore := issuesDigest(t, raw)
	raw.Close()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open v7 db: %v", err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() {
		t.Fatalf("schema version %d, want %d", v, LatestSchemaVersion())
	}
	if n, sum := issuesDigest(t, st.DB()); n != nBefore || sum != sumBefore || n == 0 {
		t.Fatalf("issues changed by migration 8 (%d rows before, %d after)", nBefore, n)
	}
	if !st.TableExists("issue_verifications") {
		t.Errorf("issue_verifications missing after upgrade")
	}
}
