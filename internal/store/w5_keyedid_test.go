package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	_ "modernc.org/sqlite"
)

// W5-ISSUES / Verification 5 MCP-1: Issue ids and path secondary keys are keyed with
// HMAC-SHA256 under a per-database random key (store_meta, never queryable), so an id shown next
// to a redacted ARN is no longer an offline oracle for the account (dictionary or brute force).

const keyedAcct = "111111111111"

func keyedFinding() model.Finding {
	f := model.Finding{Source: "prowler", CheckID: "iam_role_admin", CanonicalID: "IAM_ADMIN_ROLE", Title: "admin role", Severity: model.High,
		Status: model.Fail, Provider: "aws", Account: keyedAcct, Resource: model.Resource{ID: "arn:aws:iam::" + keyedAcct + ":role/ops", Type: "aws_iam_role"}, ScanID: "s1"}
	f.Finalize(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	return f
}

func keyedPath() model.AttackPath {
	return model.AttackPath{ID: "p-keyed", RuleID: "GRAPH_TRAVERSAL", Name: "internet → role/ops", Provider: "aws", Account: keyedAcct, Score: 9.1,
		Severity: model.Critical, Steps: []model.Step{
			{Stage: 1, Relation: "exposes", Resource: "arn:aws:ec2:us-east-1:" + keyedAcct + ":security-group/sg-1", Evidence: map[string]any{"edge": "exposes", "confidence": "verified"}},
			{Stage: 2, Relation: "runs_as", Resource: "arn:aws:iam::" + keyedAcct + ":role/ops", Evidence: map[string]any{"edge": "runs_as"}},
		}}
}

func seedKeyed(t *testing.T, st *Store) {
	t.Helper()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f := keyedFinding()
	if _, err := st.ApplyScan("s1", []model.Finding{f}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{f})}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{keyedPath()}}, t0); err != nil {
		t.Fatal(err)
	}
}

func allIssueIDs(t *testing.T, st *Store) (ids []string, skeys []string) {
	t.Helper()
	is, err := st.Issues(IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range is {
		ids = append(ids, i.ID)
		if i.SecondaryKey != "" {
			skeys = append(skeys, i.SecondaryKey)
		}
		skeys = append(skeys, i.SecondaryKeys...)
	}
	sort.Strings(ids)
	sort.Strings(skeys)
	return ids, skeys
}

func TestKeyedIssueIDsStableWithinADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seedKeyed(t, st)
	ids1, sk1 := allIssueIDs(t, st)
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	seedKeyed(t, st2) // a second ingest of the same estate
	ids2, sk2 := allIssueIDs(t, st2)
	if len(ids1) != 2 || strings.Join(ids1, ",") != strings.Join(ids2, ",") || strings.Join(sk1, ",") != strings.Join(sk2, ",") {
		t.Fatalf("ids changed across reopen/ingest:\n %v %v\n %v %v", ids1, sk1, ids2, sk2)
	}
	if got := st2.PathIssueIDOf(keyedPath()); !contains(ids2, got) {
		t.Fatalf("PathIssueIDOf %s is not a stored id %v", got, ids2)
	}
}

func TestKeyedIssueIDsDifferAcrossDatabases(t *testing.T) {
	a, b := openTemp(t), openTemp(t)
	seedKeyed(t, a)
	seedKeyed(t, b)
	ia, ka := allIssueIDs(t, a)
	ib, kb := allIssueIDs(t, b)
	for _, x := range ia {
		if contains(ib, x) {
			t.Fatalf("id %s is the same in two databases (unkeyed)", x)
		}
	}
	for _, x := range ka {
		if contains(kb, x) {
			t.Fatalf("secondary key %s is the same in two databases (unkeyed)", x)
		}
	}
}

// The Verification 5 probe recovered the account by hashing candidate ARNs. Without the key the
// same dictionary (and every hash variant the old code used) reproduces nothing.
func TestKeyedIssueIDsResistDictionaryAttack(t *testing.T) {
	st := openTemp(t)
	seedKeyed(t, st)
	ids, skeys := allIssueIDs(t, st)
	stored := map[string]bool{}
	for _, x := range append(ids, skeys...) {
		stored[x] = true
	}
	f, p := keyedFinding(), keyedPath()
	hits, sanity := 0, 0
	for n := 111111110000; n <= 111111112000; n++ {
		acct := fmt.Sprint(n)
		res := strings.Replace(f.Resource.ID, keyedAcct, acct, 1)
		cp := p
		cp.Steps = append([]model.Step(nil), p.Steps...)
		for i := range cp.Steps {
			cp.Steps[i].Resource = strings.Replace(cp.Steps[i].Resource, keyedAcct, acct, 1)
		}
		e, an, r := model.PathIssueKey(cp)
		for _, c := range []string{legacyIssueDigest(model.IssueSingle, f.CanonicalID, res), model.PathIssueID(model.IssuePath, e, an, r), model.PathSecondaryKey(cp)} {
			if stored[c] {
				hits++
			}
			if acct == keyedAcct && c != "" {
				sanity++
			}
		}
	}
	if sanity != 3 {
		t.Fatalf("sanity: the true account's unkeyed candidates were not computed")
	}
	if hits != 0 {
		t.Fatalf("dictionary attack reproduced %d stored ids without the key", hits)
	}
}

// The key and the old→new id map are never readable by untrusted SQL (/api/query, MCP sql).
func TestIDKeyNotQueryable(t *testing.T) {
	st := openTemp(t)
	seedKeyed(t, st)
	names, err := st.QueryableTables()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "store_meta" || n == "issue_id_map" {
			t.Fatalf("%s is queryable", n)
		}
	}
	for _, q := range []string{"SELECT * FROM store_meta", "SELECT hex(v) FROM store_meta", "SELECT * FROM issue_id_map", `SELECT * FROM "STORE_META"`} {
		if _, err := st.QueryReadOnly(context.Background(), q, ReadOnlyOptions{}); !errors.Is(err, ErrUnsafeSQL) {
			t.Fatalf("%s: err %v, want ErrUnsafeSQL", q, err)
		}
	}
	var n int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM store_meta WHERE k = 'issue_id_key' AND length(v) = 32").Scan(&n); err != nil || n != 1 {
		t.Fatalf("store_meta key row: %d %v", n, err)
	}
}

// buildV9Keyed is a database as the previous release left it (migrations 1..9, unkeyed ids) with
// a finding Issue and a path Issue that carry history, a verification, a ticket and a suppression.
func buildV9Keyed(t *testing.T) (path string, singleID, pathID string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "v9.db")
	db, err := sql.Open("sqlite", path+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrationsTable); err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.Version > 9 {
			break
		}
		if _, err := applyMigration(db, m); err != nil {
			t.Fatalf("migration %d: %v", m.Version, err)
		}
	}
	old := &Store{db: db, path: path} // no key: the legacy unkeyed derivation
	seedKeyed(t, old)
	f := keyedFinding()
	singleID = legacyIssueDigest(model.IssueSingle, f.CanonicalID, f.Resource.ID)
	e, a, r := model.PathIssueKey(keyedPath())
	pathID = model.PathIssueID(model.IssuePath, e, a, r)
	ids, _ := allIssueIDs(t, old)
	if !contains(ids, singleID) || !contains(ids, pathID) {
		t.Fatalf("v9 fixture ids %v, want legacy %s %s", ids, singleID, pathID)
	}
	t1 := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	if err := old.SetIssueTicket(singleID, IssueTicket{Sink: "jira", Key: "SEC-7", URL: "https://jira.example/SEC-7", State: "open"}); err != nil {
		t.Fatal(err)
	}
	if err := old.SuppressIssue(pathID, Suppression{Reason: "accepted risk", ExpiresAt: t1.Add(30 * 24 * time.Hour), ApprovedBy: "sec"}, t1); err != nil {
		t.Fatal(err)
	}
	if err := old.RecordVerification(Verification{IssueID: singleID, Result: VerifyOpen, At: t1, VerifiedBy: "rescan", Reads: 1, Confirmations: 0, Required: 3}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return path, singleID, pathID
}

func TestKeyedIDMigrationKeepsHistoryTicketsSuppressions(t *testing.T) {
	path, oldSingle, oldPath := buildV9Keyed(t)
	raw, _ := sql.Open("sqlite", path)
	var histBefore, verBefore int
	raw.QueryRow("SELECT COUNT(*) FROM path_issue_history WHERE issue_id = ?", oldPath).Scan(&histBefore)
	raw.QueryRow("SELECT COUNT(*) FROM issue_verifications WHERE issue_id = ?", oldSingle).Scan(&verBefore)
	raw.Close()
	if histBefore == 0 || verBefore == 0 {
		t.Fatalf("fixture: history %d verifications %d", histBefore, verBefore)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open v9: %v", err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() {
		t.Fatalf("schema %d, want %d", v, LatestSchemaVersion())
	}
	newSingle, newPath := st.ResolveIssueID(oldSingle), st.ResolveIssueID(oldPath)
	if newSingle == oldSingle || newPath == oldPath || newSingle != st.KeyID(oldSingle) || newPath != st.KeyID(oldPath) {
		t.Fatalf("old ids not mapped: %s→%s %s→%s", oldSingle, newSingle, oldPath, newPath)
	}
	ids, skeys := allIssueIDs(t, st)
	if contains(ids, oldSingle) || contains(ids, oldPath) || !contains(ids, newSingle) || !contains(ids, newPath) {
		t.Fatalf("ids after migration %v", ids)
	}
	if contains(skeys, model.PathSecondaryKey(keyedPath())) {
		t.Fatalf("an unkeyed secondary key survived the migration: %v", skeys)
	}
	var n int
	st.DB().QueryRow("SELECT COUNT(*) FROM path_issue_history WHERE issue_id = ?", newPath).Scan(&n)
	if n != histBefore {
		t.Fatalf("path history rows %d, want %d", n, histBefore)
	}
	st.DB().QueryRow("SELECT COUNT(*) FROM path_issue_history WHERE secondary_key = ?", model.PathSecondaryKey(keyedPath())).Scan(&n)
	if n != 0 {
		t.Fatalf("%d history rows keep an unkeyed secondary key", n)
	}
	if v, _ := st.Verifications(newSingle); len(v) != verBefore {
		t.Fatalf("verifications %d, want %d", len(v), verBefore)
	}
	single, pth := issueByID(t, st, newSingle), issueByID(t, st, newPath)
	if single.TicketKey != "SEC-7" || single.TicketSink != "jira" {
		t.Fatalf("ticket lost: %+v", single)
	}
	if pth.State != model.StateSuppressed || pth.Reason == "" {
		t.Fatalf("suppression lost: state %s reason %q", pth.State, pth.Reason)
	}
	// A rebuild after the migration keeps the same (keyed) ids, and the suppression.
	seedKeyed(t, st)
	ids2, skeys2 := allIssueIDs(t, st)
	if strings.Join(ids, ",") != strings.Join(ids2, ",") || strings.Join(skeys, ",") != strings.Join(skeys2, ",") {
		t.Fatalf("rebuild after migration changed ids: %v→%v %v→%v", ids, ids2, skeys, skeys2)
	}
	if issueByID(t, st, newPath).State != model.StateSuppressed {
		t.Fatal("suppression lost on rebuild")
	}
	// Re-opening is a no-op (migration recorded; key unchanged).
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if ids3, _ := allIssueIDs(t, st2); strings.Join(ids, ",") != strings.Join(ids3, ",") {
		t.Fatalf("reopen changed ids")
	}
}
