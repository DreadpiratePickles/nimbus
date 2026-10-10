package store

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// issuesV5Columns are the issues columns as of migration 5; the md5 over them must not
// change when migration 6 rebuilds the table.
const issuesV5Columns = "id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, resolved_at, finding_ids, sources, confidence, kind, title"

func issuesDigest(t *testing.T, db *sql.DB) (int, string) {
	t.Helper()
	// After migration 10 (keyed ids) compare under the pre-migration ids (issue_id_map).
	q := "SELECT " + issuesV5Columns + " FROM issues ORDER BY id"
	var mapped int
	db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name = 'issue_id_map'").Scan(&mapped)
	if mapped > 0 {
		q = "SELECT COALESCE((SELECT old_id FROM issue_id_map m WHERE m.new_id = issues.id), id) AS oid, " +
			strings.TrimPrefix(issuesV5Columns, "id, ") + " FROM issues ORDER BY oid"
	}
	rows, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	h := md5.New()
	n := 0
	for rows.Next() {
		vals := make([]any, 15)
		ptrs := make([]any, 15)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			h.Write([]byte(strings.TrimSpace(sqlString(v)) + "\x1f"))
		}
		h.Write([]byte("\x1e"))
		n++
	}
	return n, hex.EncodeToString(h.Sum(nil))
}

func sqlString(v any) string {
	switch x := v.(type) {
	case nil:
		return "<NULL>"
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return strings.TrimSpace(strings.ReplaceAll(sprint(x), "\n", " "))
	}
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// buildV5 creates a database exactly as migration 5 left it (testdata/schema_v5.sql is the
// recorded sqlite_master DDL), with Issues, findings, history and the v5 issues_summary view.
func buildV5(t *testing.T) string {
	t.Helper()
	ddl, err := os.ReadFile(filepath.Join("testdata", "schema_v5.sql"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v5.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatalf("v5 ddl: %v", err)
	}
	for i, n := range []string{"baseline", "finding_lifecycle", "issues", "coverage", "issues_backfill"} {
		if _, err := db.Exec("INSERT INTO schema_migrations VALUES (?,?,?)", i+1, n, "2026-10-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`
INSERT INTO findings (id, source, check_id, canonical_id, severity, status, provider, account, resource_id, first_seen, last_seen, doc, state)
  VALUES ('f1','prowler','c1','S3_PUBLIC_BUCKET','HIGH','FAIL','aws','123','arn:aws:s3:::pii','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','{}','open'),
         ('f2','nimbus','c2','S3_UNENCRYPTED','MEDIUM','FAIL','aws','123','arn:aws:s3:::pii','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','{}','resolved');
INSERT INTO finding_history VALUES ('f1','open','2026-01-01T00:00:00Z','s1'), ('f2','resolved','2026-01-02T00:00:00Z','s2');
INSERT INTO issues VALUES
  ('a1','S3_PUBLIC_BUCKET','arn:aws:s3:::pii','aws','123','HIGH','open','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',NULL,'["f1"]','["prowler"]',0.7,'single','public'),
  ('b2','S3_UNENCRYPTED','arn:aws:s3:::pii','aws','123','MEDIUM','resolved','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','2026-01-02T00:00:00Z','["f2"]','["nimbus"]',0.7,'single',NULL),
  ('c3','TOXIC_PUBLIC_ADMIN','i-1','aws','123','CRITICAL','reopened','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',NULL,'["f1","f2"]','["nimbus","prowler"]',0.91,'combination','toxic');
INSERT INTO coverage VALUES ('s1','aws','123','s3:ListBuckets','ok',NULL,'2026-01-01T00:00:00Z');
CREATE VIEW issues_summary AS
	  SELECT provider, account, severity, kind, state, COUNT(*) AS count, ROUND(AVG(confidence), 2) AS avg_confidence
	  FROM issues GROUP BY provider, account, severity, kind, state;`); err != nil {
		t.Fatal(err)
	}
	return path
}

// Item 10: migration 6 on a migration-5 database keeps every row (counts and an md5 over the
// existing issues columns unchanged) and widens issues to path Issues.
func TestMigration6OnV5Database(t *testing.T) {
	path := buildV5(t)
	raw, _ := sql.Open("sqlite", path)
	tables := []string{"findings", "finding_history", "issues", "coverage", "schema_migrations"}
	before := map[string]int{}
	for _, tb := range tables {
		before[tb] = countRows(t, raw, tb)
	}
	nBefore, sumBefore := issuesDigest(t, raw)
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open v5 db: %v", err)
	}
	defer st.Close()
	// Open runs every later migration too (7 adds governance columns, see migrate7_test.go).
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() || v < 6 {
		t.Fatalf("schema version %d (latest %d), want ≥ 6", v, LatestSchemaVersion())
	}
	for _, tb := range tables {
		want := before[tb]
		if tb == "schema_migrations" {
			want += LatestSchemaVersion() - 5
		}
		if got := countRows(t, st.DB(), tb); got != want {
			t.Errorf("%s rows: %d, want %d", tb, got, want)
		}
	}
	nAfter, sumAfter := issuesDigest(t, st.DB())
	if nAfter != nBefore || sumAfter != sumBefore {
		t.Fatalf("issues changed by migration 6: %d %s -> %d %s", nBefore, sumBefore, nAfter, sumAfter)
	}
	assertV6Shape(t, st)
	// The pre-existing view was dropped with the old table; EnsureViews recreates it.
	if _, err := st.EnsureViews(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.DB().QueryRow("SELECT SUM(count) FROM issues_summary").Scan(&n); err != nil || n != 3 {
		t.Errorf("issues_summary after migration: %d %v", n, err)
	}
	// Re-applying migration 6 (a crash after the rebuild, before it was recorded) is a no-op.
	st.DB().Exec("DELETE FROM schema_migrations WHERE version = 6")
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("re-apply migration 6: %v", err)
	}
	defer st2.Close()
	if _, sum := issuesDigest(t, st2.DB()); sum != sumBefore {
		t.Errorf("issues changed by re-applied migration 6")
	}
}

func TestMigration6OnFreshDatabase(t *testing.T) {
	st := openTemp(t)
	assertV6Shape(t, st)
}

func assertV6Shape(t *testing.T, st *Store) {
	t.Helper()
	tx, err := st.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, c := range []string{"entry_id", "anchor_id", "rule_id", "secondary_key", "score", "band", "confidence_label", "validation_json",
		"weak_link", "toxic_combination", "reason", "expires_at", "approved_by", "verified_at", "verified_by"} {
		if ok, err := hasColumn(tx, "issues", c); err != nil || !ok {
			t.Errorf("issues.%s missing (%v)", c, err)
		}
	}
	for _, c := range []string{"issue_id", "state", "at", "scan_id", "score", "secondary_key"} {
		if ok, err := hasColumn(tx, "path_issue_history", c); err != nil || !ok {
			t.Errorf("path_issue_history.%s missing (%v)", c, err)
		}
	}
	for _, kind := range []string{"path", "chokepoint", "correlated"} {
		if _, err := tx.Exec(`INSERT INTO issues (id, canonical_id, resource_id, severity, state, finding_ids, sources, confidence, kind)
		  VALUES (?, 'traversal', 'jewel', 'HIGH', 'open', '[]', '[]', 0.7, ?)`, "k-"+kind, kind); err != nil {
			t.Errorf("kind %s rejected: %v", kind, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO issues (id, canonical_id, resource_id, severity, state, finding_ids, sources, confidence, kind)
	  VALUES ('bad', 'x', 'y', 'HIGH', 'open', '[]', '[]', 0.7, 'bogus')`); err == nil {
		t.Error("kind 'bogus' accepted")
	}
	var v string
	if err := tx.QueryRow("SELECT validation_json FROM issues WHERE id = 'k-path'").Scan(&v); err != nil || v != `{"status":"theoretical"}` {
		t.Errorf("validation default = %q (%v), want theoretical", v, err)
	}
	if _, err := tx.Exec(`INSERT INTO issues (id, canonical_id, resource_id, severity, state, finding_ids, sources, confidence, kind)
	  VALUES ('sup', 'x', 'z', 'HIGH', 'suppressed', '[]', '[]', 0.7, 'path')`); err == nil {
		t.Error("suppressed row without reason/expires_at accepted by the schema")
	}
}

func sprint(v any) string { return fmt.Sprint(v) }
