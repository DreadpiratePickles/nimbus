package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// legacyV0 is the exact DDL every database created before versioned migrations has
// (store.go `schema` + `graphSchema` as of 2026-10-09), with no schema_migrations table.
const legacyV0 = `
CREATE TABLE findings (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, check_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
  title TEXT, description TEXT, severity TEXT NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL,
  account TEXT, region TEXT, resource_id TEXT, resource_type TEXT, resource_name TEXT, file TEXT,
  line_start INTEGER, line_end INTEGER, remediation TEXT, weaknesses TEXT, compliance TEXT, tags TEXT,
  scan_id TEXT, first_seen TEXT, last_seen TEXT, doc TEXT NOT NULL
);
CREATE TABLE resources (id TEXT PRIMARY KEY, type TEXT, name TEXT, provider TEXT, account TEXT, region TEXT, attributes TEXT, related TEXT, last_seen TEXT);
CREATE TABLE attack_paths (id TEXT PRIMARY KEY, rule_id TEXT, name TEXT, provider TEXT, account TEXT, severity TEXT, score REAL, scan_id TEXT, doc TEXT NOT NULL);
CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, doc TEXT NOT NULL);
CREATE TABLE alerts (finding_id TEXT, channel TEXT, external_ref TEXT, sent_at TEXT, PRIMARY KEY (finding_id, channel));
CREATE TABLE graph_nodes (id TEXT PRIMARY KEY, type TEXT, class TEXT, name TEXT, provider TEXT, account TEXT, region TEXT,
  sensitive INTEGER, criticality TEXT, owner TEXT, modified_at TEXT, cve_count INTEGER, monthly_cost REAL, weaknesses TEXT, doc TEXT NOT NULL);
CREATE TABLE graph_edges (from_id TEXT, to_id TEXT, kind TEXT, attr TEXT, PRIMARY KEY (from_id, to_id, kind));
INSERT INTO findings (id, source, check_id, canonical_id, severity, status, provider, account, resource_id, first_seen, last_seen, doc)
  VALUES ('f-open', 'prowler', 'c1', 'S3_PUBLIC_BUCKET', 'HIGH', 'FAIL', 'aws', '123', 'arn:aws:s3:::pii', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
          '{"id":"f-open","source":"prowler","check_id":"c1","canonical_id":"S3_PUBLIC_BUCKET","severity":"HIGH","status":"FAIL","provider":"aws","account":"123","resource":{"id":"arn:aws:s3:::pii","type":"aws_s3_bucket","name":"pii"},"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"}'),
         ('f-pass', 'prowler', 'c2', 'S3_UNENCRYPTED', 'MEDIUM', 'PASS', 'aws', '123', 'arn:aws:s3:::pii', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
          '{"id":"f-pass","source":"prowler","check_id":"c2","canonical_id":"S3_UNENCRYPTED","severity":"MEDIUM","status":"PASS","provider":"aws","account":"123","resource":{"id":"arn:aws:s3:::pii"},"first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"}');
`

func TestMigratesLegacyDatabaseInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacyV0); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	v, err := st.SchemaVersion()
	if err != nil || v != LatestSchemaVersion() {
		t.Fatalf("schema version = %d (%v), want %d", v, err, LatestSchemaVersion())
	}
	for _, tbl := range []string{"schema_migrations", "finding_history", "issues", "coverage"} {
		if !st.TableExists(tbl) {
			t.Errorf("table %s missing after migration", tbl)
		}
	}
	// lifecycle columns exist and were backfilled from status
	var state string
	var resolvedAt sql.NullString
	if err := st.DB().QueryRow("SELECT state, resolved_at FROM findings WHERE id='f-open'").Scan(&state, &resolvedAt); err != nil || state != "open" {
		t.Errorf("f-open state=%q err=%v, want open", state, err)
	}
	if err := st.DB().QueryRow("SELECT state FROM findings WHERE id='f-pass'").Scan(&state); err != nil || state != "resolved" {
		t.Errorf("f-pass state=%q err=%v, want resolved", state, err)
	}
	// existing data still readable through the API
	fs, err := st.Findings(Filter{})
	if err != nil || len(fs) != 2 {
		t.Fatalf("findings after migration: %d %v", len(fs), err)
	}
	st.Close()

	// re-open is a no-op: every migration recorded exactly once
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var n, distinct int
	st.DB().QueryRow("SELECT COUNT(*), COUNT(DISTINCT version) FROM schema_migrations").Scan(&n, &distinct)
	if n != LatestSchemaVersion() || distinct != n {
		t.Errorf("schema_migrations rows=%d distinct=%d, want %d", n, distinct, LatestSchemaVersion())
	}
}

func TestFreshDatabaseIsAtLatestVersion(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != LatestSchemaVersion() || v < 4 {
		t.Fatalf("fresh db version %d, latest %d", v, LatestSchemaVersion())
	}
	ms := Migrations()
	for i, m := range ms {
		if m.Version != i+1 || m.Name == "" {
			t.Errorf("migration %d: version %d name %q — versions must be dense and ordered", i, m.Version, m.Name)
		}
	}
}

// V2 defect 12: Issues are backfilled when the issues table is introduced, so
// /api/summary (IssueCounts) is right before the next scan, and a database migrated
// before the backfill existed (v4, empty issues) is backfilled once too.
func TestMigrationBackfillsIssues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(legacyV0); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	st.DB().QueryRow("SELECT COUNT(*) FROM issues WHERE state IN ('open','reopened')").Scan(&n)
	if n != 1 {
		t.Fatalf("open issues after migrating a legacy db with 1 failing finding: %d, want 1", n)
	}
	// Simulate a db migrated to v4 before the backfill existed: issues empty, v5 not applied.
	st.DB().Exec("DELETE FROM issues")
	st.DB().Exec("DELETE FROM schema_migrations WHERE version > 4")
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.DB().QueryRow("SELECT COUNT(*) FROM issues").Scan(&n)
	if n != 1 {
		t.Fatalf("issues after re-open of a v4 db: %d, want 1", n)
	}
}
