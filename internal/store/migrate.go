package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Migration is one ordered, idempotent schema step. Versions are dense (1..N) and a
// step is recorded in schema_migrations in the same transaction that applies it, so an
// interrupted upgrade is retried as a whole on the next Open.
type Migration struct {
	Version int
	Name    string
	Apply   func(tx *sql.Tx) error
}

const migrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
)`

var migrations = []Migration{
	{1, "baseline", execStep(schema + graphSchema)},
	{2, "finding_lifecycle", migrateLifecycle},
	{3, "issues", execStep(issuesSchema)},
	{4, "coverage", execStep(coverageSchema)},
	// issues_backfill marks that Issues were rebuilt from existing findings; the rebuild
	// itself runs right after migrate (Open), because RebuildIssues is not tx-scoped.
	{5, "issues_backfill", func(*sql.Tx) error { return nil }},
	{6, "path_issues", migratePathIssues},
	{7, "issue_governance", migrateIssueGovernance},
	// issue_verification: RM4 verification history and path-Issue score history (verify.go).
	{8, "issue_verification", migrateIssueVerification},
	// issue_closure: pending_verification / regressed_after_verify columns (durability.go).
	{9, "issue_closure", migrateIssueClosure},
	// keyed_issue_ids: per-database HMAC key (store_meta) and old → new id map (idkey.go, MCP-1).
	{10, "keyed_issue_ids", migrateKeyedIssueIDs},
	// scan_trend: per-scan Issue lifecycle counts on scans (trend.go, r4 #12).
	{11, "scan_trend", migrateScanTrend},
	// issue_score_history: per-scan score and band of every scored Issue (score_history.go, r5 #11).
	{12, "issue_score_history", migrateIssueScoreHistory},
}

// backfillIssuesAfter are the migrations after which Open rebuilds Issues from the
// stored findings (a database upgraded from before Issues, or one upgraded to v4
// before the backfill existed, would otherwise report 0 Issues until the next scan).
var backfillIssuesAfter = map[int]bool{3: true, 5: true}

// Migrations returns the ordered migration list (read-only copy).
func Migrations() []Migration { return append([]Migration(nil), migrations...) }

// LatestSchemaVersion is the version a freshly opened database ends at.
func LatestSchemaVersion() int { return migrations[len(migrations)-1].Version }

// SchemaVersion is the highest applied migration (0 for an unmigrated database).
func (s *Store) SchemaVersion() (int, error) {
	var v sql.NullInt64
	if !s.TableExists("schema_migrations") {
		return 0, nil
	}
	err := s.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&v)
	return int(v.Int64), err
}

func execStep(ddl string) func(*sql.Tx) error {
	return func(tx *sql.Tx) error {
		_, err := tx.Exec(ddl)
		return err
	}
}

// migrate brings db to LatestSchemaVersion. Databases created before versioning (no
// schema_migrations table) start at 0: the baseline is CREATE ... IF NOT EXISTS, so it
// is a no-op on them, and later steps add what is missing.
// It returns the versions this call applied.
func migrate(db *sql.DB) ([]int, error) {
	if _, err := db.Exec(migrationsTable); err != nil {
		return nil, err
	}
	var applied []int
	for _, m := range migrations {
		did, err := applyMigration(db, m)
		if err != nil {
			return applied, fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
		if did {
			applied = append(applied, m.Version)
		}
	}
	return applied, nil
}

func applyMigration(db *sql.DB, m Migration) (bool, error) {
	tx, err := db.Begin() // _txlock=immediate: concurrent openers serialize here
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", m.Version).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if err := m.Apply(tx); err != nil {
		return false, err
	}
	if _, err := tx.Exec("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?,?,?)", m.Version, m.Name, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func hasColumn(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// migrateLifecycle adds findings.state/resolved_at/reopened_at (backfilled from status)
// and the finding_history table. The column default keeps writers that do not know
// about lifecycle (the Python layer's INSERT) valid.
func migrateLifecycle(tx *sql.Tx) error {
	for _, c := range []struct{ name, ddl string }{
		{"state", "ALTER TABLE findings ADD COLUMN state TEXT NOT NULL DEFAULT 'open'"},
		{"resolved_at", "ALTER TABLE findings ADD COLUMN resolved_at TEXT"},
		{"reopened_at", "ALTER TABLE findings ADD COLUMN reopened_at TEXT"},
	} {
		ok, err := hasColumn(tx, "findings", c.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.Exec(c.ddl); err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(`
UPDATE findings SET state = CASE WHEN status = 'FAIL' THEN 'open' ELSE 'resolved' END;
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_scope ON findings(source, provider, account);
CREATE TABLE IF NOT EXISTS finding_history (
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  at TEXT NOT NULL,
  scan_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_fp ON finding_history(fingerprint, at);
CREATE INDEX IF NOT EXISTS idx_history_scan ON finding_history(scan_id);`)
	return err
}

// issuesV6Schema is the issues table from migration 6 on: the kind CHECK admits path,
// chokepoint and correlated Issues; path identity (entry/anchor/rule), the full-hop
// secondary key, score/band, confidence label, validation, weak-link and toxic-combination
// flags, suppression (reason/expires_at/approved_by) and verification columns are added.
// entry_id is NOT NULL DEFAULT ” so the UNIQUE key stays a real constraint for the
// finding-derived kinds (SQLite treats NULLs as distinct).
const issuesV6Schema = `
CREATE TABLE issues_v6 (
  id TEXT PRIMARY KEY,
  canonical_id TEXT NOT NULL,           -- path: rule_id
  resource_id TEXT NOT NULL,            -- path: anchor_id
  provider TEXT,
  account TEXT,
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  resolved_at TEXT,
  finding_ids TEXT NOT NULL,            -- JSON array of finding fingerprints (the evidence)
  sources TEXT NOT NULL,                -- JSON array of distinct tools that agree
  confidence REAL NOT NULL,             -- source-agreement confidence (model.IssueConfidence)
  kind TEXT NOT NULL CHECK (kind IN ('single','combination','path','chokepoint','correlated')),
  title TEXT,
  entry_id TEXT NOT NULL DEFAULT '',
  anchor_id TEXT,
  rule_id TEXT,
  secondary_key TEXT,                   -- PathSecondaryKey of the highest-scoring path
  secondary_keys TEXT,                  -- JSON array: every path's secondary key
  path_ids TEXT,                        -- JSON array: traversal path ids (attack_paths.id)
  score REAL,
  band TEXT,
  confidence_label TEXT CHECK (confidence_label IS NULL OR confidence_label IN ('verified','inferred','hint')),
  validation_json TEXT NOT NULL DEFAULT '{"status":"theoretical"}',
  weak_link INTEGER NOT NULL DEFAULT 0,
  toxic_combination TEXT,
  reason TEXT,
  expires_at TEXT,
  approved_by TEXT,
  suppressed_at TEXT,
  verified_at TEXT,
  verified_by TEXT,
  CHECK (state <> 'suppressed' OR (reason IS NOT NULL AND reason <> '' AND expires_at IS NOT NULL AND expires_at <> '')),
  UNIQUE (kind, canonical_id, resource_id, entry_id)
);
INSERT INTO issues_v6 (id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, resolved_at,
  finding_ids, sources, confidence, kind, title)
  SELECT id, canonical_id, resource_id, provider, account, severity, state, first_seen, last_seen, resolved_at,
  finding_ids, sources, confidence, kind, title FROM issues;
DROP TABLE issues;
ALTER TABLE issues_v6 RENAME TO issues;
`

const pathIssueHistorySchema = `
CREATE INDEX IF NOT EXISTS idx_issues_state ON issues(state, severity);
CREATE INDEX IF NOT EXISTS idx_issues_resource ON issues(resource_id);
CREATE INDEX IF NOT EXISTS idx_issues_kind ON issues(kind, state);
CREATE INDEX IF NOT EXISTS idx_issues_anchor ON issues(anchor_id);
CREATE TABLE IF NOT EXISTS path_issue_history (
  issue_id TEXT NOT NULL,
  state TEXT NOT NULL,
  at TEXT NOT NULL,
  scan_id TEXT,
  score REAL,
  secondary_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_path_history_issue ON path_issue_history(issue_id, at);
CREATE INDEX IF NOT EXISTS idx_path_history_scan ON path_issue_history(scan_id);
`

// migratePathIssues rebuilds issues with the v6 schema (SQLite cannot alter a CHECK
// constraint), copying every existing row unchanged, and adds path_issue_history. It is
// idempotent: a table that already admits kind 'path' is not rebuilt. issues_summary is
// dropped first (a view on the old table would break the rename); EnsureViews recreates it.
func migratePathIssues(tx *sql.Tx) error {
	var ddl string
	if err := tx.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'issues'").Scan(&ddl); err != nil {
		return fmt.Errorf("read issues ddl: %w", err)
	}
	if !strings.Contains(ddl, "'path'") {
		if _, err := tx.Exec("DROP VIEW IF EXISTS issues_summary; DROP TABLE IF EXISTS issues_v6;" + issuesV6Schema); err != nil {
			return err
		}
	}
	_, err := tx.Exec(pathIssueHistorySchema)
	return err
}

// issueGovernanceColumns are the migration-7 columns: the governance assignment (owner, its
// source, the matching rule, the why trail, SLA days, due date and grace end — RFC 3339, NULL
// when there is no SLA) and the one external ticket per Issue (sink, key, URL, state).
var issueGovernanceColumns = []struct{ name, ddl string }{
	{"owner", "ALTER TABLE issues ADD COLUMN owner TEXT"},
	{"owner_source", "ALTER TABLE issues ADD COLUMN owner_source TEXT"},
	{"owner_rule", "ALTER TABLE issues ADD COLUMN owner_rule TEXT"},
	{"due_at", "ALTER TABLE issues ADD COLUMN due_at TEXT"},
	{"grace_until", "ALTER TABLE issues ADD COLUMN grace_until TEXT"},
	{"owner_why", "ALTER TABLE issues ADD COLUMN owner_why TEXT"},
	{"sla_days", "ALTER TABLE issues ADD COLUMN sla_days INTEGER"},
	{"ticket_sink", "ALTER TABLE issues ADD COLUMN ticket_sink TEXT"},
	{"ticket_key", "ALTER TABLE issues ADD COLUMN ticket_key TEXT"},
	{"ticket_url", "ALTER TABLE issues ADD COLUMN ticket_url TEXT"},
	{"ticket_state", "ALTER TABLE issues ADD COLUMN ticket_state TEXT"},
}

// migrateIssueGovernance adds the governance and ticket columns (idempotent: a column that
// already exists is skipped) and indexes owner and due_at for the overdue / owner filters.
func migrateIssueGovernance(tx *sql.Tx) error {
	for _, c := range issueGovernanceColumns {
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
	_, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_issues_owner ON issues(owner, state);
CREATE INDEX IF NOT EXISTS idx_issues_due ON issues(due_at, state);`)
	return err
}
