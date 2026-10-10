// Package store persists findings, resources, attack paths and alert state in SQLite
// (pure-Go driver, no cgo) and exposes findings-derived inventory views for SQL queries.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
	// idKey keys Issue ids and secondary keys (idkey.go); nil only for a pre-migration-10
	// database handle built by tests (legacy unkeyed ids).
	idKey []byte
	// viewsMu serialises view (re)creation: EnsureViews drops and recreates views, so two
	// concurrent callers would race on "view already exists" (seen under concurrent /api/query).
	viewsMu sync.Mutex
	// trend holds the pre-scan Issue states between ApplyScan and SaveScan (trend.go).
	trend trendState
}

// LockViews serialises callers that (re)create views; pair with UnlockViews.
func (s *Store) LockViews()   { s.viewsMu.Lock() }
func (s *Store) UnlockViews() { s.viewsMu.Unlock() }

const schema = `
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  check_id TEXT NOT NULL,
  canonical_id TEXT NOT NULL,
  title TEXT,
  description TEXT,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  provider TEXT NOT NULL,
  account TEXT,
  region TEXT,
  resource_id TEXT,
  resource_type TEXT,
  resource_name TEXT,
  file TEXT,
  line_start INTEGER,
  line_end INTEGER,
  remediation TEXT,
  weaknesses TEXT,      -- JSON array
  compliance TEXT,      -- JSON object
  tags TEXT,            -- JSON object
  scan_id TEXT,
  first_seen TEXT,
  last_seen TEXT,
  doc TEXT NOT NULL      -- full finding JSON
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_resource ON findings(resource_id);
CREATE INDEX IF NOT EXISTS idx_findings_canonical ON findings(canonical_id);

CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY,
  type TEXT,
  name TEXT,
  provider TEXT,
  account TEXT,
  region TEXT,
  attributes TEXT,      -- JSON
  related TEXT,         -- JSON array
  last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);

CREATE TABLE IF NOT EXISTS attack_paths (
  id TEXT PRIMARY KEY,
  rule_id TEXT,
  name TEXT,
  provider TEXT,
  account TEXT,
  severity TEXT,
  score REAL,
  scan_id TEXT,
  doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  started_at TEXT,
  finished_at TEXT,
  doc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  finding_id TEXT,
  channel TEXT,
  external_ref TEXT,
  sent_at TEXT,
  PRIMARY KEY (finding_id, channel)
);
`

func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Who built the file is read on a plain read-only handle first: the WAL pragma of the main
	// handle rewrites the header, which already modifies a database we may not touch.
	origin, err := fileOrigin(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if origin == OriginPython {
		pol := currentPolicy()
		if !pol.Allow {
			return nil, &ForeignDBError{Path: path, Origin: origin}
		}
		if pol.Notice != nil {
			fmt.Fprintf(pol.Notice, "notice: upgrading %s (built by the Python layer) to the Go schema v%d; read-only commands never migrate a database\n", path, LatestSchemaVersion())
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	applied, err := migrate(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := markGoIfNeeded(db, origin); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	key, err := loadIDKey(db)
	if err != nil {
		db.Close()
		return nil, err
	}
	st := &Store{db: db, path: path, idKey: key}
	for _, v := range applied {
		if backfillIssuesAfter[v] {
			if err := st.RebuildIssues(time.Now()); err != nil {
				db.Close()
				return nil, fmt.Errorf("backfill issues: %w", err)
			}
			break
		}
	}
	return st, nil
}

func DefaultPath() string {
	if p := os.Getenv("CLOUD_POSTURE_DB"); p != "" {
		return p
	}
	return filepath.Join(".cloud-posture", "posture.db")
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.path }
func (s *Store) DB() *sql.DB  { return s.db }

type Filter struct {
	Status      string
	MinSeverity model.Severity
	Provider    string
	Account     string
	CanonicalID string
	Source      string
	ScanID      string
	Limit       int
	// IncludeResolved also returns failing findings that a later scan resolved (by
	// absence). By default they are history, not current posture.
	IncludeResolved bool
}

func (s *Store) Findings(fl Filter) ([]model.Finding, error) {
	var where []string
	var args []any
	if fl.Status != "" {
		where = append(where, "status = ?")
		args = append(args, strings.ToUpper(fl.Status))
	}
	if fl.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, fl.Provider)
	}
	if fl.Account != "" {
		where = append(where, "(account = ? OR json_extract(tags, '$.account_label') = ?)")
		args = append(args, fl.Account, fl.Account)
	}
	if fl.CanonicalID != "" {
		where = append(where, "canonical_id = ?")
		args = append(args, strings.ToUpper(fl.CanonicalID))
	}
	if fl.Source != "" {
		where = append(where, "source = ?")
		args = append(args, fl.Source)
	}
	if fl.ScanID != "" {
		where = append(where, "scan_id = ?")
		args = append(args, fl.ScanID)
	}
	if fl.MinSeverity != "" {
		var allowed []string
		for sev, rank := range map[model.Severity]int{model.Critical: 5, model.High: 4, model.Medium: 3, model.Low: 2, model.Info: 1} {
			if rank >= fl.MinSeverity.Rank() {
				allowed = append(allowed, "'"+string(sev)+"'")
			}
		}
		where = append(where, "severity IN ("+strings.Join(allowed, ",")+")")
	}
	if !fl.IncludeResolved {
		where = append(where, "NOT (state = 'resolved' AND status <> 'PASS')")
	}
	q := "SELECT doc FROM findings"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, provider, canonical_id"
	if fl.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", fl.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var f model.Finding
		if err := json.Unmarshal([]byte(doc), &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) Finding(id string) (*model.Finding, error) {
	var doc string
	if err := s.db.QueryRow("SELECT doc FROM findings WHERE id = ?", id).Scan(&doc); err != nil {
		return nil, err
	}
	var f model.Finding
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *Store) ReplaceAttackPaths(scanID string, paths []model.AttackPath) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM attack_paths"); err != nil {
		return err
	}
	for _, p := range paths {
		doc, _ := json.Marshal(p)
		if _, err := tx.Exec("INSERT INTO attack_paths (id, rule_id, name, provider, account, severity, score, scan_id, doc) VALUES (?,?,?,?,?,?,?,?,?)",
			p.ID, p.RuleID, p.Name, p.Provider, p.Account, string(p.Severity), p.Score, scanID, string(doc)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AttackPaths() ([]model.AttackPath, error) {
	rows, err := s.db.Query("SELECT doc FROM attack_paths ORDER BY score DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AttackPath
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var p model.AttackPath
		if err := json.Unmarshal([]byte(doc), &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SaveScan(sum model.ScanSummary) error {
	doc, _ := json.Marshal(sum)
	_, err := s.db.Exec("INSERT OR REPLACE INTO scans (id, started_at, finished_at, doc) VALUES (?,?,?,?)",
		sum.ScanID, sum.StartedAt.Format(time.RFC3339), sum.FinishedAt.Format(time.RFC3339), string(doc))
	if err != nil {
		return err
	}
	if err := s.recordScores(sum.ScanID, sum.FinishedAt); err != nil {
		return err
	}
	return s.recordTrend(sum.ScanID, sum.FinishedAt)
}

func (s *Store) LastScan() (*model.ScanSummary, error) {
	var doc string
	err := s.db.QueryRow("SELECT doc FROM scans ORDER BY finished_at DESC LIMIT 1").Scan(&doc)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sum model.ScanSummary
	return &sum, json.Unmarshal([]byte(doc), &sum)
}

// Alerted reports whether a finding was already delivered on a channel.
func (s *Store) Alerted(findingID, channel string) (string, bool) {
	var ref string
	err := s.db.QueryRow("SELECT external_ref FROM alerts WHERE finding_id=? AND channel=?", findingID, channel).Scan(&ref)
	return ref, err == nil
}

func (s *Store) MarkAlerted(findingID, channel, ref string) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO alerts (finding_id, channel, external_ref, sent_at) VALUES (?,?,?,?)", findingID, channel, ref, time.Now().UTC().Format(time.RFC3339))
	return err
}

// --- findings-derived inventory views -------------------------------------

// weaknessColumns maps attack-graph weaknesses onto boolean inventory columns.
// Negative names (encrypted, mfa_enabled...) are inverted so queries read naturally.
var weaknessColumns = []struct {
	Column   string
	Weakness string
	Invert   bool
}{
	{"public_access", "PUBLIC_DATA_STORE", false},
	{"internet_exposed", "PUBLIC_NETWORK_EXPOSURE", false},
	{"encrypted", "UNENCRYPTED_AT_REST", true},
	{"tls_required", "UNENCRYPTED_IN_TRANSIT", true},
	{"logging_enabled", "NO_LOGGING", true},
	{"mfa_enabled", "NO_MFA", true},
	{"admin_privileges", "OVERPRIVILEGED_IDENTITY", false},
	{"imdsv1_enabled", "IMDSV1_ENABLED", false},
	{"privileged", "PRIVILEGED_CONTAINER", false},
	{"host_access", "HOST_ACCESS", false},
	{"secrets_exposed", "SECRET_EXPOSURE", false},
	{"stale_credentials", "STALE_CREDENTIALS", false},
	{"cross_account_trust", "CROSS_ACCOUNT_TRUST", false},
	{"backup_enabled", "NO_BACKUP", true},
	{"vulnerable", "UNPATCHED", false},
}

// activeFailSQL selects a failing finding that is current posture (not resolved by a
// later scan) inside the inventory views. findingsSummarySQL is the findings_summary
// view. python/nimbus/store.py mirrors them byte for byte (ACTIVE_FAIL_SQL,
// FINDINGS_SUMMARY_SQL, ISSUES_SUMMARY_SQL); TestViewSQLMatchesPython and the pytest twin
// keep them equal.
const (
	activeFailSQL      = "f.status = 'FAIL' AND f.state <> 'resolved'"
	findingsSummarySQL = "CREATE VIEW findings_summary AS SELECT provider, account, severity, status, COUNT(*) AS count FROM findings WHERE NOT (state = 'resolved' AND status <> 'PASS') GROUP BY provider, account, severity, status"
	// issuesSummarySQL counts Issues of every kind (path Issues under kind 'path'); max_score
	// is the highest path score in the group (NULL for finding-derived kinds). Mirrored as
	// ISSUES_SUMMARY_SQL in python/nimbus/store.py.
	issuesSummarySQL = "CREATE VIEW issues_summary AS SELECT provider, account, severity, kind, state, COUNT(*) AS count, ROUND(AVG(confidence), 2) AS avg_confidence, MAX(score) AS max_score FROM issues GROUP BY provider, account, severity, kind, state"
)

// EnsureViews creates one view per resource type seen (aws_s3_bucket -> aws_s3_buckets)
// plus `findings_summary`. Views are rebuilt on every call so new types appear.
func (s *Store) EnsureViews() ([]string, error) {
	rows, err := s.db.Query("SELECT DISTINCT type FROM resources WHERE type != ''")
	if err != nil {
		return nil, err
	}
	var types []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		types = append(types, t)
	}
	rows.Close()
	sort.Strings(types)
	var views []string
	for _, t := range types {
		view := viewName(t)
		if !safeIdent.MatchString(view) {
			// Never interpolate a malformed name into DDL (inventory defect 3).
			Warnf("store: skipping inventory view for resource type %q: not a safe identifier", t)
			continue
		}
		cols := []string{
			"r.id AS id", "r.name AS name", "r.type AS type", "r.provider AS provider", "r.account AS account", "r.region AS region",
			"(SELECT COUNT(*) FROM findings f WHERE f.resource_id = r.id AND " + activeFailSQL + ") AS open_findings",
			"(SELECT MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) FROM findings f WHERE f.resource_id = r.id AND " + activeFailSQL + ") AS max_severity_rank",
		}
		for _, wc := range weaknessColumns {
			expr := fmt.Sprintf("EXISTS(SELECT 1 FROM findings f WHERE f.resource_id = r.id AND %s AND f.weaknesses LIKE '%%\"%s\"%%')", activeFailSQL, wc.Weakness)
			if wc.Invert {
				expr = "NOT " + expr
			}
			cols = append(cols, fmt.Sprintf("(%s) AS %s", expr, wc.Column))
		}
		cols = append(cols, "r.attributes AS attributes")
		sqlText := fmt.Sprintf("CREATE VIEW IF NOT EXISTS %s AS SELECT %s FROM resources r WHERE r.type = %s", quoteIdent(view), strings.Join(cols, ", "), quote(t))
		if _, err := s.db.Exec("DROP VIEW IF EXISTS " + quoteIdent(view)); err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(sqlText); err != nil {
			return nil, fmt.Errorf("view %s: %w", view, err)
		}
		views = append(views, view)
	}
	// findings_summary keeps its columns; failing findings a later scan resolved are
	// history, not posture, so they are left out (as in Findings()).
	for _, v := range []struct{ name, sql string }{
		{"findings_summary", findingsSummarySQL},
		{"issues_summary", issuesSummarySQL},
		{"coverage_summary", `CREATE VIEW coverage_summary AS
	  SELECT scan_id, provider, account, status, COUNT(*) AS count, MAX(at) AS at FROM coverage GROUP BY scan_id, provider, account, status`},
	} {
		if _, err := s.db.Exec("DROP VIEW IF EXISTS " + v.name); err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(v.sql); err != nil {
			return nil, fmt.Errorf("view %s: %w", v.name, err)
		}
		views = append(views, v.name)
	}
	return views, nil
}

func viewName(resourceType string) string {
	t := strings.ToLower(resourceType)
	t = strings.NewReplacer("/", "_", ":", "_", "-", "_", ".", "_", " ", "_").Replace(t)
	t = strings.Trim(t, "_")
	if t == "" {
		return ""
	}
	if !strings.HasSuffix(t, "s") {
		t += "s"
	}
	return t
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// safeIdent is the only shape a derived view name may take before it is used in DDL.
var safeIdent = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// quoteIdent double-quotes an identifier (callers have already validated it with safeIdent).
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// Warnf reports skipped or degraded store operations; replaceable in tests.
var Warnf = log.Printf

func (s *Store) TableExists(name string) bool {
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE (type='table' OR type='view') AND lower(name)=lower(?)", name).Scan(&n)
	return n > 0
}

// --- security graph persistence ---------------------------------------------

const graphSchema = `
CREATE TABLE IF NOT EXISTS graph_nodes (
  id TEXT PRIMARY KEY, type TEXT, class TEXT, name TEXT, provider TEXT, account TEXT, region TEXT,
  sensitive INTEGER, criticality TEXT, owner TEXT, modified_at TEXT, cve_count INTEGER, monthly_cost REAL,
  weaknesses TEXT, doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_edges (
  from_id TEXT, to_id TEXT, kind TEXT, attr TEXT, PRIMARY KEY (from_id, to_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_edges_to ON graph_edges(to_id);
`

func (s *Store) ensureGraphSchema() error {
	_, err := s.db.Exec(graphSchema)
	return err
}

// GraphNode/GraphEdge are storage-level mirrors of graph.Node/graph.Edge (kept here to avoid an import cycle).
type GraphNode struct {
	ID, Type, Class, Name, Provider, Account, Region, Criticality, Owner, ModifiedAt string
	Sensitive                                                                        bool
	CVECount                                                                         int
	MonthlyCost                                                                      float64
	Weaknesses                                                                       []string
	Doc                                                                              []byte
}

type GraphEdge struct {
	From, To, Kind string
	Attr           []byte
}

func (s *Store) ReplaceGraph(nodes []GraphNode, edges []GraphEdge) error {
	if err := s.ensureGraphSchema(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM graph_nodes"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM graph_edges"); err != nil {
		return err
	}
	ns, err := tx.Prepare("INSERT INTO graph_nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer ns.Close()
	for _, n := range nodes {
		w, _ := json.Marshal(n.Weaknesses)
		if _, err := ns.Exec(n.ID, n.Type, n.Class, n.Name, n.Provider, n.Account, n.Region, n.Sensitive, n.Criticality, n.Owner, n.ModifiedAt, n.CVECount, n.MonthlyCost, string(w), string(n.Doc)); err != nil {
			return err
		}
	}
	es, err := tx.Prepare("INSERT OR REPLACE INTO graph_edges VALUES (?,?,?,?)")
	if err != nil {
		return err
	}
	defer es.Close()
	for _, e := range edges {
		if _, err := es.Exec(e.From, e.To, e.Kind, string(e.Attr)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LoadGraph() ([]GraphNode, []GraphEdge, error) {
	if err := s.ensureGraphSchema(); err != nil {
		return nil, nil, err
	}
	rows, err := s.db.Query("SELECT doc FROM graph_nodes")
	if err != nil {
		return nil, nil, err
	}
	var nodes []GraphNode
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			rows.Close()
			return nil, nil, err
		}
		nodes = append(nodes, GraphNode{Doc: []byte(doc)})
	}
	rows.Close()
	erows, err := s.db.Query("SELECT from_id, to_id, kind, attr FROM graph_edges")
	if err != nil {
		return nil, nil, err
	}
	defer erows.Close()
	var edges []GraphEdge
	for erows.Next() {
		var e GraphEdge
		var attr string
		if err := erows.Scan(&e.From, &e.To, &e.Kind, &attr); err != nil {
			return nil, nil, err
		}
		e.Attr = []byte(attr)
		edges = append(edges, e)
	}
	return nodes, edges, erows.Err()
}
