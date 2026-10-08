// Package store persists findings, resources, attack paths and alert state in SQLite
// (pure-Go driver, no cgo) and exposes findings-derived inventory views for SQL queries.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

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
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema + graphSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func DefaultPath() string {
	if p := os.Getenv("CLOUD_POSTURE_DB"); p != "" {
		return p
	}
	return filepath.Join(".cloud-posture", "posture.db")
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string  { return s.path }
func (s *Store) DB() *sql.DB   { return s.db }

// UpsertFindings keeps first_seen from an earlier row and refreshes everything else.
func (s *Store) UpsertFindings(findings []model.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO findings (id, source, check_id, canonical_id, title, description, severity, status, provider, account, region,
	  resource_id, resource_type, resource_name, file, line_start, line_end, remediation, weaknesses, compliance, tags, scan_id, first_seen, last_seen, doc)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	  ON CONFLICT(id) DO UPDATE SET
	    status=excluded.status, severity=excluded.severity, title=excluded.title, description=excluded.description,
	    canonical_id=excluded.canonical_id, resource_name=excluded.resource_name, resource_type=excluded.resource_type,
	    remediation=excluded.remediation, weaknesses=excluded.weaknesses, compliance=excluded.compliance, tags=excluded.tags,
	    scan_id=excluded.scan_id, last_seen=excluded.last_seen, line_start=excluded.line_start, line_end=excluded.line_end,
	    doc=excluded.doc`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	resStmt, err := tx.Prepare(`INSERT INTO resources (id, type, name, provider, account, region, attributes, related, last_seen)
	  VALUES (?,?,?,?,?,?,?,?,?)
	  ON CONFLICT(id) DO UPDATE SET type=COALESCE(NULLIF(excluded.type,''), resources.type), name=excluded.name,
	    attributes=excluded.attributes, related=excluded.related, last_seen=excluded.last_seen`)
	if err != nil {
		return err
	}
	defer resStmt.Close()
	for i := range findings {
		f := &findings[i]
		if f.ID == "" {
			f.Finalize(time.Now().UTC())
		}
		doc, _ := json.Marshal(f)
		weak, _ := json.Marshal(f.Weaknesses)
		comp, _ := json.Marshal(f.Compliance)
		tags, _ := json.Marshal(f.Tags)
		if _, err := stmt.Exec(f.ID, f.Source, f.CheckID, f.CanonicalID, f.Title, f.Description, string(f.Severity), string(f.Status),
			f.Provider, f.Account, f.Region, f.Resource.ID, f.Resource.Type, f.Resource.Name, f.File, f.LineStart, f.LineEnd,
			f.Remediation, string(weak), string(comp), string(tags), f.ScanID, f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339), string(doc)); err != nil {
			return err
		}
		if f.Resource.ID != "" {
			attrs, _ := json.Marshal(f.Resource.Attributes)
			rel, _ := json.Marshal(f.Resource.Related)
			if _, err := resStmt.Exec(f.Resource.ID, f.Resource.Type, f.Resource.Name, f.Provider, f.Account, f.Region, string(attrs), string(rel), f.LastSeen.Format(time.RFC3339)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type Filter struct {
	Status      string
	MinSeverity model.Severity
	Provider    string
	Account     string
	CanonicalID string
	Source      string
	ScanID      string
	Limit       int
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
	return err
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
		if view == "" {
			continue
		}
		cols := []string{
			"r.id AS id", "r.name AS name", "r.type AS type", "r.provider AS provider", "r.account AS account", "r.region AS region",
			"(SELECT COUNT(*) FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL') AS open_findings",
			"(SELECT MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) FROM findings f WHERE f.resource_id = r.id AND f.status='FAIL') AS max_severity_rank",
		}
		for _, wc := range weaknessColumns {
			expr := fmt.Sprintf("EXISTS(SELECT 1 FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL' AND f.weaknesses LIKE '%%\"%s\"%%')", wc.Weakness)
			if wc.Invert {
				expr = "NOT " + expr
			}
			cols = append(cols, fmt.Sprintf("(%s) AS %s", expr, wc.Column))
		}
		cols = append(cols, "r.attributes AS attributes")
		sqlText := fmt.Sprintf("CREATE VIEW IF NOT EXISTS %s AS SELECT %s FROM resources r WHERE r.type = %s", view, strings.Join(cols, ", "), quote(t))
		if _, err := s.db.Exec("DROP VIEW IF EXISTS " + view); err != nil {
			return nil, err
		}
		if _, err := s.db.Exec(sqlText); err != nil {
			return nil, fmt.Errorf("view %s: %w", view, err)
		}
		views = append(views, view)
	}
	summary := `CREATE VIEW IF NOT EXISTS findings_summary AS
	  SELECT provider, account, severity, status, COUNT(*) AS count FROM findings GROUP BY provider, account, severity, status`
	s.db.Exec("DROP VIEW IF EXISTS findings_summary")
	if _, err := s.db.Exec(summary); err != nil {
		return nil, err
	}
	views = append(views, "findings_summary")
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

// Query runs arbitrary SQL and returns column names and rows (values JSON-friendly).
func (s *Store) Query(sqlText string) ([]string, [][]any, error) {
	rows, err := s.db.Query(sqlText)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		out = append(out, vals)
	}
	return cols, out, rows.Err()
}

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
	Sensitive                                                                       bool
	CVECount                                                                        int
	MonthlyCost                                                                     float64
	Weaknesses                                                                      []string
	Doc                                                                             []byte
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
