CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);
CREATE TABLE findings (
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
, state TEXT NOT NULL DEFAULT 'open', resolved_at TEXT, reopened_at TEXT);
CREATE INDEX idx_findings_status ON findings(status, severity);
CREATE INDEX idx_findings_resource ON findings(resource_id);
CREATE INDEX idx_findings_canonical ON findings(canonical_id);
CREATE TABLE resources (
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
CREATE INDEX idx_resources_type ON resources(type);
CREATE TABLE attack_paths (
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
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  started_at TEXT,
  finished_at TEXT,
  doc TEXT NOT NULL
);
CREATE TABLE alerts (
  finding_id TEXT,
  channel TEXT,
  external_ref TEXT,
  sent_at TEXT,
  PRIMARY KEY (finding_id, channel)
);
CREATE TABLE graph_nodes (
  id TEXT PRIMARY KEY, type TEXT, class TEXT, name TEXT, provider TEXT, account TEXT, region TEXT,
  sensitive INTEGER, criticality TEXT, owner TEXT, modified_at TEXT, cve_count INTEGER, monthly_cost REAL,
  weaknesses TEXT, doc TEXT NOT NULL
);
CREATE TABLE graph_edges (
  from_id TEXT, to_id TEXT, kind TEXT, attr TEXT, PRIMARY KEY (from_id, to_id, kind)
);
CREATE INDEX idx_edges_to ON graph_edges(to_id);
CREATE INDEX idx_findings_state ON findings(state);
CREATE INDEX idx_findings_scope ON findings(source, provider, account);
CREATE TABLE finding_history (
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  at TEXT NOT NULL,
  scan_id TEXT
);
CREATE INDEX idx_history_fp ON finding_history(fingerprint, at);
CREATE INDEX idx_history_scan ON finding_history(scan_id);
CREATE TABLE issues (
  id TEXT PRIMARY KEY,
  canonical_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  provider TEXT,
  account TEXT,
  severity TEXT NOT NULL,
  state TEXT NOT NULL,
  first_seen TEXT,
  last_seen TEXT,
  resolved_at TEXT,
  finding_ids TEXT NOT NULL,  -- JSON array of finding fingerprints (the evidence)
  sources TEXT NOT NULL,      -- JSON array of distinct tools that agree
  confidence REAL NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('single','combination')),
  title TEXT,
  UNIQUE (kind, canonical_id, resource_id)
);
CREATE INDEX idx_issues_state ON issues(state, severity);
CREATE INDEX idx_issues_resource ON issues(resource_id);
CREATE TABLE coverage (
  scan_id TEXT NOT NULL,
  provider TEXT,
  account TEXT,
  api TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','denied','skipped','error','timeout')),
  reason TEXT,
  at TEXT NOT NULL
);
CREATE INDEX idx_coverage_scan ON coverage(scan_id, provider, account);
