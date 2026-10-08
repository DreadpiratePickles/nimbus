"""SQLite access compatible with internal/store/store.go.

The Go binary owns the schema; this module creates the same tables (``IF NOT EXISTS``) so the
Python side also works standalone (tests, plugins, notebooks). Every row keeps the full JSON in
``doc``. Views the Go side creates (``attack_path_summary``, ``compliance_controls`` and the
per-framework views) are created here only when missing, as compatible fallbacks.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from .models import (
    SEVERITY_RANK, AttackPath, Finding, GraphEdge, GraphNode, ScanSummary, go_time, parse_severity,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, source TEXT NOT NULL, check_id TEXT NOT NULL, canonical_id TEXT NOT NULL,
  title TEXT, description TEXT, severity TEXT NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL,
  account TEXT, region TEXT, resource_id TEXT, resource_type TEXT, resource_name TEXT, file TEXT,
  line_start INTEGER, line_end INTEGER, remediation TEXT, weaknesses TEXT, compliance TEXT, tags TEXT,
  scan_id TEXT, first_seen TEXT, last_seen TEXT, doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status, severity);
CREATE INDEX IF NOT EXISTS idx_findings_resource ON findings(resource_id);
CREATE INDEX IF NOT EXISTS idx_findings_canonical ON findings(canonical_id);
CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY, type TEXT, name TEXT, provider TEXT, account TEXT, region TEXT,
  attributes TEXT, related TEXT, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(type);
CREATE TABLE IF NOT EXISTS attack_paths (
  id TEXT PRIMARY KEY, rule_id TEXT, name TEXT, provider TEXT, account TEXT, severity TEXT,
  score REAL, scan_id TEXT, doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
  finding_id TEXT, channel TEXT, external_ref TEXT, sent_at TEXT, PRIMARY KEY (finding_id, channel)
);
CREATE TABLE IF NOT EXISTS graph_nodes (
  id TEXT PRIMARY KEY, type TEXT, class TEXT, name TEXT, provider TEXT, account TEXT, region TEXT,
  sensitive INTEGER, criticality TEXT, owner TEXT, modified_at TEXT, cve_count INTEGER, monthly_cost REAL,
  weaknesses TEXT, doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_edges (from_id TEXT, to_id TEXT, kind TEXT, attr TEXT, PRIMARY KEY (from_id, to_id, kind));
CREATE INDEX IF NOT EXISTS idx_edges_to ON graph_edges(to_id);
"""

# Same table as store.go weaknessColumns: (column, weakness, inverted)
WEAKNESS_COLUMNS = [
    ("public_access", "PUBLIC_DATA_STORE", False),
    ("internet_exposed", "PUBLIC_NETWORK_EXPOSURE", False),
    ("encrypted", "UNENCRYPTED_AT_REST", True),
    ("tls_required", "UNENCRYPTED_IN_TRANSIT", True),
    ("logging_enabled", "NO_LOGGING", True),
    ("mfa_enabled", "NO_MFA", True),
    ("admin_privileges", "OVERPRIVILEGED_IDENTITY", False),
    ("imdsv1_enabled", "IMDSV1_ENABLED", False),
    ("privileged", "PRIVILEGED_CONTAINER", False),
    ("host_access", "HOST_ACCESS", False),
    ("secrets_exposed", "SECRET_EXPOSURE", False),
    ("stale_credentials", "STALE_CREDENTIALS", False),
    ("cross_account_trust", "CROSS_ACCOUNT_TRUST", False),
    ("backup_enabled", "NO_BACKUP", True),
    ("vulnerable", "UNPATCHED", False),
]

# per-framework view name -> framework key used in findings.compliance
FRAMEWORK_VIEWS = {
    "cis_aws_benchmark": "cis_aws",
    "cis_azure_benchmark": "cis_azure",
    "cis_gcp_benchmark": "cis_gcp",
    "cis_k8s_benchmark": "cis_k8s",
    "cis_github_benchmark": "cis_github",
    "nist_800_53": "nist_800_53",
    "pci_dss": "pci_dss",
    "hipaa": "hipaa",
    "gdpr": "gdpr",
    "soc2": "soc2",
    "iso_27001": "iso_27001",
}

SEVERITY_ORDER_SQL = ("CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
                      "WHEN 'LOW' THEN 3 ELSE 4 END")

ATTACK_PATH_SUMMARY_SQL = """CREATE VIEW IF NOT EXISTS attack_path_summary AS
SELECT ap.id AS id, ap.rule_id AS rule_id, ap.name AS name,
  json_extract(ap.doc, '$.steps[0].resource') AS entry_point,
  (SELECT r.type FROM resources r WHERE r.id = json_extract(ap.doc, '$.steps[0].resource')) AS entry_type,
  json_extract(ap.doc, '$.steps[#-1].resource') AS target,
  (SELECT r.type FROM resources r WHERE r.id = json_extract(ap.doc, '$.steps[#-1].resource')) AS target_type,
  json_array_length(ap.doc, '$.steps') AS path_length,
  ap.score AS score, ap.severity AS severity, ap.provider AS provider, ap.account AS account,
  json_extract(ap.doc, '$.impact') AS impact
FROM attack_paths ap"""

COMPLIANCE_CONTROLS_SQL = """CREATE VIEW IF NOT EXISTS compliance_controls AS
SELECT fw.key AS framework, ctl.value AS control_id, '' AS title, f.provider AS provider, f.account AS account,
  CASE WHEN SUM(f.status = 'FAIL') > 0 THEN 'FAIL' WHEN SUM(f.status = 'PASS') > 0 THEN 'PASS' ELSE 'NOT_ASSESSED' END AS status,
  SUM(f.status = 'FAIL') AS failed, SUM(f.status = 'PASS') AS passed,
  group_concat(DISTINCT CASE WHEN f.status = 'FAIL' THEN f.canonical_id END) AS reason
FROM findings f, json_each(CASE WHEN json_valid(f.compliance) AND f.compliance NOT IN ('null', '') THEN f.compliance ELSE '{}' END) fw,
  json_each(fw.value) ctl
GROUP BY fw.key, ctl.value, f.provider, f.account"""


def default_db_path() -> str:
    return os.environ.get("CLOUD_POSTURE_DB") or os.path.join(".cloud-posture", "posture.db")


def view_name(resource_type: str) -> str:
    t = resource_type.lower()
    for ch in "/:-. ":
        t = t.replace(ch, "_")
    t = t.strip("_")
    if not t:
        return ""
    return t if t.endswith("s") else t + "s"


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _jload(s: Any, default: Any) -> Any:
    if s in (None, ""):
        return default
    try:
        v = json.loads(s)
    except (TypeError, ValueError):
        return default
    return default if v is None else v


class Store:
    """Thin wrapper over the posture SQLite database."""

    def __init__(self, path: Optional[str | os.PathLike] = None, create: bool = True):
        self.path = str(path or default_db_path())
        if create:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            con = self._connect(write=True)
            try:
                con.executescript(SCHEMA)
                con.commit()
            finally:
                con.close()

    # -- connections -------------------------------------------------------------
    def _connect(self, write: bool = False) -> sqlite3.Connection:
        if write:
            con = sqlite3.connect(self.path, timeout=5.0)
        else:
            uri = Path(self.path).resolve().as_uri() + "?mode=ro"
            con = sqlite3.connect(uri, uri=True, timeout=5.0)
            con.execute("PRAGMA query_only = ON")
        con.row_factory = sqlite3.Row
        return con

    def exists(self) -> bool:
        return Path(self.path).exists()

    def mtime(self) -> float:
        """Latest modification time of the DB and its WAL file (0 when missing)."""
        best = 0.0
        for p in (self.path, self.path + "-wal"):
            try:
                best = max(best, os.stat(p).st_mtime)
            except OSError:
                pass
        return best

    # -- findings ----------------------------------------------------------------
    def upsert_findings(self, findings: Iterable[Finding | dict], ensure_views: bool = True) -> int:
        items = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in findings]
        now = _now()
        con = self._connect(write=True)
        n = 0
        try:
            for f in items:
                if not f.id:
                    f.finalize(now)
                if f.first_seen is None:
                    f.first_seen = now
                if f.last_seen is None:
                    f.last_seen = now
                row = con.execute("SELECT first_seen FROM findings WHERE id = ?", (f.id,)).fetchone()
                if row and row[0]:
                    from .models import parse_time
                    prev = parse_time(row[0])
                    if prev and prev < f.first_seen:
                        f.first_seen = prev
                doc = f.to_json()
                con.execute(
                    """INSERT INTO findings (id, source, check_id, canonical_id, title, description, severity, status, provider,
                    account, region, resource_id, resource_type, resource_name, file, line_start, line_end, remediation, weaknesses,
                    compliance, tags, scan_id, first_seen, last_seen, doc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET status=excluded.status, severity=excluded.severity, title=excluded.title,
                      description=excluded.description, canonical_id=excluded.canonical_id, resource_name=excluded.resource_name,
                      resource_type=excluded.resource_type, remediation=excluded.remediation, weaknesses=excluded.weaknesses,
                      compliance=excluded.compliance, tags=excluded.tags, scan_id=excluded.scan_id, last_seen=excluded.last_seen,
                      line_start=excluded.line_start, line_end=excluded.line_end, doc=excluded.doc""",
                    (f.id, f.source, f.check_id, f.canonical_id, f.title, f.description, f.severity.value, f.status.value,
                     f.provider, f.account, f.region, f.resource.id, f.resource.type, f.resource.name, f.file, f.line_start,
                     f.line_end, f.remediation, json.dumps(f.weaknesses or None), json.dumps(f.compliance or None),
                     json.dumps(f.tags or None), f.scan_id, _rfc3339(f.first_seen), _rfc3339(f.last_seen), doc),
                )
                if f.resource.id:
                    con.execute(
                        """INSERT INTO resources (id, type, name, provider, account, region, attributes, related, last_seen)
                        VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                        type=COALESCE(NULLIF(excluded.type,''), resources.type), name=excluded.name,
                        attributes=excluded.attributes, related=excluded.related, last_seen=excluded.last_seen""",
                        (f.resource.id, f.resource.type, f.resource.name, f.provider, f.account, f.region,
                         json.dumps(f.resource.attributes), json.dumps(f.resource.related), _rfc3339(f.last_seen)),
                    )
                n += 1
            con.commit()
        finally:
            con.close()
        if ensure_views:
            self.ensure_views()
        return n

    def findings(self, status: Optional[str] = None, severity: Optional[str] = None, min_severity: Optional[str] = None,
                 provider: Optional[str] = None, account: Optional[str] = None, canonical_id: Optional[str] = None,
                 source: Optional[str] = None, scan_id: Optional[str] = None, resource_id: Optional[str] = None,
                 limit: Optional[int] = None) -> list[Finding]:
        where, args = [], []
        if status:
            where.append("status = ?"); args.append(status.upper())
        if severity:
            sevs = [parse_severity(s).value for s in str(severity).split(",") if s.strip()]
            where.append("severity IN (%s)" % ",".join("?" * len(sevs))); args.extend(sevs)
        if min_severity:
            rank = parse_severity(min_severity).rank
            allowed = [s for s, r in SEVERITY_RANK.items() if r >= rank]
            where.append("severity IN (%s)" % ",".join("?" * len(allowed))); args.extend(allowed)
        if provider:
            where.append("provider = ?"); args.append(provider.lower())
        if account:
            where.append("(account = ? OR json_extract(tags, '$.account_label') = ?)"); args.extend([account, account])
        if canonical_id:
            where.append("canonical_id = ?"); args.append(canonical_id.upper())
        if source:
            where.append("source = ?"); args.append(source)
        if scan_id:
            where.append("scan_id = ?"); args.append(scan_id)
        if resource_id:
            where.append("resource_id = ?"); args.append(resource_id)
        q = "SELECT doc FROM findings"
        if where:
            q += " WHERE " + " AND ".join(where)
        q += f" ORDER BY {SEVERITY_ORDER_SQL}, provider, canonical_id"
        if limit and int(limit) > 0:
            q += f" LIMIT {int(limit)}"
        if not self.exists():
            return []
        con = self._connect()
        try:
            return [Finding.model_validate_json(r[0]) for r in con.execute(q, args)]
        finally:
            con.close()

    def finding(self, finding_id: str) -> Optional[Finding]:
        if not self.exists():
            return None
        con = self._connect()
        try:
            row = con.execute("SELECT doc FROM findings WHERE id = ?", (finding_id,)).fetchone()
        finally:
            con.close()
        return Finding.model_validate_json(row[0]) if row else None

    # -- attack paths / scans ----------------------------------------------------
    def replace_attack_paths(self, paths: Iterable[AttackPath | dict], scan_id: str = "") -> None:
        con = self._connect(write=True)
        try:
            con.execute("DELETE FROM attack_paths")
            for p in paths:
                p = p if isinstance(p, AttackPath) else AttackPath.model_validate(p)
                con.execute("INSERT INTO attack_paths (id, rule_id, name, provider, account, severity, score, scan_id, doc) VALUES (?,?,?,?,?,?,?,?,?)",
                            (p.id, p.rule_id, p.name, p.provider, p.account, p.severity.value, p.score, scan_id, json.dumps(p.to_doc())))
            con.commit()
        finally:
            con.close()

    def attack_paths(self) -> list[AttackPath]:
        if not self.exists():
            return []
        con = self._connect()
        try:
            return [AttackPath.model_validate_json(r[0]) for r in con.execute("SELECT doc FROM attack_paths ORDER BY score DESC")]
        finally:
            con.close()

    def save_scan(self, summary: ScanSummary | dict) -> None:
        s = summary if isinstance(summary, ScanSummary) else ScanSummary.model_validate(summary)
        con = self._connect(write=True)
        try:
            con.execute("INSERT OR REPLACE INTO scans (id, started_at, finished_at, doc) VALUES (?,?,?,?)",
                        (s.scan_id, _rfc3339(s.started_at), _rfc3339(s.finished_at), json.dumps(s.to_doc())))
            con.commit()
        finally:
            con.close()

    def scans(self) -> list[ScanSummary]:
        if not self.exists():
            return []
        con = self._connect()
        try:
            return [ScanSummary.model_validate_json(r[0]) for r in con.execute("SELECT doc FROM scans ORDER BY finished_at DESC")]
        finally:
            con.close()

    def last_scan(self) -> Optional[ScanSummary]:
        s = self.scans()
        return s[0] if s else None

    def mark_alerted(self, finding_id: str, channel: str, ref: str) -> None:
        con = self._connect(write=True)
        try:
            con.execute("INSERT OR REPLACE INTO alerts (finding_id, channel, external_ref, sent_at) VALUES (?,?,?,?)",
                        (finding_id, channel, ref, _rfc3339(_now())))
            con.commit()
        finally:
            con.close()

    # -- graph ---------------------------------------------------------------------
    def replace_graph(self, nodes: Iterable[GraphNode | dict], edges: Iterable[GraphEdge | dict]) -> None:
        con = self._connect(write=True)
        try:
            con.execute("DELETE FROM graph_nodes")
            con.execute("DELETE FROM graph_edges")
            for n in nodes:
                n = n if isinstance(n, GraphNode) else GraphNode.model_validate(n)
                con.execute("INSERT OR REPLACE INTO graph_nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (n.id, n.type, n.class_, n.name, n.provider, n.account, n.region, int(n.sensitive), n.criticality,
                             n.owner, n.modified_at, n.cve_count, n.monthly_cost, json.dumps(n.weaknesses or None), json.dumps(n.to_doc())))
            for e in edges:
                e = e if isinstance(e, GraphEdge) else GraphEdge.model_validate(e)
                con.execute("INSERT OR REPLACE INTO graph_edges VALUES (?,?,?,?)", (e.from_, e.to, e.kind, json.dumps(e.attr or None)))
            con.commit()
        finally:
            con.close()

    def graph(self) -> tuple[list[dict], list[dict]]:
        """Return (nodes, edges) as plain dicts in the graph.Node / graph.Edge JSON shape."""
        if not self.exists():
            return [], []
        con = self._connect()
        try:
            nodes = []
            for r in con.execute("SELECT * FROM graph_nodes"):
                doc = _jload(r["doc"], {})
                for col in ("id", "type", "class", "name", "provider", "account", "region", "criticality", "owner", "modified_at"):
                    if not doc.get(col) and r[col]:
                        doc[col] = r[col]
                if r["sensitive"] and not doc.get("sensitive"):
                    doc["sensitive"] = True
                if r["cve_count"] and not doc.get("cve_count"):
                    doc["cve_count"] = r["cve_count"]
                if not doc.get("weaknesses"):
                    doc["weaknesses"] = _jload(r["weaknesses"], [])
                nodes.append(doc)
            edges = [{"from": r["from_id"], "to": r["to_id"], "kind": r["kind"], "attr": _jload(r["attr"], {})}
                     for r in con.execute("SELECT from_id, to_id, kind, attr FROM graph_edges")]
            return nodes, edges
        except sqlite3.OperationalError:
            return [], []
        finally:
            con.close()

    # -- views -------------------------------------------------------------------
    def ensure_views(self) -> list[str]:
        """Rebuild inventory views + findings_summary (like Go EnsureViews) and create the
        Go-owned summary views only when they do not exist yet."""
        con = self._connect(write=True)
        made: list[str] = []
        try:
            types = sorted({r[0] for r in con.execute("SELECT DISTINCT type FROM resources WHERE type != ''")})
            for t in types:
                v = view_name(t)
                if not v or v in FRAMEWORK_VIEWS or v in ("findings", "resources", "scans", "alerts", "attack_paths"):
                    continue
                kind = con.execute("SELECT type FROM sqlite_master WHERE name = ?", (v,)).fetchone()
                if kind and kind[0] != "view":
                    continue
                cols = [
                    "r.id AS id", "r.name AS name", "r.type AS type", "r.provider AS provider", "r.account AS account", "r.region AS region",
                    "(SELECT COUNT(*) FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL') AS open_findings",
                    "(SELECT MAX(CASE f.severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END) "
                    "FROM findings f WHERE f.resource_id = r.id AND f.status='FAIL') AS max_severity_rank",
                ]
                for col, weak, inv in WEAKNESS_COLUMNS:
                    expr = (f"EXISTS(SELECT 1 FROM findings f WHERE f.resource_id = r.id AND f.status = 'FAIL' "
                            f"AND f.weaknesses LIKE '%\"{weak}\"%')")
                    if inv:
                        expr = "NOT " + expr
                    cols.append(f"({expr}) AS {col}")
                cols.append("r.attributes AS attributes")
                con.execute(f"DROP VIEW IF EXISTS {v}")
                con.execute(f"CREATE VIEW IF NOT EXISTS {v} AS SELECT {', '.join(cols)} FROM resources r WHERE r.type = {_q(t)}")
                made.append(v)
            con.execute("DROP VIEW IF EXISTS findings_summary")
            con.execute("CREATE VIEW IF NOT EXISTS findings_summary AS SELECT provider, account, severity, status, COUNT(*) AS count "
                        "FROM findings GROUP BY provider, account, severity, status")
            made.append("findings_summary")
            con.execute(ATTACK_PATH_SUMMARY_SQL)
            con.execute(COMPLIANCE_CONTROLS_SQL)
            for view, fw in FRAMEWORK_VIEWS.items():
                con.execute(f"CREATE VIEW IF NOT EXISTS {view} AS SELECT control_id, title, provider, account, status, failed, passed, reason "
                            f"FROM compliance_controls WHERE framework = {_q(fw)}")
            con.commit()
        finally:
            con.close()
        return made

    def views(self) -> list[str]:
        if not self.exists():
            return []
        con = self._connect()
        try:
            return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")]
        finally:
            con.close()

    def tables(self) -> list[str]:
        if not self.exists():
            return []
        con = self._connect()
        try:
            return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        finally:
            con.close()

    def table_exists(self, name: str) -> bool:
        if not self.exists():
            return False
        con = self._connect()
        try:
            r = con.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view') AND lower(name) = lower(?)", (name,)).fetchone()
            return bool(r and r[0])
        finally:
            con.close()

    def columns(self, name: str) -> list[str]:
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            return []
        con = self._connect()
        try:
            return [r[1] for r in con.execute(f"PRAGMA table_info({name})")]
        except sqlite3.Error:
            return []
        finally:
            con.close()

    def schema_text(self, max_views: int = 80) -> str:
        """Compact schema description (tables + views with columns) for LLM prompts."""
        lines = ["-- SQLite database for cloud-posture. JSON columns: weaknesses (array), compliance (object framework->[controls]), tags, doc."]
        for kind, names in (("TABLE", self.tables()), ("VIEW", self.views()[:max_views])):
            for n in names:
                cols = self.columns(n)
                lines.append(f"{kind} {n}({', '.join(cols)})")
        return "\n".join(lines)

    # -- raw SQL -----------------------------------------------------------------
    def query(self, sql: str, params: Sequence[Any] | dict | None = None, allow_write: bool = False) -> tuple[list[str], list[list[Any]]]:
        con = self._connect(write=allow_write)
        try:
            cur = con.execute(sql, params or ())
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [[_plain(v) for v in r] for r in cur.fetchall()]
            if allow_write:
                con.commit()
            return cols, rows
        finally:
            con.close()


def _plain(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return v


def _rfc3339(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return go_time(dt.replace(microsecond=0))
