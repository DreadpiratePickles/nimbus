"""V2 defect 7: Python's views must apply Go's lifecycle (state) filter, and cannot drift from Go."""
import re
from pathlib import Path

from nimbus import store as store_mod
from nimbus.store import Store

GO_STORE = Path(__file__).resolve().parents[2] / "internal" / "store" / "store.go"


def _go_const(name: str) -> str:
    src = GO_STORE.read_text()
    m = re.search(name + r'\s*=\s*"((?:[^"\\]|\\.)*)"', src)
    assert m, f"{name} not found in {GO_STORE}"
    return m.group(1).encode().decode("unicode_escape")


def test_view_sql_matches_go():
    assert store_mod.ACTIVE_FAIL_SQL == _go_const("activeFailSQL")
    assert store_mod.FINDINGS_SUMMARY_SQL == _go_const("findingsSummarySQL")
    assert store_mod.ISSUES_SUMMARY_SQL == _go_const("issuesSummarySQL")


def _finding(fid_suffix: str, sev: str, status: str = "FAIL"):
    return {
        "source": "native", "check_id": "c" + fid_suffix, "canonical_id": "S3_PUBLIC_BUCKET", "title": "t",
        "severity": sev, "status": status, "provider": "aws", "account": "111111111111",
        "resource": {"id": "arn:aws:s3:::b" + fid_suffix, "type": "aws_s3_bucket", "name": "b" + fid_suffix},
        "weaknesses": ["PUBLIC_DATA_STORE"],
    }


def test_python_views_exclude_resolved(tmp_path):
    st = Store(str(tmp_path / "p.db"))
    st.upsert_findings([_finding("1", "CRITICAL"), _finding("2", "HIGH")])
    con = st._connect(write=True)
    # a Go-migrated DB: lifecycle columns exist and a later scan resolved one finding
    con.execute("ALTER TABLE findings ADD COLUMN state TEXT NOT NULL DEFAULT 'open'")
    con.execute("UPDATE findings SET state = 'resolved' WHERE severity = 'CRITICAL'")
    con.commit()
    con.close()
    st.ensure_views()  # what python -m nimbus ingest runs
    _, rows = st.query("SELECT severity, count FROM findings_summary WHERE status = 'FAIL'")
    assert rows == [["HIGH", 1]]
    _, rows = st.query("SELECT name, open_findings, public_access FROM aws_s3_buckets ORDER BY name")
    assert rows == [["b1", 0, 0], ["b2", 1, 1]]


def test_python_views_without_lifecycle_columns(tmp_path):
    st = Store(str(tmp_path / "p.db"))
    st.upsert_findings([_finding("1", "CRITICAL")])
    _, rows = st.query("SELECT severity, count FROM findings_summary WHERE status = 'FAIL'")
    assert rows == [["CRITICAL", 1]]


def test_python_rebuilds_issues_summary_on_go_db(tmp_path):
    """P1-ISSUES item 10: on a Go-migrated DB (issues with path columns) Python recreates
    issues_summary with Go's SQL, so path Issues are counted under their own kind."""
    st = Store(str(tmp_path / "p.db"))
    st.upsert_findings([_finding("1", "HIGH")])
    con = st._connect(write=True)
    con.execute("CREATE TABLE issues (id TEXT PRIMARY KEY, provider TEXT, account TEXT, severity TEXT, kind TEXT, state TEXT, "
                "confidence REAL, score REAL)")
    con.execute("INSERT INTO issues VALUES ('a','aws','1','CRITICAL','path','open',0.7,9.5), ('b','aws','1','CRITICAL','path','open',0.7,7.6), "
                "('c','aws','1','HIGH','single','open',0.7,NULL)")
    con.execute("CREATE VIEW issues_summary AS SELECT kind, COUNT(*) AS count FROM issues GROUP BY kind")  # an older definition
    con.commit()
    con.close()
    st.ensure_views()
    _, rows = st.query("SELECT kind, count, max_score FROM issues_summary ORDER BY kind")
    assert rows == [["path", 2, 9.5], ["single", 1, None]]


def test_python_skips_issues_summary_without_path_columns(tmp_path):
    st = Store(str(tmp_path / "p.db"))
    st.upsert_findings([_finding("1", "HIGH")])
    st.ensure_views()
    assert "issues_summary" not in st.views()
