"""Security regressions for inventory defects 1, 2 and 3 (Python side)."""
from __future__ import annotations

import time

import httpx
import pytest

from nimbus.store import Store, UnsafeQuery

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from nimbus.server import create_app  # noqa: E402

TOKEN = "test-token-123"


@pytest.fixture
def outbound(monkeypatch):
    """Record (and block) every outbound HTTP request made through httpx."""
    calls: list[str] = []

    def fake_send(self, request, *a, **kw):
        calls.append(str(request.url))
        return httpx.Response(200, json={}, request=request)

    monkeypatch.setattr(httpx.Client, "send", fake_send)
    return calls


def _count(store: Store) -> int:
    return store.query("SELECT COUNT(*) FROM findings")[1][0][0]


# ---------------------------------------------------------------- defect 1: /api/query


@pytest.mark.parametrize("sql", [
    "WITH x AS (SELECT 1)\nDELETE FROM findings",
    "SELECT '--';DELETE FROM findings",
    "ATTACH DATABASE '/tmp/nimbus-evil.db' AS evil",
    "PRAGMA writable_schema=1",
    "SELECT * FROM pragma_table_info('findings')",
    "SELECT sql FROM sqlite_master",
    'SELECT sql FROM "sqlite_schema"',
    "SELECT * FROM sqlite_temp_master",
])
def test_query_readonly_rejects_bypasses(seeded, sql):
    """The engine-level guard holds even without the lexical sanitizer in front of it."""
    with pytest.raises(UnsafeQuery):
        seeded.query_readonly(sql)
    assert _count(seeded) == 12


def test_query_readonly_allows_views_and_ctes(seeded):
    seeded.ensure_views()
    cols, rows = seeded.query_readonly("SELECT SUM(count) AS n FROM findings_summary")
    assert cols == ["n"] and rows == [[12]]
    cols, rows = seeded.query_readonly("WITH f AS (SELECT * FROM findings) SELECT COUNT(*) FROM f, json_each(f.weaknesses)")
    assert rows[0][0] > 0


def test_query_readonly_times_out(seeded):
    start = time.monotonic()
    with pytest.raises(UnsafeQuery, match="timeout"):
        seeded.query_readonly("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x FROM c WHERE x = 1 OR x < 0",
                              timeout=0.3)
    assert time.monotonic() - start < 2.0


def test_api_query_rejects_bypasses(seeded):
    client = TestClient(create_app(seeded.path))
    for sql in ("SELECT '--';DELETE FROM findings", "SELECT * FROM sqlite_master", "ATTACH 'x.db' AS x",
                "SELECT * FROM pragma_table_info('findings')"):
        assert client.post("/api/query", json={"sql": sql}).status_code == 400, sql
    assert client.post("/api/query", json={"sql": "SELECT COUNT(*) AS n FROM findings"}).json()["rows"] == [[12]]
    assert _count(seeded) == 12


# ---------------------------------------------------------------- defect 3: view DDL


def test_crafted_resource_type_is_not_interpolated(seeded):
    from nimbus.models import Finding

    f = Finding.model_validate(dict(source="native", check_id="c", canonical_id="X", title="t", severity="HIGH", status="FAIL",
                                    provider="aws", account="1", resource={"id": "evil", "type": "x\tAS\tSELECT\t1--", "name": "e"}))
    seeded.upsert_findings([f.finalize()])
    made = seeded.ensure_views()
    assert not any("\t" in v or "select" in v for v in made)
    assert _count(seeded) == 13


# ---------------------------------------------------------------- defect 2: /api/alerts


def test_alerts_disabled_without_server_token(seeded, monkeypatch, outbound):
    monkeypatch.delenv("CLOUD_POSTURE_TOKEN", raising=False)
    client = TestClient(create_app(seeded.path))
    fid = seeded.findings()[0].id
    r = client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]})
    assert r.status_code in (404, 501)
    assert outbound == []


def test_alerts_requires_bearer_token(seeded, monkeypatch, outbound):
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", TOKEN)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/server-side")
    client = TestClient(create_app(seeded.path))
    fid = seeded.findings()[0].id
    assert client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]}).status_code == 401
    assert client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert outbound == []


@pytest.mark.parametrize("target", [
    {"type": "slack", "webhook_url": "https://attacker.example/hook"},
    {"type": "github", "api_url": "https://attacker.example", "repo": "a/b"},
    {"type": "jira", "base_url": "https://attacker.example"},
    {"type": "datadog", "site": "attacker.example"},
    "https://attacker.example/hook",
])
def test_alerts_never_take_destinations_from_the_request(seeded, monkeypatch, outbound, target):
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("DD_API_KEY", "dd_secret")
    client = TestClient(create_app(seeded.path))
    fid = seeded.findings()[0].id
    r = client.post("/api/alerts", json={"finding_ids": [fid], "targets": [target]}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 400
    assert outbound == []


def test_alerts_use_server_side_destination(seeded, monkeypatch, outbound):
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", TOKEN)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/server-side")
    client = TestClient(create_app(seeded.path))
    fid = seeded.findings()[0].id
    r = client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    assert outbound == ["https://hooks.slack.com/services/T/B/server-side"]


def test_token_is_trimmed_consistently(seeded, monkeypatch, outbound):
    """Go trims CLOUD_POSTURE_TOKEN and refuses whitespace-only; Python must match."""
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", f"  {TOKEN}  ")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/server-side")
    client = TestClient(create_app(seeded.path))
    fid = seeded.findings()[0].id
    r = client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]},
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code != 401, "a token with surrounding whitespace must authenticate once trimmed"
    monkeypatch.setenv("CLOUD_POSTURE_TOKEN", "   ")
    client = TestClient(create_app(seeded.path))
    r = client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["slack"]},
                    headers={"Authorization": "Bearer    "})
    assert r.status_code in (404, 501), "a whitespace-only token must count as no token"
