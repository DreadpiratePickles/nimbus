"""Track A2: verifier follow-ups on the Python read-only query path and server (N2, N5, Host/CSRF)."""
from __future__ import annotations

import sqlite3
import time

import pytest

from nimbus.store import QueryTimeout, Store, UnsafeQuery

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from nimbus.server import create_app  # noqa: E402


# ---------------------------------------------------------------- N2: runaway single function calls


@pytest.mark.parametrize("sql", [
    "SELECT length(printf('%.*c', 1000000000, 'x'))",
    "SELECT length(randomblob(1000000000))",
    "SELECT length(zeroblob(1000000000))",
    "SELECT length(replace(hex(zeroblob(1000)), '0', hex(zeroblob(1000))))",
])
def test_huge_values_are_refused_fast(seeded, sql):
    start = time.monotonic()
    try:
        _, rows = seeded.query_readonly(sql, timeout=10)
        assert rows == [[None]], rows  # SQLite printf() yields NULL when its output is too big
    except UnsafeQuery as exc:
        assert "too big" in str(exc)
    assert time.monotonic() - start < 1.0


def test_readonly_connection_limits(seeded):
    con = seeded._readonly_connection()
    try:
        assert con.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == 1 << 20
        assert con.getlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH) == 64 << 10
        assert con.getlimit(sqlite3.SQLITE_LIMIT_ATTACHED) == 0
        assert con.getlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT) <= 64
        assert con.getlimit(sqlite3.SQLITE_LIMIT_TRIGGER_DEPTH) <= 1
    finally:
        con.close()


def test_timeout_fires_within_a_second_of_the_deadline(seeded):
    heavy = ("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) "
             "SELECT count(length(replace(hex(zeroblob(200000)), '0', 'ab'))) FROM c")
    start = time.monotonic()
    with pytest.raises(QueryTimeout):
        seeded.query_readonly(heavy, timeout=1.0)
    assert time.monotonic() - start < 2.0


def test_api_query_timeout_is_408(seeded, monkeypatch):
    monkeypatch.setenv("NIMBUS_QUERY_TIMEOUT", "0.5")
    client = TestClient(create_app(seeded.path))
    start = time.monotonic()
    r = client.post("/api/query", json={"sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c"})
    assert r.status_code == 408, r.text
    assert time.monotonic() - start < 3.0


# ---------------------------------------------------------------- N5: CTEs are not tables


@pytest.mark.parametrize("sql", [
    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 10) SELECT count(*) FROM c",
    "WITH a AS (SELECT * FROM findings), b AS (SELECT * FROM a WHERE severity = 'CRITICAL') SELECT count(*) FROM b",
    "WITH a AS (SELECT id FROM findings), b AS (SELECT count(*) AS n FROM a) SELECT n FROM b",
    "SELECT id, row_number() OVER (PARTITION BY severity ORDER BY id) AS rn FROM findings",
    "SELECT f.id, j.value FROM findings f, json_each(f.weaknesses) j",
    "SELECT count(*) FROM (SELECT 1 UNION ALL SELECT 2)",
])
def test_legitimate_cte_and_window_queries(seeded, sql):
    cols, rows = seeded.query_readonly(sql)
    assert cols and rows is not None


def test_cte_count_value(seeded):
    _, rows = seeded.query_readonly("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 10) SELECT count(*) FROM c")
    assert rows == [[10]]


@pytest.mark.parametrize("sql", [
    "SELECT count(*) FROM dbstat",
    "SELECT * FROM dbstat AS c",
    "WITH c AS (SELECT * FROM dbstat) SELECT count(*) FROM c",
    "SELECT count(*) FROM sqlite_master",
    "SELECT count(*) FROM sqlite_temp_master",
    "SELECT * FROM notes",
    "SELECT * FROM notes_content",
    "SELECT * FROM notes_config",
    "SELECT * FROM app_config",
])
def test_internal_and_virtual_tables_still_denied(seeded, sql):
    con = sqlite3.connect(seeded.path)
    con.executescript("CREATE VIRTUAL TABLE IF NOT EXISTS notes USING fts5(body); INSERT INTO notes VALUES ('secret');"
                      "CREATE TABLE IF NOT EXISTS app_config(k, v);")
    con.close()
    with pytest.raises(UnsafeQuery):
        seeded.query_readonly(sql)


# ---------------------------------------------------------------- Host allowlist + CSRF


def test_foreign_host_is_421(seeded, monkeypatch):
    monkeypatch.delenv("NIMBUS_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(seeded.path, bind_host="127.0.0.1"), base_url="http://127.0.0.1:8765")
    assert client.get("/api/summary").status_code == 200
    for host in ("evil.example", "evil.example:8765", "127.0.0.1.nip.io", "testserver", ""):
        r = client.get("/api/summary", headers={"Host": host})
        assert r.status_code == 421, (host, r.status_code)
    for host in ("localhost:8765", "LOCALHOST", "127.0.0.1", "[::1]:8765"):
        assert client.get("/api/summary", headers={"Host": host}).status_code == 200, host


def test_allowed_hosts_flag_and_env(seeded, monkeypatch):
    monkeypatch.setenv("NIMBUS_ALLOWED_HOSTS", "dash.example, other.example:9000")
    client = TestClient(create_app(seeded.path, bind_host="10.0.0.5", allowed_hosts=["cli.example"]), base_url="http://10.0.0.5:8765")
    for host in ("10.0.0.5:8765", "dash.example", "other.example:1234", "cli.example:8765"):
        assert client.get("/api/summary", headers={"Host": host}).status_code == 200, host
    assert client.get("/api/summary", headers={"Host": "evil.example"}).status_code == 421


def test_unspecified_bind_host_is_not_a_host_name(seeded, monkeypatch):
    monkeypatch.delenv("NIMBUS_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app(seeded.path, bind_host="0.0.0.0"), base_url="http://localhost:8765")
    assert client.get("/api/summary", headers={"Host": "0.0.0.0:8765"}).status_code == 421


@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site", "Origin": "http://sub.localhost:8765"},
    {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", "Content-Type": "text/plain"},
])
def test_cross_site_post_is_403(seeded, headers):
    client = TestClient(create_app(seeded.path, bind_host="127.0.0.1"), base_url="http://127.0.0.1:8765")
    r = client.post("/api/query", content='{"sql": "SELECT 1"}', headers={"Content-Type": "application/json", **headers})
    assert r.status_code == 403, r.text


@pytest.mark.parametrize("headers", [
    {},
    {"Sec-Fetch-Site": "same-origin"},
    {"Sec-Fetch-Site": "none"},
    {"Origin": "http://127.0.0.1:8765"},
    {"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:8765"},
])
def test_same_origin_and_non_browser_post_allowed(seeded, headers):
    client = TestClient(create_app(seeded.path, bind_host="127.0.0.1"), base_url="http://127.0.0.1:8765")
    r = client.post("/api/query", json={"sql": "SELECT 1 AS one"}, headers=headers)
    assert r.status_code == 200, r.text


def test_store_unused_import_guard():
    assert Store  # keep the import used


def test_websocket_checks_host_and_origin(seeded):
    from starlette.websockets import WebSocketDisconnect

    client = TestClient(create_app(seeded.path, bind_host="127.0.0.1"), base_url="http://127.0.0.1:8765")
    # (Starlette's websocket test transport sends Host: testserver unless told otherwise.)
    for headers in ({"Host": "evil.example"}, {"Host": "127.0.0.1:8765", "Origin": "https://evil.example"}):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws", headers=headers) as ws:
                ws.receive_text()
    with client.websocket_connect("/ws", headers={"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"}):
        pass


def test_ipv6_bind_host(seeded, monkeypatch):
    monkeypatch.delenv("NIMBUS_ALLOWED_HOSTS", raising=False)
    from nimbus.server import allowed_host_names

    assert "::" not in allowed_host_names("::") and "0.0.0.0" not in allowed_host_names("0.0.0.0")
    assert "fd00::5" in allowed_host_names("fd00::5") and "fd00::5" in allowed_host_names("[fd00::5]")
