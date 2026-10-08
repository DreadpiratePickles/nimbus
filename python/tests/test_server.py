import os
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from nimbus.server import create_app  # noqa: E402


@pytest.fixture
def client(seeded, monkeypatch):
    monkeypatch.setenv("NIMBUS_WS_POLL", "0.05")
    return TestClient(create_app(seeded.path))


def test_summary_findings(client, seeded):
    s = client.get("/api/summary").json()
    assert s["total"] == 12 and s["failed"] == 11 and s["attack_paths"] == 2 and s["last_scan"]["scan_id"] == "scan-1"
    fs = client.get("/api/findings", params={"severity": "CRITICAL"}).json()
    assert [f["canonical_id"] for f in fs] == ["RDS_PUBLIC"]
    assert len(client.get("/api/findings", params={"provider": "aws", "status": "FAIL", "limit": 3}).json()) == 3
    assert client.get("/api/findings", params={"canonical_id": "IAM_USER_NO_MFA", "status": "PASS"}).json()[0]["resource"]["name"] == "bob"
    assert len(client.get("/api/findings", params={"account": "prod-cluster"}).json()) == 1
    fid = fs[0]["id"]
    one = client.get(f"/api/findings/{fid}").json()
    assert one["id"] == fid and one["attack_paths"][0]["id"] == "ap-db"
    assert client.get("/api/findings/nope").status_code == 404


def test_paths_graph_risk(client):
    paths = client.get("/api/attack-paths").json()
    assert [p["id"] for p in paths] == ["ap-db", "ap-admin"]
    g = client.get("/api/graph").json()
    assert {"nodes", "edges"} == set(g)
    n = {x["data"]["id"]: x["data"] for x in g["nodes"]}
    assert n["internet"]["class"] == "internet" and n["i-0abc"]["label"] == "web-1"
    assert {"source", "target", "kind"} <= set(g["edges"][0]["data"])
    top = client.get("/api/risk/top", params={"n": 2}).json()
    assert len(top) == 2 and top[0]["canonical_id"] == "RDS_PUBLIC"


def test_compliance_reports_queries(client):
    c = client.get("/api/compliance/soc2").json()
    assert c["framework"]["key"] == "soc2" and c["failing"] > 0
    r = client.get("/api/reports/soc2.html")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"] and f"{c['score_percent']:.1f}%" in r.text
    assert client.get("/api/reports/cis_aws.md").text.startswith("# CIS")
    pdf = client.get("/api/reports/pci_dss.pdf")
    assert pdf.status_code in (200, 501)
    if pdf.status_code == 200:
        assert pdf.content[:4] == b"%PDF"
    assert client.get("/api/reports/soc2.exe").status_code == 400
    qs = client.get("/api/queries").json()
    assert any(q["name"] == "top_risky_accounts" for q in qs)
    assert client.post("/api/query", json={"sql": "SELECT COUNT(*) AS n FROM findings"}).json() == {"columns": ["n"], "rows": [[12]]}
    assert client.post("/api/query", json={"sql": "DELETE FROM findings"}).status_code == 400
    assert client.post("/api/query", json={"sql": "SELECT * FROM nope"}).status_code == 400
    assert client.get("/api/queries/public_buckets_with_pii").json()["rows"]


def test_ai_endpoints(client, seeded):
    res = client.post("/api/copilot", json={"question": "users without MFA"}).json()
    assert res["intent"] == "no_mfa" and res["rows"]
    fid = seeded.findings(canonical_id="S3_PUBLIC_BUCKET")[0].id
    ex = client.post("/api/explain", json={"finding_id": fid}).json()
    assert ex["explanation"].startswith("An attacker could")
    fx = client.post("/api/fix", json={"finding_id": fid, "format": "terraform"}).json()
    assert "customer-pii" in fx["code"] and fx["problems"] == []
    assert client.post("/api/fix", json={"finding_id": fid, "format": "pulumi"}).status_code == 400
    assert client.post("/api/explain", json={"finding_id": "nope"}).status_code == 404
    inv = client.post("/api/investigate", json={"finding_id": fid}).json()
    assert "blast_radius" in inv


def test_alerts_endpoint(client, seeded, monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    fid = seeded.findings()[0].id
    res = client.post("/api/alerts", json={"finding_ids": [fid, "missing"], "targets": ["slack"]}).json()
    assert res["results"][0]["skipped"] and res["missing"] == ["missing"]
    assert client.post("/api/alerts", json={"finding_ids": [fid], "targets": ["carrier-pigeon"]}).status_code == 400


def test_index_pages(client, tmp_path, monkeypatch):
    r = client.get("/")
    assert r.status_code == 200 and "Top risks" in r.text and "RDS_PUBLIC" in r.text
    page = tmp_path / "dash.html"
    page.write_text("<html>custom dashboard</html>")
    monkeypatch.setenv("CLOUD_POSTURE_DASHBOARD_HTML", str(page))
    assert client.get("/").text == "<html>custom dashboard</html>"


def test_websocket_pushes_on_db_change(client, seeded):
    with client.websocket_connect("/ws") as ws:
        time.sleep(0.15)
        future = time.time() + 5
        os.utime(seeded.path, (future, future))
        msg = ws.receive_json()
        assert msg == {"type": "findings_updated", "scan_id": "scan-1"}
