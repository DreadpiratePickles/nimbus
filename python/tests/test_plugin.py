import json
import subprocess
import sys
from pathlib import Path

import httpx

import nimbus
from nimbus import plugin as P

ROOT = Path(__file__).resolve().parents[1]
OKTA = ROOT / "nimbus" / "plugins" / "example_okta.py"


def okta_transport() -> httpx.MockTransport:
    users_p1 = [{"id": "u1", "status": "ACTIVE", "profile": {"login": "admin@acme.com"}},
                {"id": "u2", "status": "ACTIVE", "profile": {"login": "dev@acme.com"}}]
    users_p2 = [{"id": "u3", "status": "ACTIVE", "profile": {"login": "secure-admin@acme.com"}}]
    roles = {"u1": [{"type": "SUPER_ADMIN"}], "u2": [], "u3": [{"type": "ORG_ADMIN"}]}
    factors = {"u1": [{"factorType": "push", "status": "PENDING_ACTIVATION"}], "u3": [{"factorType": "webauthn", "status": "ACTIVE"}]}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["Authorization"] == "SSWS test-token"
        path = req.url.path
        if path == "/api/v1/users":
            if req.url.params.get("after") == "u2":
                return httpx.Response(200, json=users_p2)
            return httpx.Response(200, json=users_p1, headers={"Link": '<https://acme.okta.com/api/v1/users?after=u2>; rel="next"'})
        uid = path.split("/")[4]
        if path.endswith("/roles"):
            return httpx.Response(200, json=roles[uid])
        if path.endswith("/factors"):
            return httpx.Response(200, json=factors.get(uid, []))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_okta_plugin_with_mock_transport():
    client = httpx.Client(transport=okta_transport(), base_url="https://acme.okta.com", headers={"Authorization": "SSWS test-token"})
    fs = P.run(OKTA, client=client)
    by = {f.resource.name: f for f in fs}
    assert set(by) == {"admin@acme.com", "secure-admin@acme.com"}
    bad = by["admin@acme.com"]
    assert bad.status.value == "FAIL" and by["secure-admin@acme.com"].status.value == "PASS"
    assert bad.source == "okta-plugin" and bad.check_id == "okta_admin_user_mfa_enrolled"
    assert bad.canonical_id == "OKTA_ADMIN_NO_MFA" and bad.provider == "okta" and bad.account == "acme.okta.com"
    assert bad.severity.value == "CRITICAL" and bad.weaknesses == ["NO_MFA", "OVERPRIVILEGED_IDENTITY"]
    assert bad.resource.type == "okta_user" and bad.id == bad.fingerprint()
    assert bad.compliance["soc2"] == ["CC6.1"]


def test_okta_plugin_skips_without_env(monkeypatch, capsys):
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    assert P.run(OKTA) == []
    assert "skipped" in capsys.readouterr().err


def test_decorator_results_errors_and_cli(tmp_path):
    src = tmp_path / "myplugin.py"
    src.write_text('''
import nimbus

@nimbus.plugin.check("acme_bucket_owner", "Buckets have an owner tag", severity="low", provider="aws",
                     weaknesses=[], compliance={"soc2": ["CC6.1"]}, resource_type="aws_s3_bucket")
def owner(region="us-east-1"):
    yield {"resource_id": "arn:aws:s3:::b1", "account": "1", "region": region, "passed": False, "message": "no owner"}
    yield {"resource_id": "arn:aws:s3:::b2", "account": "1", "region": region, "status": "PASS"}

@nimbus.plugin.check("acme_boom", "Always breaks", provider="aws")
def boom():
    raise ValueError("kaput")

@nimbus.plugin.check("acme_single", "Returns one", provider="gcp")
def single():
    return nimbus.models.Finding(resource={"id": "x"}, account="p", severity="HIGH")
''')
    fs = P.run(src, region="eu-west-1")
    by = {f.check_id: f for f in fs if f.resource.id != "arn:aws:s3:::b2"}
    assert by["acme_bucket_owner"].status.value == "FAIL" and by["acme_bucket_owner"].description == "no owner"
    assert by["acme_bucket_owner"].region == "eu-west-1" and by["acme_bucket_owner"].canonical_id == "PLUGIN:acme_bucket_owner"
    assert by["acme_bucket_owner"].severity.value == "LOW"
    assert by["acme_boom"].status.value == "ERROR" and "kaput" in by["acme_boom"].description
    assert by["acme_single"].severity.value == "HIGH" and by["acme_single"].provider == "gcp"
    assert nimbus.plugin.REGISTRY["acme_boom"].title == "Always breaks"

    out = subprocess.run([sys.executable, "-m", "nimbus.plugin", str(src), "--jsonl"], capture_output=True, text=True, cwd=ROOT, check=True)
    lines = [json.loads(line) for line in out.stdout.splitlines()]
    assert len(lines) == 4 and {"id", "source", "check_id", "canonical_id", "first_seen", "last_seen"} <= set(lines[0])
    assert "RuntimeWarning" not in out.stderr
    out = subprocess.run([sys.executable, "-m", "nimbus.plugin", str(src), "--json"], capture_output=True, text=True, cwd=ROOT, check=True)
    assert len(json.loads(out.stdout)) == 4
