import yaml

from nimbus.ai import llm
from nimbus.ai.explain import explain_attack_path, explain_finding
from nimbus.ai.fix import generate_fix, stub_fix, validate_fix
from nimbus.models import AttackPath

from .conftest import F, sample_findings, sample_paths


def test_offline_model_default(monkeypatch):
    monkeypatch.delenv("NIMBUS_MODEL", raising=False)
    assert llm.model_name() == "claude-opus-5-5"
    monkeypatch.setenv("NIMBUS_MODEL", "x")
    assert llm.model_name() == "x"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert not llm.llm_available()  # NIMBUS_OFFLINE=1 from conftest
    assert llm.complete("s", "p") is None


def test_explain_offline():
    fs = sample_findings()
    f = next(x for x in fs if x.canonical_id == "S3_PUBLIC_BUCKET")
    res = explain_finding(f)
    assert res["mode"] == "offline" and res["explanation"].startswith("An attacker could read")
    assert "customer-pii" in res["explanation"]
    p = AttackPath.model_validate(sample_paths(fs)[1])
    txt = explain_attack_path(p)["explanation"]
    assert txt.startswith("An attacker could") and "IMDSv1" in txt and "Full cloud account compromise" in txt
    assert "confirm" in txt  # same_account caveat


def test_fix_templates_and_validation(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    fs = sample_findings()
    s3 = next(x for x in fs if x.canonical_id == "S3_PUBLIC_BUCKET")
    res = generate_fix(s3, "terraform")
    assert res["mode"] == "template" and res["problems"] == []
    assert "aws_s3_bucket_public_access_block" in res["code"] and "customer-pii" in res["code"]
    pod = next(x for x in fs if x.canonical_id == "K8S_PRIVILEGED_CONTAINER")
    res = generate_fix(pod, "k8s")
    assert res["format"] == "kubernetes" and res["problems"] == []
    assert yaml.safe_load(res["code"].split("\n", 3)[-1])["spec"]["containers"][0]["securityContext"]["privileged"] is False
    for fmt in ("terraform", "cloudformation", "bicep", "kubernetes"):
        other = F(check_id="x", canonical_id="GH_BRANCH_UNPROTECTED", resource={"id": "org/repo", "name": "org/repo"})
        out = generate_fix(other, fmt)
        assert out["mode"] == "stub" and out["problems"] == [], (fmt, out["problems"])
    assert validate_fix('resource "a" "b" {', "terraform") == ["unbalanced braces"]
    assert any("YAML" in p for p in validate_fix("a: [", "cloudformation"))
    assert validate_fix("Resources:\n  X:\n    Type: !Ref Foo\n", "cloudformation", "X") == []
    assert "does not mention" in validate_fix(stub_fix(s3, "bicep"), "bicep", "other-name")[0]


def test_llm_path_with_fake_client(monkeypatch, seeded):
    from types import SimpleNamespace

    from nimbus.ai.copilot import SecurityCopilot

    calls = []

    class FakeMessages:
        def create(self, **kw):
            calls.append(kw)
            text = ("```sql\nSELECT COUNT(*) AS n FROM findings WHERE status = 'FAIL'\n```" if "Schema:" in kw["messages"][0]["content"]
                    else "There are 11 open findings.")
            return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=text)])

    monkeypatch.delenv("NIMBUS_OFFLINE", raising=False)
    monkeypatch.delenv("NIMBUS_MODEL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())))
    res = SecurityCopilot(seeded).ask("how many open findings?")
    assert res["mode"] == "llm" and res["rows"] == [[11]] and res["answer"] == "There are 11 open findings."
    assert calls[0]["model"] == "claude-opus-5-5" and calls[0]["fallbacks"] == "default"
    assert calls[0]["betas"] == ["server-side-fallback-2026-07-01"] and "thinking" not in calls[0]
    # unsafe model SQL is rejected, never executed
    monkeypatch.setattr(FakeMessages, "create", lambda self, **kw: SimpleNamespace(
        stop_reason="end_turn", content=[SimpleNamespace(type="text", text="```sql\nDROP TABLE findings\n```")]))
    res = SecurityCopilot(seeded).ask("drop everything")
    assert "rejected unsafe SQL" in res["error"] and len(seeded.findings()) == 12
