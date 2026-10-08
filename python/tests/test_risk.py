import json
import subprocess
import sys
from pathlib import Path

from nimbus.risk import Context, Weights, prioritize, prioritize_store, score_finding

from .conftest import sample_findings, sample_graph, sample_paths


def test_ranking_order_and_reasons(seeded):
    res = prioritize_store(seeded, top=50)
    ids = [r.finding.canonical_id for r in res]
    assert "IAM_USER_NO_MFA" in ids and len(res) == 11  # PASS finding excluded
    # internet-exposed, sensitive, production DB on an attack path ranks first
    assert ids[0] == "RDS_PUBLIC"
    top = res[0].to_dict()
    assert set(top) >= {"finding_id", "risk_score", "severity", "canonical_id", "resource", "reasons"}
    assert 0 < top["risk_score"] <= 100
    joined = " | ".join(top["reasons"])
    assert "attack path" in joined and "Internet-exposed" in joined and "sensitive" in joined
    assert "changed in the last 24h" in joined
    # dev, owned, LOW finding ranks last
    assert ids[-1] == "TRIVY:LOW_THING"
    scores = [r.risk_score for r in res]
    assert scores == sorted(scores, reverse=True)


def test_context_changes_score():
    fs = sample_findings()
    imds = next(f for f in fs if f.canonical_id == "EC2_IMDSV1")
    bare = score_finding(imds, Context())
    ctx = Context(sample_graph(), sample_paths(fs))
    rich = score_finding(imds, ctx)
    assert rich.risk_score > bare.risk_score
    assert rich.features["exposure"] == 1.0  # graph edge from internet
    assert any("CVE" in r for r in rich.reasons)
    assert rich.attack_paths == ["ap-admin"]


def test_linear_model_json(tmp_path):
    fs = sample_findings()
    model = tmp_path / "model.json"
    model.write_text(json.dumps({"intercept": -1.0, "coefficients": {"severity": 0.0, "exposure": 0.0, "identity_risk": 10.0}}))
    w = Weights.load(str(model))
    res = prioritize(fs, sample_graph(), sample_paths(fs), weights=w)
    assert res[0].features["identity_risk"] > 0


def test_cli_contract(seeded):
    root = Path(__file__).resolve().parents[1]
    out = subprocess.run([sys.executable, "-m", "nimbus.risk", "--db", seeded.path, "--top", "3", "--json"],
                         capture_output=True, text=True, cwd=root, check=True)
    data = json.loads(out.stdout)
    assert len(data) == 3
    assert all({"finding_id", "risk_score", "severity", "canonical_id", "resource", "reasons"} <= set(d) for d in data)
    assert isinstance(data[0]["resource"], str)


def test_builtin_weights_mirror_json():
    from nimbus.risk import _BUILTIN_WEIGHTS

    w = Weights.default()
    assert w.bias == _BUILTIN_WEIGHTS["bias"] and w.weights == _BUILTIN_WEIGHTS["weights"]
