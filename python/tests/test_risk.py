import json
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from nimbus.risk import (NOT_SCORED, Context, Weights, compliance_weight_for, features_for, load_go_risk, prioritize,
                         prioritize_store, score, score_finding)

from .conftest import sample_findings, sample_graph, sample_paths

# Go's ranking of the conftest estate (internal/risk TestPythonGolden keeps it in sync with the Go formula).
GO_RISK = Path(__file__).parent / "fixtures" / "go_risk.json"


@pytest.fixture
def go_records() -> dict:
    return load_go_risk(GO_RISK)


def test_ranking_order_and_reasons(seeded):
    res = prioritize_store(seeded, top=50, risk=GO_RISK)
    ids = [r.finding.canonical_id for r in res]
    assert "IAM_USER_NO_MFA" in ids and len(res) == 11  # PASS finding excluded
    # internet-exposed, sensitive, production DB on an attack path ranks first
    assert ids[0] == "RDS_PUBLIC"
    top = res[0].to_dict()
    assert set(top) >= {"finding_id", "risk_score", "band", "score_version", "explanation", "severity", "canonical_id", "resource", "reasons"}
    assert top["risk_score"] == 10.0 and top["band"] == "Critical" and top["score_version"] == "2.4.0"
    joined = " | ".join(top["reasons"])
    assert "attack path" in joined and "internet exposed" in joined and "sensitive" in joined
    assert "changed in the last 24h" in joined
    # dev, owned, LOW finding ranks last
    assert ids[-1] == "TRIVY:LOW_THING"
    scores = [r.risk_score for r in res]
    assert scores == sorted(scores, reverse=True)


def test_python_reports_go_numbers_verbatim(seeded, go_records):
    """No second formula: every score, band, reason and version is Go's, byte for byte."""
    for r in prioritize_store(seeded, top=0, risk=GO_RISK):
        rec = go_records[r.finding.id]
        assert r.risk_score == rec["risk_score"] and r.band == rec["band"]
        assert r.reasons == rec["reasons"] and r.score_version == rec["score_version"]
        assert r.explanation == rec["explanation"]


def test_band_always_matches_score(seeded):
    """Defect 19: a score must never be shown with another formula's band."""
    def band(s):
        return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 5 else "Low"
    for r in prioritize_store(seeded, top=0, risk=GO_RISK):
        assert r.band == band(r.risk_score)


def test_unscored_without_go_output(seeded, monkeypatch):
    monkeypatch.delenv("NIMBUS_RISK_JSON", raising=False)
    res = prioritize_store(seeded, top=0)
    assert res and all(r.risk_score is None and r.band == NOT_SCORED for r in res)
    assert res[0].finding.canonical_id == "RDS_PUBLIC"  # unscored fall back to severity order only
    assert NOT_SCORED in res[0].reasons[0]


def test_risk_json_beside_db_and_env(seeded, tmp_path, monkeypatch):
    monkeypatch.delenv("NIMBUS_RISK_JSON", raising=False)
    per_db = Path(seeded.path + ".risk.json")  # what Go writes: <db>.risk.json
    shutil.copy(GO_RISK, per_db)
    assert prioritize_store(seeded, top=1)[0].risk_score == 10.0
    per_db.unlink()
    monkeypatch.setenv("NIMBUS_RISK_JSON", str(GO_RISK))
    assert prioritize_store(seeded, top=1)[0].band == "Critical"


def test_risk_json_is_per_database(seeded, monkeypatch):
    """V2 defect 10: another DB's ranking in the same directory is never read for this one."""
    monkeypatch.delenv("NIMBUS_RISK_JSON", raising=False)
    shutil.copy(GO_RISK, Path(seeded.path).parent / "other.db.risk.json")
    shutil.copy(GO_RISK, Path(seeded.path).parent / "risk.json")  # legacy shared file: ambiguous, ignored
    res = prioritize_store(seeded, top=1)
    assert res[0].risk_score is None and res[0].band == NOT_SCORED


def test_context_changes_score():
    fs = sample_findings()
    imds = next(f for f in fs if f.canonical_id == "EC2_IMDSV1")
    bare = score_finding(imds, Context())
    assert bare.risk_score is None and bare.band == NOT_SCORED
    ctx = Context(sample_graph(), sample_paths(fs), risk=GO_RISK)
    rich = score_finding(imds, ctx)
    assert rich.risk_score == 9.9 and rich.band == "Critical"  # Go 2.2.0 (saturation bound), read from go_risk.json
    assert rich.features["exposure"] == 1.4  # Go: internet edge without width data -> wide
    assert rich.features["identity"] == 1.1  # Go: IMDSv1 credential vector; the web role it runs as is not admin
    assert any("attack path" in r for r in rich.reasons)
    assert rich.attack_paths == ["ap-admin"]


def test_score_reproduces_go_from_factors(go_records):
    """docs/scoring.md 'by hand': base × Π multipliers == Go's score for every fixture finding."""
    fs = sample_findings()
    ctx = Context(sample_graph(), sample_paths(fs), risk=GO_RISK)
    checked = 0
    for f in fs:
        if f.id not in go_records:
            continue
        feats, _, _ = features_for(f, ctx)
        assert score(feats) == go_records[f.id]["risk_score"]
        assert abs(feats["base"] * __import__("math").prod(v for k, v in feats.items() if k != "base") - go_records[f.id]["risk_score"]) <= 0.01
        checked += 1
    assert checked == 11
    assert score({}) is None


def test_linear_model_json(tmp_path):
    """Custom Python weights are ignored (warned) — they can no longer change a Go score."""
    fs = sample_findings()
    model = tmp_path / "model.json"
    model.write_text(json.dumps({"intercept": -1.0, "coefficients": {"severity": 0.0, "exposure": 0.0, "identity_risk": 10.0}}))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        w = Weights.load(str(model))
    assert any("ignored" in str(c.message) for c in caught)
    with_model = prioritize(fs, sample_graph(), sample_paths(fs), weights=w, risk=GO_RISK)
    without = prioritize(fs, sample_graph(), sample_paths(fs), weights=Weights.default(), risk=GO_RISK)
    assert [(r.finding.id, r.risk_score) for r in with_model] == [(r.finding.id, r.risk_score) for r in without]


def test_cli_contract(seeded):
    root = Path(__file__).resolve().parents[1]
    # without Go output the Go caller gets [] and keeps its own ranking (never a Python number)
    out = subprocess.run([sys.executable, "-m", "nimbus.risk", "--db", seeded.path, "--top", "3", "--json"],
                         capture_output=True, text=True, cwd=root, check=True, env={"PATH": "", "NIMBUS_OFFLINE": "1"})
    assert json.loads(out.stdout) == []
    # an implicitly discovered risk.json is not echoed to the Go caller either (it would rescale it)
    shutil.copy(GO_RISK, Path(seeded.path + ".risk.json"))
    out = subprocess.run([sys.executable, "-m", "nimbus.risk", "--db", seeded.path, "--top", "3", "--json"],
                         capture_output=True, text=True, cwd=root, check=True, env={"PATH": "", "NIMBUS_OFFLINE": "1"})
    assert json.loads(out.stdout) == []
    out = subprocess.run([sys.executable, "-m", "nimbus.risk", "--db", seeded.path, "--top", "3", "--json", "--risk-json", str(GO_RISK)],
                         capture_output=True, text=True, cwd=root, check=True)
    data = json.loads(out.stdout)
    assert len(data) == 3
    assert all({"finding_id", "risk_score", "band", "score_version", "severity", "canonical_id", "resource", "reasons"} <= set(d) for d in data)
    assert isinstance(data[0]["resource"], str) and data[0]["score_version"] == "2.4.0"


def test_builtin_weights_mirror_json():
    from nimbus.risk import _BUILTIN_WEIGHTS

    w = Weights.default()
    assert w.score_version == _BUILTIN_WEIGHTS["score_version"] == "2.4.0"


def test_compliance_weight_mirrors_go(go_records):
    """compliance_weight_for is a pure utility returning Go's published compliance_scope multiplier."""
    assert compliance_weight_for("PCI_DSS") == 1.0 and compliance_weight_for("gdpr") == 1.0 and compliance_weight_for("cis_aws") == 1.0  # 2.1.0
    for f in sample_findings():
        rec = go_records.get(f.id)
        if not rec:
            continue
        go = next(x["multiplier"] for x in rec["explanation"]["factors"] if x["name"] == "compliance_scope")
        assert max((compliance_weight_for(fw) for fw, c in f.compliance.items() if c), default=1.0) == go
