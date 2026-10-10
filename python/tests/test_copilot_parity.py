"""Copilot <-> engine parity on the lab estate (delta r2 shortfall #8 / done-criterion 8).

Builds the Go binary, ingests lab/local/out/estate.findings.json and checks that the copilot's
exposure verdict for every resource ``paths`` lists as an exposure (or suppressed exposure)
equals the CLI's, and that "top attack paths" returns one row per path Issue. Skips only when
the Go toolchain or the lab files are absent; a failing `go build` fails."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nimbus.ai.evals import run_parity

ROOT = Path(__file__).resolve().parents[2]
LAB_FINDINGS = ROOT / "lab" / "local" / "out" / "estate.findings.json"
LAB_CFG = ROOT / "lab" / "local" / "cloud-posture.lab.yaml"


def _go() -> str | None:
    return shutil.which("go") or next((p for p in ("/opt/homebrew/bin/go", "/usr/local/go/bin/go") if os.path.exists(p)), None)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    go = _go()
    if not go or not LAB_FINDINGS.exists() or not LAB_CFG.exists():
        pytest.skip("Go toolchain or lab estate not available")
    d = tmp_path_factory.mktemp("parity")
    exe, db = d / "cloud-posture", d / "lab.db"
    env = {**os.environ, "CLOUD_POSTURE_NO_NETWORK": "1", "GOFLAGS": os.environ.get("GOFLAGS", "")}
    b = subprocess.run([go, "build", "-o", str(exe), "./cmd/cloud-posture"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=600)
    if b.returncode != 0:  # Verification 6: a broken build must fail the parity test, not skip it
        pytest.fail(f"go build failed: {b.stderr[-400:]}")
    i = subprocess.run([str(exe), "-c", str(LAB_CFG), "--db", str(db), "-q", "ingest", str(LAB_FINDINGS), "--source", "native"],
                       env=env, capture_output=True, text=True, timeout=300)
    assert i.returncode == 0, i.stderr[-800:]
    return exe, db, env


def test_copilot_agrees_with_paths_on_the_lab(lab, monkeypatch):
    exe, db, env = lab
    monkeypatch.setenv("CLOUD_POSTURE_NO_NETWORK", "1")
    rep = run_parity(str(db), str(exe), config=str(LAB_CFG))
    print(f"parity: {rep['agreeing']}/{rep['checked']} exposure verdicts agree; "
          f"graph.Verdict status {rep['status_agreeing']}/{rep['status_checked']}, label {rep['label_agreeing']}; "
          f"path Issues cli={rep['cli_path_issues']} copilot={rep['copilot_path_issues']}")
    assert rep["checked"] >= 25, rep  # distinct resources across exposures + suppressed + path entries
    assert rep["disagreements"] == [], rep["disagreements"]
    # graph.Verdict parity: same status, and the copilot prints the engine's Label
    assert rep["status_checked"] >= 20 and rep["status_agreeing"] == rep["status_checked"], rep["status_disagreements"]
    assert rep["label_agreeing"] == rep["status_checked"], rep["status_disagreements"]
    assert rep["copilot_path_issues"] == rep["cli_path_issues"]
    # the shortfall's named cases
    v = rep["copilot"]
    assert v["nimbus-lab-ledger"] == "blocked"
    assert v["nimbus-lab-shared-reports"] == "not_exposed"
    assert v["nimbus-lab-customer-pii"] == "exposed"


def test_who_can_reads_the_lab_through_go(lab, monkeypatch):
    exe, db, env = lab
    from nimbus.ai.copilot import SecurityCopilot

    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    res = SecurityCopilot(str(db), use_llm=False).ask("who can read nimbus-lab-customer-pii")
    assert res["intent"] == "who_can", res
    cli = subprocess.run([str(exe), "--db", str(db), "-q", "who-can", "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii", "--json"],
                         env=env, capture_output=True, text=True, timeout=120)
    import json
    want = {r["principal"] for r in json.loads(cli.stdout or "[]")}
    got = {r[res["columns"].index("principal")] for r in res["rows"]}
    assert want and got == want


def test_copilot_matches_engine_data_without_overlay(lab, monkeypatch):
    """Verify-5: the parity above is circular for status/label (the overlay copies the CLI). Here
    the overlay is off: the copilot's own SQL over the stored graph / Issues must match
    graph.Verdict per node and the stored path Issues by id, band and score."""
    from nimbus.ai.evals import run_engine_parity

    exe, db, env = lab
    monkeypatch.setenv("CLOUD_POSTURE_NO_NETWORK", "1")
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    rep = run_engine_parity(str(db), str(exe), config=str(LAB_CFG))
    print(f"engine parity: verdicts {rep['verdicts_checked'] - len(rep['verdict_disagreements'])}/{rep['verdicts_checked']}; "
          f"path Issues engine={rep['engine_path_issues']} copilot={rep['copilot_path_issues']}")
    assert rep["overlay_columns"] == [], "overlay was on: the comparison would be circular"
    assert rep["verdicts_checked"] >= 25, rep
    assert rep["verdict_disagreements"] == [], rep["verdict_disagreements"]
    assert rep["engine_path_issues"] >= 15
    assert rep["missing_issues"] == [] and rep["extra_issues"] == [], rep
    assert rep["issue_field_disagreements"] == [], rep["issue_field_disagreements"]


def test_unknown_reachability_is_never_read_as_exposed():
    """Verification 6: the engine's "unknown" must not accept a copilot "exposed"."""
    from nimbus.ai.evals import _VERDICT_STATUS

    assert _VERDICT_STATUS["unknown"] == {"unknown"}
    assert "exposed" not in _VERDICT_STATUS["blocked"]


def test_engine_parity_catches_a_tampered_issue_score(lab, monkeypatch, tmp_path):
    """Verification 6: the path-Issue half compares the engine's analysis (``paths --format json
    --grouped``) with the copilot's rows, so a score changed in the issues table is caught (both
    sides used to read the same rows)."""
    import shutil as _sh
    import sqlite3

    from nimbus.ai.evals import run_engine_parity

    exe, db, env = lab
    copy = tmp_path / "tampered.db"
    _sh.copy(db, copy)
    con = sqlite3.connect(copy)
    iid = con.execute("SELECT id FROM issues WHERE kind = 'path' ORDER BY score DESC LIMIT 1").fetchone()[0]
    con.execute("UPDATE issues SET score = 1.0, band = 'Low' WHERE id = ?", (iid,))
    con.commit()
    con.close()
    monkeypatch.setenv("CLOUD_POSTURE_NO_NETWORK", "1")
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    rep = run_engine_parity(str(copy), str(exe), config=str(LAB_CFG))
    assert any(d[0] == iid for d in rep["issue_field_disagreements"]), rep
