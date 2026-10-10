"""Copilot UX (competitive delta r3 #11): the copilot finds the Go binary without
CLOUD_POSTURE_BIN, says once and clearly where it looked when it cannot, folds its SQL under a
``Sources:`` block (``show_sql`` prints it), and the LLM agent can call who_can / verify_state."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys

import pytest

from nimbus.ai import copilot as cpmod
from nimbus.ai.copilot import SecurityCopilot, cloud_posture_bin, cloud_posture_bin_error
from nimbus.ai.guardrails import ALLOWED_TOOLS, ToolGate, TurnBudget


def _exe(path, out="[]"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\nimport json, sys\nprint({out!r})\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """No env var, an empty PATH, no package sibling, cwd without ./bin."""
    monkeypatch.delenv("CLOUD_POSTURE_BIN", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
    monkeypatch.setattr(cpmod, "_PACKAGE_ROOTS", [tmp_path / "no-repo"])
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return tmp_path


def test_bin_env_wins(isolated, monkeypatch):
    exe = _exe(isolated / "explicit" / "cloud-posture")
    _exe(isolated / "work" / "bin" / "cloud-posture")
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    assert cloud_posture_bin() == str(exe)


def test_bin_env_invalid_is_explicit_error(isolated, monkeypatch):
    _exe(isolated / "work" / "bin" / "cloud-posture")
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(isolated / "missing"))
    assert cloud_posture_bin() is None  # an explicit setting is never silently replaced
    msg = cloud_posture_bin_error()
    assert "CLOUD_POSTURE_BIN" in msg and "missing" in msg and msg.count("\n") == 0


def test_bin_on_path(isolated, monkeypatch):
    d = isolated / "pathdir"
    exe = _exe(d / "cloud-posture")
    monkeypatch.setenv("PATH", str(d))
    assert cloud_posture_bin() == str(exe)


def test_bin_sibling_of_package(isolated, monkeypatch):
    repo = isolated / "repo"
    exe = _exe(repo / "bin" / "cloud-posture")
    monkeypatch.setattr(cpmod, "_PACKAGE_ROOTS", [repo])
    assert cloud_posture_bin() == str(exe)


def test_bin_dot_bin(isolated):
    exe = _exe(isolated / "work" / "bin" / "cloud-posture")
    assert os.path.samefile(cloud_posture_bin(), exe)


def test_bin_missing_names_every_place_once(isolated):
    assert cloud_posture_bin() is None
    msg = cloud_posture_bin_error()
    for want in ("CLOUD_POSTURE_BIN", "PATH", "./bin"):
        assert want in msg, msg
    assert msg.count("not available") + msg.count("not found") == 1


def test_who_can_answer_states_the_error_once(isolated, seeded):
    cp = SecurityCopilot(seeded, use_llm=False)
    res = cp.ask("who can s3:GetObject on arn:aws:s3:::b1?")
    assert res["intent"] == "who_can"
    assert res["answer"].count("not found") + res["answer"].count("not available") == 1, res["answer"]


def test_sql_folded_under_sources(seeded):
    cp = SecurityCopilot(seeded, use_llm=False)
    res = cp.ask("public buckets")
    assert res["sql"] and "Sources:" in res["answer"]
    assert res["sql"].splitlines()[0] not in res["answer"], "SQL printed in the answer without show_sql"
    assert "--show-sql" in res["answer"]
    assert res["citations"]["queries"] == [res["sql"]]
    cp2 = SecurityCopilot(seeded, use_llm=False, show_sql=True)
    res2 = cp2.ask("public buckets")
    assert res2["answer"].count(res2["sql"].splitlines()[0]) == 1, "show_sql prints the SQL exactly once"


def test_agent_tools_include_who_can_and_verify_state():
    assert "who_can" in ALLOWED_TOOLS and "verify_state" in ALLOWED_TOOLS
    assert "who_can" in cpmod.AGENT_SYSTEM and "verify_state" in cpmod.AGENT_SYSTEM


def test_agent_verify_state_reads_issue_and_history(seeded, tmp_path):
    con = sqlite3.connect(seeded.path)
    con.execute("CREATE TABLE IF NOT EXISTS issues (id TEXT PRIMARY KEY, kind TEXT, state TEXT, title TEXT, band TEXT, score REAL, provider TEXT, account TEXT)")
    con.execute("INSERT INTO issues VALUES ('iss-1', 'path', 'pending_verification', 'Internet → admin', 'High', 7.0, 'aws', '111111111111')")
    con.execute("CREATE TABLE IF NOT EXISTS issue_verifications (issue_id TEXT, at TEXT, result TEXT, verified_by TEXT, reads INTEGER, confirmations INTEGER, required INTEGER, reason TEXT, evidence TEXT)")
    con.execute("INSERT INTO issue_verifications VALUES ('iss-1', '2026-10-10T00:00:00Z', 'open', 'rescan', 1, 0, 2, 'path survives', '[]')")
    con.commit()
    con.close()
    cp = SecurityCopilot(seeded, use_llm=True)
    gate = ToolGate(cp, TurnBudget())
    res = gate.call("verify_state", {"issue_id": "iss-1"})
    assert res["state"] == "pending_verification" and res["verifications"][0]["result"] == "open"
    assert res["command"] == "cloud-posture verify iss-1" and res["mutates"] is False
    assert gate.call("verify_state", {"issue_id": "nope"}).get("error")
    out = cp._outbound_result(res)
    assert "111111111111" not in out


def test_agent_who_can_uses_the_binary(seeded, tmp_path, monkeypatch):
    rows = [{"principal": "arn:aws:iam::111111111111:role/admin", "holder": "arn:aws:iam::111111111111:role/admin",
             "decision": "allow", "statement": "s#0", "confidence": "verified", "because": "admin"}]
    exe = _exe(tmp_path / "cp" / "cloud-posture", json.dumps(rows))
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    cp = SecurityCopilot(seeded, use_llm=True)
    gate = ToolGate(cp, TurnBudget())
    res = gate.call("who_can", {"action": "s3:GetObject", "resource": "arn:aws:s3:::b1"})
    assert res["rows"] and res["columns"][0] == "principal"
    assert "111111111111" not in cp._outbound_result(res)


def test_cli_ask_prints_sql_once_only_with_show_sql(seeded):
    """delta r3 #11: `nimbus ask` (what `cloud-posture ask` runs) printed ~3 KB of SQL twice;
    now the SQL is folded under Sources: and printed exactly once with --show-sql."""
    from typer.testing import CliRunner

    from nimbus.cli import app

    r = CliRunner().invoke(app, ["ask", "public buckets", "--db", str(seeded.path)])
    assert r.exit_code == 0, r.output
    first = SecurityCopilot(seeded, use_llm=False).ask("public buckets")["sql"].splitlines()[0]
    assert first not in r.output and "Sources:" in r.output and "--show-sql" in r.output
    r2 = CliRunner().invoke(app, ["ask", "public buckets", "--db", str(seeded.path), "--show-sql"])
    assert r2.exit_code == 0, r2.output
    assert r2.output.count(first) == 1, r2.output


def test_overlay_never_runs_the_binary_on_a_python_db(seeded, tmp_path, monkeypatch):
    """The implicit verdict overlay must not hand a Python-built database to the Go binary: opening
    it migrates the schema and back-fills Issues, after which attack paths read from an Issues
    table with no path Issues (observed: 'attack paths to RDS' lost ap-db)."""
    marker = tmp_path / "ran"
    exe = tmp_path / "cp" / "cloud-posture"
    exe.parent.mkdir(parents=True)
    exe.write_text(f"#!{sys.executable}\nopen({str(marker)!r}, 'w').write('x')\nprint('{{}}')\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    cp = SecurityCopilot(seeded, use_llm=False)
    cp.ask("Which S3 buckets are public?")
    assert not marker.exists(), "verdict overlay ran the Go binary on a Python-built database"
    assert cp.ask("attack paths to RDS")["intent"] == "attack_paths"
