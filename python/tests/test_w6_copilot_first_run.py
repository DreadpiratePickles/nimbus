"""W6-POLISH item 4 (competitive delta r4 #6 / N2 / N3): the copilot's first run from a fresh
clone never prints a Python traceback, and answers do not drown the terminal in 40-50 KB tables."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]


def _run_without(module: str, *args: str) -> subprocess.CompletedProcess:
    """`python -m nimbus <args>` with `module` made unimportable (a fresh clone without pip install)."""
    code = (f"import sys; sys.modules[{module!r}] = None; import runpy; "
            "sys.argv = ['nimbus'] + sys.argv[1:]; runpy.run_module('nimbus', run_name='__main__')")
    env = dict(os.environ, PYTHONPATH=str(PKG_ROOT))
    return subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, env=env, timeout=60)


def test_missing_dependency_prints_install_line_not_traceback(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-key")  # W7 r5 #12: [ai] is requested only with a key
    r = _run_without("typer", "ask", "--", "who can read pii")
    assert r.returncode != 0
    assert "Traceback" not in r.stderr + r.stdout, r.stderr
    assert "typer" in r.stderr and 'pip install -e "' in r.stderr and '[ai]"' in r.stderr, r.stderr


def test_ask_table_capped_unless_full():
    from nimbus.cli import _ask_table

    cols = ["principal", "decision", "because"]
    rows = [[f"arn:aws:iam::111111111111:role/r{i}", "allow", "x" * 300] for i in range(60)]
    short = _ask_table(cols, rows, full=False)
    body = short.rsplit("\n", 2)[0]
    assert len(body.encode()) <= 2048 + 200, len(body)
    assert "--full" in short and "60" in short
    assert short.count("arn:aws:iam::111111111111:role/r") <= 20
    full = _ask_table(cols, rows, full=True)
    assert full.count("arn:aws:iam::111111111111:role/r") == 60
    assert "--full" not in full


def test_cli_ask_has_full_flag(seeded):
    from typer.testing import CliRunner

    from nimbus.cli import app

    r = CliRunner().invoke(app, ["ask", "public buckets", "--db", str(seeded.path), "--full"])
    assert r.exit_code == 0, r.output


def test_single_blocked_resource_answer_names_it():
    """r4 AI1: "is the ledger exposed?" opened with the blanket "Nothing here is exposed to the
    internet." — the answer names the resource it is about."""
    from nimbus.ai.copilot import SecurityCopilot

    cols = ["resource_name", "verdict", "reason", "label"]
    one = SecurityCopilot._summarize_exposure(cols, [["nimbus-lab-ledger", "blocked", "route table has no IGW route", ""]])
    assert one.startswith("nimbus-lab-ledger is not exposed to the internet."), one
    assert "Nothing here" not in one
    two = SecurityCopilot._summarize_exposure(cols, [["a", "blocked", "x", ""], ["b", "not_exposed", "y", ""]])
    assert two.startswith("None of these 2 resources is exposed to the internet."), two
