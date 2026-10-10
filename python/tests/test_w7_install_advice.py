"""W7-POLISH r5 #12: until a PyPI release exists (the release flips nimbus.cli.PYPI_PUBLISHED), the
copilot's install hint is the from-source command; [ai] (the anthropic SDK) is requested only when
an API key is configured — the offline copilot runs on the base package."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]


def _run_without_typer(env_extra):
    code = ("import sys; sys.modules['typer'] = None; import runpy; "
            "sys.argv = ['nimbus', 'ask', '--', 'q']; runpy.run_module('nimbus', run_name='__main__')")
    env = dict(os.environ, PYTHONPATH=str(PKG_ROOT))
    env.pop("ANTHROPIC_API_KEY", None)
    env.update(env_extra)
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)


def test_checkout_hint_asks_for_ai_only_with_a_key():
    r = _run_without_typer({})
    assert f'pip install -e "{PKG_ROOT}"' in r.stderr and "[ai]" not in r.stderr, r.stderr
    r = _run_without_typer({"ANTHROPIC_API_KEY": "sk-test-not-a-key"})
    assert f'pip install -e "{PKG_ROOT}[ai]"' in r.stderr, r.stderr


def test_install_target_without_a_checkout(monkeypatch):
    import nimbus.cli as cli

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(cli, "PYPI_PUBLISHED", False)
    t = cli._install_target(checkout=None)
    assert "git+https://github.com/DreadpiratePickles/nimbus" in t and "#subdirectory=python" in t and "[ai]" not in t
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-key")
    assert cli._install_target(checkout=None).startswith('"nimbus-cspm[ai] @ git+https://')
    monkeypatch.setattr(cli, "PYPI_PUBLISHED", True)
    assert cli._install_target(checkout=None) == '"nimbus-cspm[ai]"'
