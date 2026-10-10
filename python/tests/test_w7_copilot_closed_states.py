"""W7-POLISH item 8 (verification 7 defect 7): a verified_fixed (or pending_verification) path
Issue is not open. The copilot counts open Issues the way the Go store does (state open or
reopened), so `issues`, the MCP summary and the copilot agree."""
import sqlite3

import pytest

from nimbus.ai.copilot import SecurityCopilot

from .test_copilot_engine import engine_db  # noqa: F401  (fixture)


@pytest.mark.parametrize("state", ["verified_fixed", "pending_verification", "resolved"])
def test_closed_path_issue_is_not_listed(engine_db, monkeypatch, state):  # noqa: F811
    monkeypatch.setenv("CLOUD_POSTURE_BIN", "/nonexistent/cloud-posture")
    con = sqlite3.connect(engine_db.path)
    con.execute("UPDATE issues SET state = ? WHERE id = 'i-web'", (state,))
    con.commit()
    con.close()
    res = SecurityCopilot(engine_db, use_llm=False).ask("top attack paths")
    ids = [r[res["columns"].index("issue_id")] for r in res["rows"]]
    assert "i-web" not in ids and "i-pii" in ids, (state, ids)


def test_reopened_path_issue_is_listed(engine_db, monkeypatch):  # noqa: F811
    monkeypatch.setenv("CLOUD_POSTURE_BIN", "/nonexistent/cloud-posture")
    con = sqlite3.connect(engine_db.path)
    con.execute("UPDATE issues SET state = 'reopened' WHERE id = 'i-web'")
    con.commit()
    con.close()
    res = SecurityCopilot(engine_db, use_llm=False).ask("top attack paths")
    assert "i-web" in [r[res["columns"].index("issue_id")] for r in res["rows"]]
