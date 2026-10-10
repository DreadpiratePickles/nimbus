"""W7-POLISH: the copilot decides "a Go command built / upgraded this database" from the same
marker the Go store uses (store_meta built_by, internal/store/origin.go), not from the presence of
an issues table. A Python-built database never triggers the Go overlay (it would refuse anyway);
a Go database from before the marker (schema_migrations, no store_meta) still counts as Go."""
import sqlite3

from nimbus.ai.copilot import SecurityCopilot
from nimbus.store import Store


def _copilot(path):
    return SecurityCopilot(Store(path), use_llm=False)


def test_python_built_db_with_an_issues_table_is_not_go(tmp_path):
    p = tmp_path / "py.db"
    Store(p)  # marks built_by=python
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE IF NOT EXISTS issues (id TEXT PRIMARY KEY)")
    con.commit()
    con.close()
    assert _copilot(p)._go_built() is False


def test_go_marker_and_legacy_go_db_are_go(tmp_path):
    p = tmp_path / "go.db"
    con = sqlite3.connect(p)
    con.executescript("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);"
                      "CREATE TABLE store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL); INSERT INTO store_meta VALUES ('built_by', X'676f');")
    con.commit()
    con.close()
    assert _copilot(p)._go_built() is True
    p2 = tmp_path / "legacy.db"
    con = sqlite3.connect(p2)
    con.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
    con.commit()
    con.close()
    assert _copilot(p2)._go_built() is True


def test_python_db_upgraded_by_go_is_go(tmp_path):
    p = tmp_path / "up.db"
    Store(p)
    con = sqlite3.connect(p)
    con.execute("UPDATE store_meta SET v = 'go' WHERE k = 'built_by'")  # what an ingest/scan upgrade writes
    con.commit()
    con.close()
    assert _copilot(p)._go_built() is True
