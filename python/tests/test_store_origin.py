"""W6-VERIFY r4 #15: the Python layer marks the databases it builds, so Go read-only commands
never migrate them (internal/store/origin.go), and never re-marks a Go-built database."""
import sqlite3

from nimbus.store import Store


def _built_by(path):
    con = sqlite3.connect(path)
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE name = 'store_meta'").fetchone():
            return None
        row = con.execute("SELECT v FROM store_meta WHERE k = 'built_by'").fetchone()
        return (row[0].decode() if isinstance(row[0], bytes) else row[0]) if row else None
    finally:
        con.close()


def test_python_built_db_is_marked(tmp_path):
    p = tmp_path / "py.db"
    Store(p)
    assert _built_by(p) == "python"
    Store(p)  # idempotent
    assert _built_by(p) == "python"


def test_go_built_db_is_never_marked_python(tmp_path):
    p = tmp_path / "go.db"
    con = sqlite3.connect(p)
    con.executescript("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);"
                      "CREATE TABLE store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL); INSERT INTO store_meta VALUES ('built_by', 'go');")
    con.commit()
    con.close()
    Store(p)
    assert _built_by(p) == "go"
    p2 = tmp_path / "legacy-go.db"
    con = sqlite3.connect(p2)
    con.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
    con.commit()
    con.close()
    Store(p2)
    assert _built_by(p2) is None
