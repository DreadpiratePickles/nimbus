"""W5-ISSUES / Verification 5 MCP-1: the Go store keeps the per-database Issue id key in
store_meta and the old (unkeyed) -> new id map in issue_id_map. Neither is queryable from the
Python read-only path (copilot / API), nor listed as a table."""
import sqlite3

import pytest

from nimbus.store import Store


def _db(tmp_path):
    p = tmp_path / "k.db"
    st = Store(p)
    con = sqlite3.connect(p)
    con.executescript(
        "CREATE TABLE IF NOT EXISTS store_meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS issue_id_map (old_id TEXT PRIMARY KEY, new_id TEXT NOT NULL);"
        "INSERT INTO store_meta VALUES ('issue_id_key', randomblob(32));"
        "INSERT INTO issue_id_map VALUES ('aa', 'bb');"
    )
    con.commit()
    con.close()
    return st


@pytest.mark.parametrize("sql", ["SELECT * FROM store_meta", "SELECT hex(v) FROM store_meta", "SELECT * FROM issue_id_map",
                                 'SELECT * FROM "STORE_META"', "SELECT (SELECT old_id FROM issue_id_map) AS x"])
def test_internal_tables_not_queryable(tmp_path, sql):
    st = _db(tmp_path)
    with pytest.raises(Exception):
        st.query_readonly(sql)


def test_internal_tables_not_listed(tmp_path):
    st = _db(tmp_path)
    assert "store_meta" not in st.queryable_tables() and "issue_id_map" not in st.queryable_tables()
    assert "store_meta" not in st.tables() and "issue_id_map" not in st.tables()
