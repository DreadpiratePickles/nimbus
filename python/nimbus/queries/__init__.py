"""Named compliance & security query library (SQL files indexed by index.yaml)."""
from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any, Optional

import yaml

from ..ai.sqlsafety import sanitize
from ..store import Store


@lru_cache(maxsize=1)
def index() -> list[dict[str, Any]]:
    root = resources.files("nimbus").joinpath("queries")
    data = yaml.safe_load(root.joinpath("index.yaml").read_text(encoding="utf-8")) or {}
    out = []
    for q in data.get("queries", []):
        q = dict(q)
        q["sql_text"] = root.joinpath(q["sql"]).read_text(encoding="utf-8")
        out.append(q)
    return out


def list_queries() -> list[dict[str, Any]]:
    return [{k: v for k, v in q.items() if k != "sql_text"} | {"sql_text": q["sql_text"]} for q in index()]


def get(name: str) -> Optional[dict[str, Any]]:
    return next((q for q in index() if q["name"] == name), None)


def run_named(store: Store, name: str, max_rows: int = 1000) -> tuple[list[str], list[list[Any]]]:
    q = get(name)
    if q is None:
        raise KeyError(f"unknown query {name!r}; see `nimbus query --list`")
    return store.query(sanitize(q["sql_text"], max_rows))


def run_sql(store: Store, sql: str, max_rows: int = 1000) -> tuple[list[str], list[list[Any]]]:
    """Run ad-hoc untrusted SQL: lexical sanitize, then engine-enforced read-only execution."""
    return store.query_readonly(sanitize(sql, max_rows), max_rows=max_rows)
