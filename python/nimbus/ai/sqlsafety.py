"""Guard rails for model- or user-supplied SQL: a single read-only SELECT/WITH statement."""
from __future__ import annotations

import re

MAX_ROWS = 200

FORBIDDEN = ("insert", "update", "delete", "drop", "alter", "create", "attach", "detach", "pragma", "replace\\s+into",
             "vacuum", "reindex", "analyze", "begin", "commit", "rollback", "savepoint", "release", "truncate",
             "load_extension", "writefile", "readfile")


class UnsafeSQL(ValueError):
    pass


def _strip_comments(sql: str) -> str:
    out, i, n = [], 0, len(sql)
    quote = None
    while i < n:
        ch = sql[i]
        if quote:
            out.append(ch)
            if ch == quote:
                if i + 1 < n and sql[i + 1] == quote:  # escaped '' or ""
                    out.append(sql[i + 1]); i += 2; continue
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch; out.append(ch); i += 1; continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        out.append(ch); i += 1
    return "".join(out)


def _without_strings(sql: str) -> str:
    return re.sub(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`", "''", sql)


def sanitize(sql: str, max_rows: int = MAX_ROWS) -> str:
    """Return a cleaned single SELECT/WITH statement with a LIMIT, or raise UnsafeSQL."""
    if not sql or not sql.strip():
        raise UnsafeSQL("empty query")
    s = _strip_comments(sql).strip()
    while s.endswith(";"):
        s = s[:-1].rstrip()
    bare = _without_strings(s)
    if ";" in bare:
        raise UnsafeSQL("multiple statements are not allowed")
    if not re.match(r"^\s*(select|with)\b", bare, re.I):
        raise UnsafeSQL("only SELECT / WITH queries are allowed")
    for kw in FORBIDDEN:
        if re.search(rf"\b{kw}\b", bare, re.I):
            raise UnsafeSQL(f"forbidden keyword: {kw.split(chr(92))[0].upper()}")
    m = re.search(r"\blimit\s+(\d+)(\s*(,|offset)\s*\d+)?\s*$", bare, re.I)
    if not m:
        s = f"{s}\nLIMIT {max_rows}"
    elif int(m.group(1)) > max_rows:
        s = f"SELECT * FROM (\n{s}\n) LIMIT {max_rows}"
    return s
