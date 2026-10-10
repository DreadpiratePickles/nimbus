"""Copilot guardrails (plan AI4): what the model may do, what it sees, and how much it may spend.

* **Allowlisted read-only tools only.** ``ALLOWED_TOOLS`` is the complete list; ``ToolGate``
  refuses (and records) anything else, by exact name. Every allowed tool reads the local DB.
* **Untrusted-data wrapping.** Tool results go to the model inside ``<untrusted_data>`` as
  ASCII-only JSON with ``<``/``>`` escaped, so a hostile title cannot close the wrapper, fake a
  tool call, or hide text with bidi/zero-width characters.
* **Per-turn caps.** ``TurnBudget``: tool calls (refused ones count), model calls, tokens, cost
  (when per-Mtok prices are configured) and wall time.
* **Identifier-safe SQL** (verify-4 defect 3). Model-chosen SQL may not transform identifiers
  before they reach the outbound redactor: identifier-transforming functions (``hex``, ``substr``,
  ``CAST``, ``replace``, ``group_concat``, ``json_extract``, ...), the ``||``/``->`` operators,
  renaming an expression into an allowlisted column name (``hex(account) AS title``, implicit
  ``tags title``), and LIKE/GLOB/range comparisons on account columns (yes/no oracles) are
  refused; raw identifiers in tool arguments (not placeholders) are refused; the session's
  redactor is seeded with the estate's account ids so value-level checks recognise their pieces.
* **Citations.** ``Citations`` collects every SQL statement run and every finding / Issue / path
  id the results touched; ``Citations.footer`` is appended to every answer.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .providers import Completion
from .redact import OUTBOUND_COLUMNS
from .sqlsafety import UnsafeSQL

ALLOWED_TOOLS: dict[str, str] = {
    "sql": 'Run one read-only SELECT over the posture DB. args: {"query": "SELECT ..."}',
    "finding": 'Get one finding by id (no raw provider JSON). args: {"id": "..."}',
    "attack_paths": 'List stored attack paths, optionally for one finding. args: {"finding_id": "..."} (optional)',
    "blast_radius": 'Resources reachable from a resource within N hops. args: {"resource_id": "...", "max_hops": 4}',
    "remediation_guidance": 'Remediation steps for a check. args: {"canonical_id": "S3_PUBLIC_BUCKET"}',
    "who_can": 'Principals that can perform an action on a resource (IAM evaluator, anonymous first). '
               'args: {"action": "s3:GetObject", "resource": "arn:aws:s3:::bucket/*"}',
    "verify_state": 'An Issue\'s state and verification history, and the command a human runs to verify it (read-only). '
                    'args: {"issue_id": "..."}',
}


class ToolRefused(Exception):
    pass


class BudgetExceeded(Exception):
    pass


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class TurnBudget:
    max_tool_calls: int = 8
    max_llm_calls: int = 10
    max_seconds: float = 90.0
    max_tokens: int = 200_000
    max_cost_usd: float = 0.0  # 0 = no cost cap (prices unknown); tokens still capped
    usd_per_mtok_in: float = 0.0
    usd_per_mtok_out: float = 0.0
    clock: Callable[[], float] = time.monotonic
    tool_calls: int = 0
    llm_calls: int = 0
    tokens: int = 0
    cost_usd: float = 0.0
    started: float = field(default=-1.0)

    @classmethod
    def from_env(cls) -> "TurnBudget":
        return cls(max_tool_calls=int(_env_float("NIMBUS_AI_MAX_TOOL_CALLS", 8)), max_llm_calls=int(_env_float("NIMBUS_AI_MAX_LLM_CALLS", 10)),
                   max_seconds=_env_float("NIMBUS_AI_MAX_SECONDS", 90), max_tokens=int(_env_float("NIMBUS_AI_MAX_TOKENS", 200_000)),
                   max_cost_usd=_env_float("NIMBUS_AI_MAX_COST_USD", 0), usd_per_mtok_in=_env_float("NIMBUS_LLM_USD_PER_MTOK_IN", 0),
                   usd_per_mtok_out=_env_float("NIMBUS_LLM_USD_PER_MTOK_OUT", 0))

    def _start(self) -> None:
        if self.started < 0:
            self.started = self.clock()

    def check_time(self) -> None:
        self._start()
        if self.clock() - self.started > self.max_seconds:
            raise BudgetExceeded(f"budget: time cap of {self.max_seconds:g}s reached")

    def tool_call(self) -> None:
        self.check_time()
        if self.tool_calls >= self.max_tool_calls:
            raise BudgetExceeded(f"budget: tool-call cap of {self.max_tool_calls} reached")
        self.tool_calls += 1

    def llm_call(self) -> None:
        self.check_time()
        if self.llm_calls >= self.max_llm_calls:
            raise BudgetExceeded(f"budget: model-call cap of {self.max_llm_calls} reached")
        self.llm_calls += 1

    def charge(self, c: Optional[Completion]) -> None:
        if c is None:
            return
        self.tokens += c.input_tokens + c.output_tokens
        self.cost_usd += c.input_tokens / 1e6 * self.usd_per_mtok_in + c.output_tokens / 1e6 * self.usd_per_mtok_out
        if self.tokens > self.max_tokens:
            raise BudgetExceeded(f"budget: token cap of {self.max_tokens} reached ({self.tokens})")
        if self.max_cost_usd and self.cost_usd > self.max_cost_usd:
            raise BudgetExceeded(f"budget: cost cap of ${self.max_cost_usd:.2f} reached (${self.cost_usd:.4f})")

    def summary(self) -> dict[str, Any]:
        return {"tool_calls": self.tool_calls, "llm_calls": self.llm_calls, "tokens": self.tokens, "cost_usd": round(self.cost_usd, 6)}


_ID_COLS = {"id": "finding_ids", "finding_id": "finding_ids", "finding_ids": "finding_ids", "issue_id": "issue_ids", "path_id": "path_ids"}


@dataclass
class Citations:
    queries: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    issue_ids: list[str] = field(default_factory=list)
    path_ids: list[str] = field(default_factory=list)

    def _add(self, kind: str, v: Any) -> None:
        if isinstance(v, (list, tuple)):
            for x in v:
                self._add(kind, x)
            return
        if isinstance(v, str) and v.startswith("[") :
            try:
                return self._add(kind, json.loads(v))
            except ValueError:
                pass
        if v in (None, ""):
            return
        lst = getattr(self, kind)
        if str(v) not in lst:
            lst.append(str(v))

    def query(self, sql: str) -> None:
        if sql and sql not in self.queries:
            self.queries.append(sql)

    def table(self, columns: list[str], rows: list[list[Any]]) -> None:
        """Collect ids from a result. An ``id`` column is a path id when the row shape is an
        attack path (rule_id but no canonical_id), else a finding id."""
        lower = [c.lower() for c in columns]
        table_hint = "attack_paths" if "rule_id" in lower and "canonical_id" not in lower else "findings"
        for i, c in enumerate(columns):
            kind = _ID_COLS.get(c.lower())
            if kind is None:
                continue
            if c.lower() == "id" and table_hint == "attack_paths":
                kind = "path_ids"
            for r in rows:
                self._add(kind, r[i])

    def doc(self, d: Any) -> None:
        """Collect ids from a tool's JSON result."""
        if isinstance(d, dict):
            for k, v in d.items():
                kind = _ID_COLS.get(k)
                if kind and k != "id":
                    self._add(kind, v)
                else:
                    self.doc(v)
        elif isinstance(d, list):
            for x in d:
                self.doc(x)

    def as_dict(self) -> dict[str, list[str]]:
        return {"queries": list(self.queries), "finding_ids": list(self.finding_ids), "issue_ids": list(self.issue_ids),
                "path_ids": list(self.path_ids)}

    def footer(self, max_ids: int = 10, show_sql: bool = False) -> str:
        """The Sources block. SQL is folded (counted, not printed) unless show_sql: it is kept in
        ``as_dict()["queries"]`` for --json and printed once with --show-sql (delta r3 #11)."""
        parts = []
        if self.queries and show_sql:
            parts.append("SQL: " + " | ".join(q.replace("\n", " ") for q in self.queries))
        elif self.queries:
            parts.append(f"{len(self.queries)} quer{'y' if len(self.queries) == 1 else 'ies'} (--show-sql to print)")
        for label, ids in (("findings", self.finding_ids), ("issues", self.issue_ids), ("paths", self.path_ids)):
            if ids:
                more = f" (+{len(ids) - max_ids} more)" if len(ids) > max_ids else ""
                parts.append(f"{label}: " + ", ".join(ids[:max_ids]) + more)
        return "Sources: " + ("; ".join(parts) if parts else "no query was run")


_UNTRUSTED = ("<untrusted_data>", "</untrusted_data>")


def wrap_untrusted(data: Any) -> str:
    """ASCII-only JSON with markup escaped, inside the untrusted-data wrapper."""
    body = json.dumps(data, ensure_ascii=True, default=str, sort_keys=True)
    body = body.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return _UNTRUSTED[0] + body + _UNTRUSTED[1]


_JSON_BLOCK = re.compile(r"```(?:json)?\s*\n(.*?)```", re.S)


def parse_action(text: str) -> tuple[str, str, dict]:
    """Parse a model turn: ('tool', name, args) | ('answer', text, {}) | ('invalid', reason, {})."""
    t = (text or "").strip()
    m = _JSON_BLOCK.search(t)
    cand = m.group(1).strip() if m else t
    if not cand.startswith("{"):
        i = cand.find("{")
        if i < 0 or not m and not cand.rstrip().endswith("}"):
            return ("answer", t, {})
        cand = cand[i:]
    try:
        obj = json.loads(cand)
    except ValueError:
        return ("answer", t, {})
    if not isinstance(obj, dict):
        return ("invalid", "not an object", {})
    if "tool" in obj:
        name, args = obj.get("tool"), obj.get("args", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            return ("invalid", "tool must be a string and args an object", {})
        return ("tool", name, args)
    if "answer" in obj and isinstance(obj["answer"], str):
        return ("answer", obj["answer"], {})
    return ("invalid", "expected {tool, args} or {answer}", {})


_TRANSFORMING_FUNCS = frozenset({
    "hex", "unhex", "substr", "substring", "cast", "replace", "printf", "format", "char", "unicode", "instr", "quote",
    "reverse", "trim", "ltrim", "rtrim", "group_concat", "string_agg", "concat", "concat_ws", "soundex", "json",
    "jsonb", "json_extract", "jsonb_extract", "json_each", "json_tree", "json_object", "json_array", "json_group_array",
    "json_group_object", "json_quote", "json_set", "json_insert", "json_replace", "json_patch", "json_remove",
    "like", "glob", "regexp", "match", "zeroblob", "randomblob", "unistr", "octet_length",
})
_ACCOUNT_COLUMNS = frozenset({"account", "account_id", "accounts", "subscription", "project"})
# Identifier columns: no function (but count) may take them as an argument, no comparison other
# than equality / IN may test them, and no ORDER BY may rank them (verify-5 PY-1, PY-4).
_IDENT_COLUMNS = _ACCOUNT_COLUMNS | frozenset({"resource_id", "arn", "principal", "from_id", "to_id"})
_ORACLE_OPS = frozenset({"like", "glob", "regexp", "match", "between", "<", ">", "<=", ">="})
# Arithmetic and bitwise operators rebuild an id from pieces (account/1000, account % 1000):
# refused in model-chosen SQL, the same rule as the Go MCP view layer (computed values over
# redacted columns). "*" is allowed only as the column wildcard (SELECT *, count(*), t.*).
_ARITH_OPS = frozenset({"/", "%", "+", "-", "<<", ">>", "&", "|", "~"})
_COUNT_OK = frozenset({"count"})
_COLLATIONS = frozenset({"nocase", "binary", "rtrim"})
_SQL_KEYWORDS = frozenset({
    "select", "distinct", "all", "from", "where", "and", "or", "not", "as", "on", "join", "left", "right", "inner", "outer",
    "cross", "natural", "using", "by", "order", "group", "having", "asc", "desc", "limit", "offset", "union", "intersect",
    "except", "case", "when", "then", "else", "end", "is", "null", "in", "exists", "with", "recursive", "values", "collate",
    "nocase", "nulls", "first", "last", "filter", "over", "partition", "window", "escape", "like", "glob", "between",
    "true", "false", "rows", "range", "preceding", "following", "current", "row", "unbounded",
})
_TOK = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`|\[[^\]]*\]|\|\||->>|->|<<|>>|<=|>=|<>|!=|==|[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\S")


def _ident(tok: str) -> str:
    if tok[:1] in ('"', "`", "[", "'") and len(tok) >= 2:
        return tok[1:-1].lower()
    return tok.lower()


def _is_name(tok: str) -> bool:
    return bool(tok) and (tok[0].isalpha() or tok[0] in ('_', '"', '`', '['))


def check_identifier_safe_sql(sql: str) -> None:
    """Refuse model-chosen SQL that could carry an identifier past the outbound redactor in a
    transformed form, rename a withheld column into an allowlisted one, or answer a yes/no
    oracle about a redacted id (see the module doc). Raises UnsafeSQL. Every SQL statement a
    model chose goes through here: the agent's sql tool and ask()'s LLM path."""
    from .sqlsafety import _strip_comments
    toks = _TOK.findall(_strip_comments(sql))
    low = [t.lower() for t in toks]
    n = len(toks)

    def skip_parens_back(i: int) -> str:
        while i >= 0 and toks[i] in ("(", ")"):
            i -= 1
        return low[i] if i >= 0 else ""

    def skip_parens_fwd(i: int) -> str:
        while i < n and toks[i] in ("(", ")"):
            i += 1
        return low[i] if i < n else ""

    order_by = False
    for i, t in enumerate(toks):
        lt = low[i]
        nxt = toks[i + 1] if i + 1 < n else ""
        prev = toks[i - 1] if i > 0 else ""
        lprev = prev.lower()
        quoted = t[:1] == "'"
        if lt in ("union", "intersect", "except") and not quoted:
            raise UnsafeSQL(f"compound SELECT ({t.upper()}) is not allowed: later columns inherit the first SELECT's names")
        if lt == "with" and not quoted and i + 2 < n and _is_name(nxt) and toks[i + 2] == "(":
            raise UnsafeSQL("a WITH column list is not allowed: it renames columns past the outbound allowlist")
        if not quoted and _ident(t) in _TRANSFORMING_FUNCS and nxt == "(":
            raise UnsafeSQL(f"{_ident(t)}() is not allowed: it can transform an identifier past redaction")
        if t in ("||", "->", "->>"):
            raise UnsafeSQL(f"the {t} operator is not allowed: it can transform an identifier past redaction")
        if t in _ARITH_OPS or (t == "*" and lprev not in ("select", ",", "(", ".", "distinct", "all")):
            raise UnsafeSQL(f"arithmetic ({t}) is not allowed in model-chosen SQL: it can rebuild an identifier from pieces")
        if not quoted and _is_name(t) and nxt == "(" and lt not in _SQL_KEYWORDS and lt not in _COUNT_OK:
            depth, j = 0, i + 1
            while j < n:
                if toks[j] == "(":
                    depth += 1
                elif toks[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif _ident(toks[j]) in _IDENT_COLUMNS and toks[j][:1] != "'":
                    raise UnsafeSQL(f"{_ident(t)}() on the identifier column {_ident(toks[j])!r} is not allowed")
                j += 1
        if lt == "order" and nxt.lower() == "by":
            order_by = True
        elif lt in ("limit", "offset"):
            order_by = False
        if not quoted and _ident(t) in _IDENT_COLUMNS:
            if order_by:
                raise UnsafeSQL(f"ORDER BY {_ident(t)} is not allowed (it ranks redacted ids: an ordering oracle)")
            before, after = skip_parens_back(i - 1), skip_parens_fwd(i + 1)
            if before in _ORACLE_OPS or after in _ORACLE_OPS or (after == "not" and i + 2 < n and low[i + 2] in _ORACLE_OPS):
                raise UnsafeSQL(f"a range / LIKE comparison on {_ident(t)!r} is not allowed (a yes/no oracle on a redacted id)")
        if lt in _ORACLE_OPS:
            near = [_ident(x) for x in toks[max(0, i - 3):i] + toks[i + 1:i + 4] if x[:1] != "'"]
            if any(x in _ACCOUNT_COLUMNS for x in near):
                raise UnsafeSQL(f"{t.upper()} on an account column is not allowed (it is a yes/no oracle on a redacted id)")
        if lt == "as" and nxt:
            alias, src = _ident(nxt), _ident(prev)
            if alias in OUTBOUND_COLUMNS and src != alias:
                raise UnsafeSQL(f"renaming an expression to the allowlisted column {alias!r} is not allowed")
        # implicit alias: an allowlisted name right after the end of an expression
        if i > 0 and _ident(t) in OUTBOUND_COLUMNS and (i < 2 or toks[i - 2] != "."):
            if quoted:
                alias_pos = prev == ")" or (_is_name(prev) and lprev not in _SQL_KEYWORDS) or lprev in ("end",) or lprev in _COLLATIONS
                if alias_pos and nxt.lower() in ("", ",", "from", ")", ";"):
                    raise UnsafeSQL(f"renaming to the allowlisted column {_ident(t)!r} is not allowed")
            elif lt not in _SQL_KEYWORDS or lt in ("first", "last", "range", "rows"):
                expr_end = prev == ")" or lprev == "end" or lprev in _COLLATIONS or prev[:1] in ("'",) or \
                    (_is_name(prev) and lprev not in _SQL_KEYWORDS and _ident(prev) != _ident(t))
                if expr_end:
                    raise UnsafeSQL(f"renaming {_ident(prev)!r} to the allowlisted column {_ident(t)!r} is not allowed")


class ToolGate:
    """Runs allowlisted tools for one turn, enforcing the budget and recording citations."""

    def __init__(self, copilot: Any, budget: TurnBudget):
        self.cp, self.budget = copilot, budget
        self.citations = Citations()
        self.executed: list[dict[str, Any]] = []
        self.refused: list[dict[str, Any]] = []
        self._seed_redactor()

    def _redactor(self) -> Any:
        r = getattr(self.cp, "redactor", None)
        return r if r is not None and getattr(r, "enabled", False) else None

    def _seed_redactor(self) -> None:
        """Teach the session's redactor every account id in the estate, so value-level checks can
        recognise pieces of one (substr, concatenation) before any query has shown it."""
        seed = getattr(self.cp, "seed_redactor", None)
        if seed is not None and self._redactor() is not None:
            seed()

    def call(self, name: str, args: dict[str, Any]) -> Any:
        self.budget.tool_call()
        if name not in ALLOWED_TOOLS:
            self.refused.append({"tool": name, "args": args, "reason": "not in the read-only tool allowlist"})
            raise ToolRefused(f"tool {name!r} is not allowed; allowed: {', '.join(ALLOWED_TOOLS)}")
        r = self._redactor()
        if r is not None and getattr(r, "last_input_raw", False):
            r.last_input_raw = False
            self.refused.append({"tool": name, "args": args, "reason": "raw identifier in arguments"})
            raise ToolRefused("this session redacts identifiers: pass the placeholders you were shown (ACCT_..., IP_...), "
                              "not raw account ids or IP addresses")
        if r is not None and name == "sql":
            try:
                check_identifier_safe_sql(str(args.get("query", "")))
            except UnsafeSQL as exc:
                self.refused.append({"tool": name, "args": args, "reason": f"unsafe SQL: {exc}"})
                raise ToolRefused(f"rejected SQL: {exc}") from exc
        try:
            res = getattr(self, "_" + name)(**{k: v for k, v in args.items()})
        except UnsafeSQL as exc:
            self.refused.append({"tool": name, "args": args, "reason": f"unsafe SQL: {exc}"})
            raise ToolRefused(f"rejected unsafe SQL: {exc}") from exc
        except TypeError as exc:
            self.refused.append({"tool": name, "args": args, "reason": f"bad arguments: {exc}"})
            raise ToolRefused(f"bad arguments for {name}: {exc}") from exc
        self.executed.append({"tool": name, "args": args})
        return res

    # Each tool is read-only: the store's read-only query path or read accessors.
    def _sql(self, query: str) -> dict[str, Any]:
        sql, cols, rows = self.cp.run_sql(query, origin="agent")
        self.citations.query(sql)
        self.citations.table(cols, rows)
        return {"sql": sql, "columns": cols, "rows": rows}

    def _finding(self, id: str) -> dict[str, Any]:
        f = self.cp.store.finding(id)
        if f is None:
            return {"error": f"no finding {id}"}
        self.citations._add("finding_ids", f.id)
        d = f.to_doc()
        d.pop("raw", None)
        (d.get("resource") or {}).pop("attributes", None)
        return d

    def _attack_paths(self, finding_id: str = "") -> dict[str, Any]:
        paths = self.cp.store.attack_paths()
        if finding_id:
            paths = [p for p in paths if finding_id in p.finding_ids]
        out = [{"id": p.id, "name": p.name, "score": p.score, "severity": getattr(p.severity, "value", p.severity),
                "finding_ids": p.finding_ids, "steps": [{"resource": s.resource, "weakness": s.weakness, "title": s.title} for s in p.steps]}
               for p in paths[:20]]
        for p in out:
            self.citations._add("path_ids", p["id"])
        return {"paths": out}

    def _who_can(self, action: str, resource: str) -> dict[str, Any]:
        res = self.cp.who_can_rows(str(action), str(resource))
        if "error" not in res:
            self.citations.query(res["command"])
        return res

    def _verify_state(self, issue_id: str) -> dict[str, Any]:
        res = self.cp.verify_state(str(issue_id))
        if "issue_id" in res:
            self.citations._add("issue_ids", res["issue_id"])
        return res

    def _blast_radius(self, resource_id: str, max_hops: int = 4) -> dict[str, Any]:
        return self.cp.blast_radius(resource_id, max_hops=min(int(max_hops), 6))

    def _remediation_guidance(self, canonical_id: str) -> dict[str, Any]:
        g = self.cp.remediation_guidance_offline(canonical_id)
        return {k: g[k] for k in ("canonical_id", "title", "severity", "open_findings", "steps")}
