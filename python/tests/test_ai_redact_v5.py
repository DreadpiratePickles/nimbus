"""Verify-5 PY-1..5 (ported from the verifier probe, scratchpad verify-5 tree-sec): copilot outbound redaction vs. tricky model-chosen SQL (offline, fake data,
ScriptedProvider - nothing leaves the machine).

Convention: a PASSING test means the protection holds; a FAILING test is a leak / gap to report.
Every case prints an OUTCOME line (refused / ran + outbound excerpt) so ``-rA`` keeps evidence.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import unicodedata

import pytest

from nimbus.ai import llm
from nimbus.ai.copilot import ANSWER_SYSTEM, SecurityCopilot
from nimbus.ai.guardrails import ToolGate, ToolRefused, TurnBudget, check_identifier_safe_sql
from nimbus.ai.providers import ScriptedProvider
from nimbus.ai.redact import Redactor, minimise
from nimbus.ai.sqlsafety import UnsafeSQL
from tests.conftest import F, sample_graph

ACCT = "731946280517"           # distinctive fake account (findings only)
OTHER = "468213579024"          # fake account present ONLY in graph_nodes (seeding gap, #5)
SECRET_DESC = "desc-secret-qq9z"  # text in a withheld column (description)
_PH = re.compile(r"\b(?:ACCT|IP|SUB|TAG)_[0-9a-f]{8}\b")


# ------------------------------------------------------------------ helpers
def _norm(s: str) -> str:
    """Map any Unicode decimal digit to ASCII so fullwidth / Arabic-Indic forms are recognised."""
    return "".join(str(unicodedata.decimal(c)) if unicodedata.decimal(c, None) is not None else c for c in s)


def leak_reasons(text: str, acct: str = ACCT) -> list[str]:
    """Why ``text`` lets a reader recover ``acct`` (empty = no leak). Placeholders are ignored."""
    t = _norm(_PH.sub(" ", text))
    out = []
    if acct in re.sub(r"\D", "", t) and acct in re.sub(r"[\s\-.]", "", t):
        out.append("full account (possibly spaced/dashed)")
    for run in re.findall(r"\d(?:[\d \-.]*\d)?", t):
        d = re.sub(r"\D", "", run)
        if len(d) >= 6 and (d in acct or acct in d):
            out.append(f"digit run {run!r}")
        try:
            x = float(run.replace(" ", "").replace("-", ""))
        except ValueError:
            continue
        if abs(x - int(acct)) < 1:
            out.append(f"numeric ~account {run!r}")
    if acct.encode().hex().upper() in t.upper():
        out.append("hex(account)")
    for m in re.finditer(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", t):
        ep = int(_dt.datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S").replace(tzinfo=_dt.timezone.utc).timestamp())
        if abs(ep * 100 - int(acct)) < 100:
            out.append(f"datetime(account/100) {m.group(0)}")
    return sorted(set(out))


@pytest.fixture(autouse=True)
def _reset():
    llm.set_provider(None)
    yield
    llm.set_provider(None)


@pytest.fixture
def store(seeded):
    fs = [F(check_id=f"v5_{i}", canonical_id="S3_PUBLIC_BUCKET", title=f"bucket v5-{i} public", description=SECRET_DESC,
            severity="CRITICAL", account=ACCT, resource={"id": f"arn:aws:s3:::v5-{i}", "type": "aws_s3_bucket", "name": f"v5-{i}"},
            weaknesses=["PUBLIC_DATA_STORE"]) for i in range(2)]
    seeded.upsert_findings(fs)
    nodes, edges = sample_graph()
    nodes = nodes + [
        {"id": "v5-node-other", "type": "aws_instance", "class": "compute", "provider": "aws", "account": OTHER,
         "name": "edge " + " ".join([OTHER[:4], OTHER[4:8], OTHER[8:]])},
        {"id": "v5-node-acct", "type": "aws_instance", "class": "compute", "provider": "aws", "account": ACCT,
         "name": "edge " + " ".join([ACCT[:4], ACCT[4:8], ACCT[8:]])},
    ]
    seeded.replace_graph(nodes, edges)
    return seeded


def gate_run(cp: SecurityCopilot, q: str) -> tuple[str, str]:
    """Run q the way agent() does (restore_obj -> ToolGate.call) and return (status, outbound text)."""
    gate = ToolGate(cp, TurnBudget(max_tool_calls=5, max_llm_calls=5))
    args = cp.redactor.restore_obj({"query": q})
    try:
        res = gate.call("sql", args)
    except ToolRefused as exc:
        status, out = "REFUSED", str(exc)
    except Exception as exc:  # sqlite error from deliberately odd SQL
        status, out = "ERROR", f"{type(exc).__name__}: {exc}"
    else:
        status, out = "RAN", cp._outbound_result(res)
    print(f"OUTCOME {status} | {q} | {out[:400]}")
    return status, out


def guard(q: str) -> str:
    try:
        check_identifier_safe_sql(q)
    except UnsafeSQL as exc:
        print(f"GUARD refused | {q} | {exc}")
        return f"refused: {exc}"
    print(f"GUARD allowed | {q}")
    return "allowed"


# ------------------------------------------------------------------ 1. numeric derivations (redact.py:125-128)
NUMERIC = [
    "SELECT account/1000 AS n FROM findings",
    "SELECT account % 1000000 AS n FROM findings",
    "SELECT account/1000 AS n, account % 1000 AS m FROM findings",
    "SELECT account * 10 AS n FROM findings",
    "SELECT account - 0.5 AS n FROM findings",
    "SELECT round(account / 1e6, 6) AS n FROM findings",
    "SELECT account + 1 AS n FROM findings",
    "SELECT abs(account) AS n FROM findings",
    "SELECT account * 1.0 AS n FROM findings",
    "SELECT length(account) AS n FROM findings",
    "SELECT substr(account,1,6)+0 AS n FROM findings",
    "SELECT unicode(account) AS n FROM findings",
]


@pytest.mark.parametrize("q", NUMERIC)
def test_numeric_derivation_does_not_leak(store, q):
    cp = SecurityCopilot(store, use_llm=True)
    status, out = gate_run(cp, q)
    assert not leak_reasons(out), (status, leak_reasons(out), out[:300])


@pytest.mark.parametrize("q", ["SELECT account/1000 AS n FROM findings", "SELECT account % 1000000 AS n FROM findings",
                               "SELECT account * 10 AS n FROM findings", "SELECT account - 0.5 AS n FROM findings"])
def test_guardrail_refuses_arithmetic_on_account(q):
    assert guard(q).startswith("refused")


# ------------------------------------------------------------------ 2. ask() path (copilot.py:614-675)
ASK = [
    "SELECT substr(account,1,6) AS a, substr(account,7) AS b FROM findings",
    "SELECT substr(account,1,6) AS title, substr(account,7) AS name FROM findings",
    "SELECT hex(account) AS title FROM findings",
    "SELECT replace(account, '1', ' 1') AS title FROM findings",
    "SELECT account/1000 AS n, account % 1000 AS m FROM findings",
    "SELECT description AS title FROM findings",
]


def _ask(store, q: str):
    def responder(system, prompt):
        return "ok" if system == ANSWER_SYSTEM else f"```sql\n{q}\n```"
    p = ScriptedProvider(responder)
    llm.set_provider(p)
    cp = SecurityCopilot(store, use_llm=True)
    res = cp.ask("list accounts")
    sent = "\n".join(pr for s, pr in p.calls if s == ANSWER_SYSTEM)
    data = sent[sent.find("Rows ("):] if "Rows (" in sent else sent
    print(f"ASK mode={res['mode']} err={res.get('error')} known_accounts={cp.redactor.known_accounts()} | {q} | {data[:500]}")
    return res, sent


@pytest.mark.parametrize("q", ASK)
def test_ask_path_does_not_leak_to_provider(store, q):
    res, sent = _ask(store, q)
    assert res["mode"] == "llm", res
    # Either the guard refused the model's SQL before it ran (nothing was sent), or what was sent
    # does not leak. (The verifier's probe required a sent prompt; a refusal is the stronger
    # outcome, adopted here.)
    if "rejected" in (res.get("error") or ""):
        assert not sent, "a refused statement's rows reached the provider"
        return
    assert sent, "the fake provider must have received the answer prompt"
    reasons = leak_reasons(sent) + (["withheld column description"] if SECRET_DESC in sent else [])
    assert not reasons, reasons


def test_ask_path_applies_identifier_safe_sql(store):
    res, _ = _ask(store, "SELECT substr(account,1,6) AS title FROM findings")
    assert "rejected" in (res.get("error") or ""), "ask() ran model SQL without check_identifier_safe_sql"


# ------------------------------------------------------------------ 3. aliasing into allowlisted names (guardrails.py:268-276)
ALIAS = [
    "SELECT upper(account) title FROM findings",
    "SELECT (account) title FROM findings",
    "SELECT CASE WHEN 1 THEN account END title FROM findings",
    "SELECT account COLLATE nocase title FROM findings",
    "SELECT title FROM findings UNION SELECT account FROM findings",
    "WITH x(title) AS (SELECT account FROM findings) SELECT title FROM x",
    "SELECT t AS title FROM (SELECT account AS t FROM findings)",
    "SELECT account AS 'title' FROM findings",
    "SELECT (description) title FROM findings",
    "SELECT CASE WHEN 1 THEN description END title FROM findings",
    "SELECT title FROM findings UNION SELECT description FROM findings",
    "WITH x(title) AS (SELECT description FROM findings) SELECT title FROM x",
    "SELECT description AS 'title' FROM findings",
    "SELECT description 'title' FROM findings",
    "SELECT datetime(account/100, 'unixepoch') first_seen FROM findings",
]


@pytest.mark.parametrize("q", ALIAS)
def test_guardrail_refuses_alias_into_allowlisted(q):
    assert guard(q).startswith("refused")


@pytest.mark.parametrize("q", ALIAS)
def test_alias_does_not_leak(store, q):
    cp = SecurityCopilot(store, use_llm=True)
    status, out = gate_run(cp, q)
    reasons = leak_reasons(out) + (["withheld column description"] if SECRET_DESC in out else [])
    assert not reasons, (status, reasons, out[:300])


# ------------------------------------------------------------------ 4. yes/no oracles (guardrails.py:264-267)
# (name, template, true-guess, false-guess): protection holds when the outbound answer does not
# depend on whether the guess is right.
ORACLES = [
    ("eq_raw", "SELECT count(*) AS n FROM findings WHERE account = '{g}'", ACCT, "123456789012"),
    ("in_raw", "SELECT count(*) AS n FROM findings WHERE account IN ('{g}')", ACCT, "123456789012"),
    ("substr_eq", "SELECT count(*) AS n FROM findings WHERE substr(account,1,4)='{g}'", ACCT[:4], "1234"),
    ("instr", "SELECT count(*) AS n FROM findings WHERE instr(account,'{g}') = 1", ACCT[:4], "1234"),
    ("like", "SELECT count(*) AS n FROM findings WHERE account LIKE '{g}%'", ACCT[:4], "1234"),
    ("range", "SELECT count(*) AS n FROM findings WHERE account > '{g}'", "7319", "7320"),
    ("between", "SELECT count(*) AS n FROM findings WHERE account BETWEEN '{g}' AND '{g}9'", "7319", "7320"),
    ("range_paren_window", "SELECT count(*) AS n FROM findings WHERE (((account))) > '{g}'", "7319", "7320"),
    ("range_ifnull_window", "SELECT count(*) AS n FROM findings WHERE ifnull(account, '') >= '{g}'", "7319", "7320"),
    ("arith_eq", "SELECT count(*) AS n FROM findings WHERE account / 1000000 = {g}", ACCT[:6], "123456"),
    ("arith_build_eq", "SELECT count(*) AS n FROM findings WHERE account = {g} * 10 + 7", ACCT[:11], "12345678901"),
    ("arith_range", "SELECT count(*) AS n FROM findings WHERE account - {g} * 10 > 0", "73194628050", "73194628052"),
    ("case_sum", "SELECT sum(CASE WHEN account / 1000000 = {g} THEN 1 ELSE 0 END) AS hits FROM findings", ACCT[:6], "123456"),
]


@pytest.mark.parametrize("name,tmpl,good,bad", ORACLES, ids=[o[0] for o in ORACLES])
def test_oracle_answer_independent_of_guess(store, name, tmpl, good, bad):
    cp = SecurityCopilot(store, use_llm=True)
    a = gate_run(cp, tmpl.format(g=good))
    b = gate_run(cp, tmpl.format(g=bad))
    assert a == b, (name, a[1][:200], b[1][:200])


def test_order_by_account_is_refused(store):
    """ORDER BY account LIMIT 1 ranks redacted accounts (low-bandwidth ordering oracle)."""
    cp = SecurityCopilot(store, use_llm=True)
    status, _ = gate_run(cp, "SELECT id FROM findings ORDER BY account DESC LIMIT 1")
    assert status == "REFUSED"


# ------------------------------------------------------------------ 5. ToolGate seeding (guardrails.py:299-300)
def test_gate_seeds_accounts_from_every_table(store):
    cp = SecurityCopilot(store, use_llm=True)
    ToolGate(cp, TurnBudget())
    known = cp.redactor.known_accounts()
    print("KNOWN", known)
    assert ACCT in known
    assert OTHER in known, "account present only in graph_nodes is not seeded"


def test_spaced_account_in_graph_node_name_withheld(store):
    cp = SecurityCopilot(store, use_llm=True)
    status, out = gate_run(cp, "SELECT name FROM graph_nodes WHERE id LIKE 'v5-node-%'")
    assert status == "RAN"
    assert not leak_reasons(out, ACCT), leak_reasons(out, ACCT)
    assert not leak_reasons(out, OTHER), ("graph-only account leaks", leak_reasons(out, OTHER), out[:300])


# ------------------------------------------------------------------ 6. value shapes (Redactor, fresh vs seeded)
FW = ACCT.translate(str.maketrans("0123456789", "０１２３４５６７８９"))
AR = ACCT.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
SHAPES = {
    "fullwidth": f"owner {FW}",
    "arabic_indic": f"owner {AR}",
    "spaced": f"owner {ACCT[:4]} {ACCT[4:8]} {ACCT[8:]}",
    "dashed": f"owner {ACCT[:4]}-{ACCT[4:8]}-{ACCT[8:]}",
    "dotted": f"owner {ACCT[:4]}.{ACCT[4:8]}.{ACCT[8:]}",
    "arn_gov": f"arn:aws-us-gov:iam::{ACCT}:role/x",
    "arn_cn": f"arn:aws-cn:iam::{ACCT}:role/x",
    "arn_isob": f"arn:aws-iso-b:iam::{ACCT}:role/x",
    "email": f"{ACCT}@x.com",
    "glued": f"acct{ACCT}x",
}


@pytest.mark.parametrize("seeded_redactor", [False, True], ids=["fresh", "seeded"])
@pytest.mark.parametrize("shape", list(SHAPES))
def test_value_shape_redacted(shape, seeded_redactor):
    r = Redactor(enabled=True)
    if seeded_redactor:
        r.learn("ACCT", [ACCT])
    _, rows, _ = minimise(["title"], [[SHAPES[shape]]], r)
    blob = json.dumps(rows, ensure_ascii=False)
    print(f"SHAPE {shape} seeded={seeded_redactor} -> {blob}")
    assert not leak_reasons(blob), leak_reasons(blob)


# ------------------------------------------------------------------ 7. encodings / quoting / comments / case
SYNTAX = [
    "SELECT printf('%d', account) AS n FROM findings",
    "SELECT hex(account) AS n FROM findings",
    "SELECT quote(account) AS n FROM findings",
    "SELECT char(unicode(account)) AS n FROM findings",
    "SELECT unicode(account) AS n FROM findings",
    "SELECT hex/**/(account) AS n FROM findings",
    'SELECT "hex"(account) AS n FROM findings',
    "SELECT HEX (account) AS n FROM findings",
    "SELECT count(*) AS n FROM findings WHERE acc/**/ount LIKE '7%'",
    """SELECT count(*) AS n FROM findings WHERE "account" LIKE '7%'""",
    "SELECT count(*) AS n FROM findings WHERE [account] LIKE '7%'",
    "SELECT count(*) AS n FROM findings WHERE `account` LIKE '7%'",
    "SELECT count(*) AS n FROM findings f WHERE f.account LIKE '7%'",
    "SELECT count(*) AS n FROM findings WHERE ACCOUNT LIKE '7%'",
    'SELECT "account" FROM findings',
    "SELECT f.account title FROM findings f",
    'SELECT account AS "Title" FROM findings',
]


@pytest.mark.parametrize("q", SYNTAX)
def test_syntax_variant_refused_or_redacted(store, q):
    cp = SecurityCopilot(store, use_llm=True)
    status, out = gate_run(cp, q)
    assert status in ("REFUSED", "ERROR") or not leak_reasons(out), (status, leak_reasons(out), out[:300])
    if "LIKE '7%'" in q and status == "RAN":
        n = re.search(r'"n": (\d+)', out)
        assert n is None or n.group(1) == "0", ("LIKE oracle on account answered", out[:200])


# ------------------------------------------------------------------ 8. every SQL path goes through the guard (PY-2)
def test_every_sql_call_site_declares_its_origin():
    """Enumerate every call that runs SQL in the copilot: each goes through run_sql with an explicit
    origin (model-chosen SQL: "llm"/"agent", which the guard checks), and the store's
    query_readonly is called only from run_sql."""
    import ast
    import inspect
    from nimbus.ai import copilot, guardrails
    run_sql_calls, ro_calls = [], []
    for mod in (copilot, guardrails):
        tree = ast.parse(inspect.getsource(mod))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "run_sql":
                        run_sql_calls.append((mod.__name__, fn.name, {k.arg for k in node.keywords}))
                    if node.func.attr == "query_readonly":
                        ro_calls.append((mod.__name__, fn.name))
    assert len(run_sql_calls) >= 3, run_sql_calls
    for mod, fn, kws in run_sql_calls:
        assert "origin" in kws, f"{mod}.{fn} calls run_sql without an origin"
    assert ro_calls == [("nimbus.ai.copilot", "run_sql")], f"query_readonly called outside run_sql: {ro_calls}"


def test_run_sql_guards_model_origins(store):
    cp = SecurityCopilot(store, use_llm=True)
    for origin in ("llm", "agent"):
        with pytest.raises(UnsafeSQL):
            cp.run_sql("SELECT account/1000 AS n FROM findings", origin=origin)
    with pytest.raises(ValueError):
        cp.run_sql("SELECT 1", origin="mystery")
    cp.run_sql("SELECT count(*) AS n FROM findings", origin="llm")  # plain model SQL still runs
