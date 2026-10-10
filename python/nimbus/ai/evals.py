"""Copilot eval suite (plan AI2): questions with the SQL a model returned and the facts the
answer must contain, over the test fixture estate (``tests/conftest.py`` ``seeded``).

The model outputs here are *scripted*: hand-written to match what a capable model produces for
the schema prompt, because this environment has no network. ``recorded_responder`` replays them
through any provider transport (Anthropic SDK, OpenAI-compatible HTTP, Bedrock converse) so the
whole ask() pipeline - provider plumbing, SQL safety, read-only execution, minimisation,
redaction, citations - is exercised identically for each. Re-recording the outputs from a live
provider is a follow-up (needs credentials and network; not available in this environment).

Each case: ``question``; ``sql`` (the model's SQL); ``answer`` (the model's summary);
``expect`` (facts on the executed rows: ``count``, ``contains``); optionally ``offline_intent``
(+ ``expect_offline``) when the offline rule engine must answer it too; ``no_model`` when the
question must be answered without any model call (pasted identifiers).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Callable, Optional

from . import llm
from .copilot import SecurityCopilot, identifier_sql
from .sqlsafety import sanitize

_FAIL = "status = 'FAIL'"
_SEV = "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"

CASES: list[dict[str, Any]] = [
    {"question": "How many open findings are there?", "sql": f"SELECT COUNT(*) AS n FROM findings WHERE {_FAIL}",
     "answer": "There are 11 open findings.", "expect": {"count": 1, "contains": [11]}},
    {"question": "Which S3 buckets are public?", "offline_intent": "public_buckets",
     "sql": f"SELECT id, resource_name, severity FROM findings WHERE {_FAIL} AND weaknesses LIKE '%\"PUBLIC_DATA_STORE\"%'",
     "answer": "One bucket is public: customer-pii.", "expect": {"count": 1, "contains": ["customer-pii"]}},
    {"question": "show me public databases", "offline_intent": "public_databases",
     "sql": f"SELECT id, resource_name, canonical_id FROM findings WHERE {_FAIL} AND resource_type = 'aws_db_instance' "
            "AND weaknesses LIKE '%PUBLIC_NETWORK_EXPOSURE%'",
     "answer": "The orders RDS instance is publicly accessible.", "expect": {"count": 1, "contains": ["orders"]}},
    {"question": "list unencrypted databases", "offline_intent": "unencrypted",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND weaknesses LIKE '%UNENCRYPTED_AT_REST%' AND resource_type = 'aws_db_instance'",
     "answer": "orders stores data unencrypted.", "expect": {"count": 1, "contains": ["orders"]}},
    {"question": "unencrypted buckets", "offline_intent": "unencrypted",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND weaknesses LIKE '%UNENCRYPTED_AT_REST%' AND resource_type = 'aws_s3_bucket'",
     "answer": "customer-pii has no default encryption.", "expect": {"count": 1, "contains": ["customer-pii"]}},
    {"question": "users without MFA", "offline_intent": "no_mfa",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND weaknesses LIKE '%NO_MFA%'",
     "answer": "alice has console access without MFA.", "expect": {"count": 1, "contains": ["alice"]}},
    {"question": "stale access keys", "offline_intent": "stale_credentials",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND weaknesses LIKE '%STALE_CREDENTIALS%'",
     "answer": "deploy has an access key older than 90 days.", "expect": {"count": 1, "contains": ["deploy"]}},
    {"question": "privileged pods", "offline_intent": "privileged_pods",
     "sql": f"SELECT id, resource_name, account FROM findings WHERE {_FAIL} AND weaknesses LIKE '%PRIVILEGED_CONTAINER%'",
     "answer": "api-0 runs privileged.", "expect": {"count": 1, "contains": ["api-0"]}},
    {"question": "attack paths to RDS", "offline_intent": "attack_paths",
     "sql": "SELECT id, name, score FROM attack_paths WHERE lower(doc) LIKE '%rds%' ORDER BY score DESC",
     "answer": "One path reaches the orders database.", "expect": {"contains": ["ap-db"]}},
    {"question": "what are my top risks?", "offline_intent": "top_risks",
     "sql": f"SELECT id, canonical_id, severity FROM findings WHERE {_FAIL} ORDER BY {_SEV} LIMIT 5",
     "answer": "The public RDS instance is the top risk.", "expect": {"count": 5, "contains": ["RDS_PUBLIC"]},
     "expect_offline": {"count": 11, "contains": ["RDS_PUBLIC"]}},
    {"question": "findings by account", "offline_intent": "findings_by_account",
     "sql": f"SELECT account, COUNT(*) AS failed FROM findings WHERE {_FAIL} GROUP BY account ORDER BY failed DESC",
     "answer": "Most findings are in the main AWS account.", "expect": {"count": 3, "contains": ["prod-cluster", "proj-dev", 9]}},
    {"question": "count findings by provider", "offline_intent": "findings_by_provider",
     "sql": f"SELECT provider, COUNT(*) AS failed FROM findings WHERE {_FAIL} GROUP BY provider",
     "answer": "AWS dominates.", "expect": {"count": 3, "contains": ["kubernetes", "gcp", "aws"]}},
    {"question": "show critical findings", "offline_intent": "findings_by_severity",
     "sql": f"SELECT id, canonical_id, resource_name FROM findings WHERE {_FAIL} AND severity = 'CRITICAL'",
     "answer": "One critical: the public RDS instance.", "expect": {"count": 1, "contains": ["RDS_PUBLIC"]}},
    {"question": "List medium severity findings", "offline_intent": "findings_by_severity",
     "sql": f"SELECT id, canonical_id FROM findings WHERE {_FAIL} AND severity = 'MEDIUM'",
     "answer": "Three medium findings.", "expect": {"count": 3, "contains": ["S3_UNENCRYPTED", "IAM_STALE_KEYS", "EC2_PUBLIC_IP"]}},
    {"question": "compliance status for CIS 1.10", "offline_intent": "compliance_control_status",
     "sql": "SELECT status, COUNT(*) AS n FROM findings WHERE compliance LIKE '%\"1.10\"%' GROUP BY status",
     "answer": "CIS 1.10 fails for one user and passes for one.", "expect": {"count": 2, "contains": ["FAIL", "PASS"]},
     "expect_offline": {"count": 1, "contains": ["1.10", "FAIL"]}},
    {"question": "internet exposed instances in aws", "offline_intent": "public_instances",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND provider = 'aws' AND resource_type = 'aws_instance' "
            "AND weaknesses LIKE '%PUBLIC_NETWORK_EXPOSURE%'",
     "answer": "web-1 has a public IP.", "expect": {"count": 1, "contains": ["web-1"]}},
    {"question": "Which findings are on the orders database?",
     "sql": f"SELECT id, canonical_id FROM findings WHERE {_FAIL} AND resource_name = 'orders'",
     "answer": "Two findings: public and unencrypted.", "expect": {"count": 2, "contains": ["RDS_PUBLIC", "RDS_UNENCRYPTED"]}},
    {"question": "Which resources have both public exposure and IMDSv1?",
     "sql": f"SELECT resource_name FROM findings WHERE {_FAIL} GROUP BY resource_id HAVING SUM(weaknesses LIKE '%PUBLIC_NETWORK_EXPOSURE%') > 0 "
            "AND SUM(weaknesses LIKE '%IMDSV1_ENABLED%') > 0",
     "answer": "web-1 is both exposed and on IMDSv1.", "expect": {"count": 1, "contains": ["web-1"]}},
    {"question": "How many attack paths are critical?", "sql": "SELECT COUNT(*) AS n FROM attack_paths WHERE severity = 'CRITICAL'",
     "answer": "Two critical attack paths.", "expect": {"count": 1, "contains": [2]}},
    {"question": "Which IAM identities are overprivileged?",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND weaknesses LIKE '%OVERPRIVILEGED_IDENTITY%'",
     "answer": "deploy has administrator privileges.", "expect": {"count": 1, "contains": ["deploy"]}},
    {"question": "What is the highest-scoring attack path?", "sql": "SELECT id, name, score FROM attack_paths ORDER BY score DESC LIMIT 1",
     "answer": "The public database path scores 9.5.", "expect": {"count": 1, "contains": ["ap-db", 9.5]}},
    {"question": "Which checks fail in more than one place?",
     "sql": f"SELECT canonical_id, COUNT(*) AS n FROM findings WHERE {_FAIL} GROUP BY canonical_id HAVING n > 1",
     "answer": "No check fails more than once.", "expect": {"count": 0}},
    {"question": "Which findings map to PCI DSS?",
     "sql": f"SELECT id, canonical_id FROM findings WHERE {_FAIL} AND compliance LIKE '%pci_dss%'",
     "answer": "Two findings affect PCI DSS.", "expect": {"count": 2, "contains": ["S3_PUBLIC_BUCKET", "RDS_PUBLIC"]}},
    {"question": "Which GCP buckets have problems?",
     "sql": f"SELECT id, resource_name FROM findings WHERE {_FAIL} AND provider = 'gcp'",
     "answer": "logs-dev has a logging gap.", "expect": {"count": 1, "contains": ["logs-dev"]}},
    {"question": "arn:aws:s3:::customer-pii", "offline_intent": "identifier", "no_model": True,
     "sql": identifier_sql("arn:aws:s3:::customer-pii").sql, "answer": "",
     "expect": {"count": 2, "contains": ["S3_PUBLIC_BUCKET", "S3_UNENCRYPTED"]}},
]

_Q = re.compile(r"^Question: (.*)$", re.M)


def recorded_responder() -> Callable[[str, str], str]:
    """Replays each case's model outputs: the SQL for the schema prompt, the answer otherwise."""
    by_q = {c["question"]: c for c in CASES}

    def respond(system: str, prompt: str) -> str:
        m = _Q.search(prompt)
        case = by_q.get(m.group(1).strip()) if m else None
        if case is None:
            return ""
        if "Schema:" in prompt:
            return f"```sql\n{case['sql']}\n```"
        return case["answer"]

    return respond


def _check(rows: list[list[Any]], expect: dict[str, Any]) -> list[str]:
    errs = []
    if "count" in expect and len(rows) != expect["count"]:
        errs.append(f"rows {len(rows)} != {expect['count']}")
    cells = {str(c) for r in rows for c in r}
    for v in expect.get("contains", []):
        if str(v) not in cells:
            errs.append(f"missing {v!r}")
    return errs


def run_eval(store, provider: Optional[Any]) -> dict[str, Any]:
    """Run every case through SecurityCopilot.ask with ``provider`` (None = offline rule mode,
    only the cases with ``offline_intent``). Returns {passed, failed: [(question, errors)], results}."""
    passed, failed, results = 0, [], []
    prev = llm._override
    try:
        llm.set_provider(provider)
        for case in CASES:
            if provider is None and not case.get("offline_intent"):
                continue
            calls_before = len(getattr(provider, "calls", []))
            cp = SecurityCopilot(store, use_llm=provider is not None)
            res = cp.ask(case["question"])
            errs: list[str] = []
            if provider is None:
                if res["intent"] != case["offline_intent"]:
                    errs.append(f"intent {res['intent']} != {case['offline_intent']}")
                errs += _check(res["rows"], case.get("expect_offline", case["expect"]))
            elif case.get("no_model"):
                if res["mode"] != "offline" or len(getattr(provider, "calls", [])) != calls_before:
                    errs.append("identifier paste reached the model")
                errs += _check(res["rows"], case["expect"])
            else:
                if res["mode"] != "llm":
                    errs.append(f"mode {res['mode']}: {res.get('error', '')}")
                if res["sql"] != sanitize(case["sql"]):
                    errs.append(f"executed SQL differs: {res['sql']!r}")
                errs += _check(res["rows"], case["expect"])
                if not res["answer"].startswith(case["answer"]):
                    errs.append(f"answer {res['answer'][:80]!r}")
            if res.get("citations", {}).get("queries") != [res["sql"]] or "Sources:" not in res.get("answer", ""):
                errs.append("answer does not cite its SQL")
            results.append({"question": case["question"], "mode": res["mode"], "ok": not errs, "errors": errs})
            if errs:
                failed.append((case["question"], errs))
            else:
                passed += 1
    finally:
        llm.set_provider(prev)
    return {"passed": passed, "failed": failed, "results": results}


# ---------------------------------------------------------------- engine parity (delta r2 #8)
# The copilot must never contradict the engine. Each case is a copilot question and the CLI
# output it must agree with, on a Go-ingested estate (tests/test_copilot_parity.py runs it on the
# lab). CLI exposure widths map onto copilot verdicts: wide/narrow -> exposed (or unknown:
# exposed, inferred), blocked -> blocked, a suppressed (trusted/private) exposure -> not_exposed.
PARITY_CASES: list[dict[str, Any]] = [
    {"question": "what is exposed to the internet?", "intent": "public_any",
     "cli": ["paths", "--exposures", "--format", "json"], "compare": "exposure_verdicts"},
    {"question": "top attack paths", "intent": "path_issues", "cli": ["paths"], "compare": "path_issue_count"},
]
_CLI_VERDICT = {"wide": {"exposed", "unknown"}, "narrow": {"exposed", "unknown"}, "entry": {"exposed", "unknown"},
                "blocked": {"blocked"}, "trusted": {"not_exposed"}, "private": {"not_exposed"}}
_PATH_ISSUES = re.compile(r"^(\d+) attack path Issue\(s\)", re.M)


def _cli(exe: str, db: str, config: Optional[str], args: list[str]) -> str:
    cmd = [exe] + (["-c", config] if config else []) + ["--db", db, "-q", "--no-network"] + args
    cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env={**os.environ, "CLOUD_POSTURE_NO_NETWORK": "1"})
    if cp.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {cp.stderr[-400:]}")
    return cp.stdout


def run_parity(db: str, exe: str, config: Optional[str] = None) -> dict[str, Any]:
    """Compare the offline copilot with the CLI on a Go-built database. Exposure: for every
    resource in ``paths --exposures --format json`` (exposures, suppressed, path entries) the
    copilot's verdict matches the CLI group, and for exposures and entries its status equals
    graph.Verdict's status and its wording is the verdict Label. Paths: one row per path Issue.
    Returns {checked, agreeing, disagreements, status_checked, status_agreeing, label_agreeing,
    status_disagreements, cli_path_issues, copilot_path_issues, copilot: {name: verdict}, cases}."""
    cp = SecurityCopilot(db, use_llm=False, cli=exe, cli_config=config)
    out: dict[str, Any] = {"checked": 0, "agreeing": 0, "disagreements": [], "status_checked": 0, "status_agreeing": 0,
                           "label_agreeing": 0, "status_disagreements": [], "cases": []}
    for case in PARITY_CASES:
        res = cp.ask(case["question"])
        ok = res["intent"] == case["intent"]
        text = _cli(exe, db, config, case["cli"])
        if case["compare"] == "exposure_verdicts":
            doc = json.loads(text)
            cols = res["columns"]
            rows = {r[cols.index("resource_id")]: dict(zip(cols, r)) for r in res["rows"]} if "verdict" in cols else {}
            out["copilot"] = {d["resource_name"]: d["verdict"] for d in rows.values()}
            seen: set[str] = set()
            for group in ("suppressed", "exposures", "entries"):
                for e in doc.get(group) or []:
                    nid, name = e["node_id"], e.get("name") or e["node_id"]
                    if nid in seen:
                        continue
                    seen.add(nid)
                    got = rows.get(nid, {})
                    out["checked"] += 1
                    if got.get("verdict") in _CLI_VERDICT.get(e["width"], {e["width"]}):
                        out["agreeing"] += 1
                    else:
                        out["disagreements"].append((name, e["width"], got.get("verdict")))
                        ok = False
                    if group == "suppressed":
                        continue
                    v = e.get("verdict") or {}
                    out["status_checked"] += 1
                    st_ok = got.get("status") == v.get("status", "")
                    one = cp.ask(f"is {name} exposed to the internet?")  # the answer prints the engine's Label
                    lb_ok = got.get("label") == v.get("label", "") and one["intent"] == "exposure_verdict" and (
                        not v.get("label") or v["label"] in one["answer"])
                    out["status_agreeing"] += st_ok
                    out["label_agreeing"] += lb_ok
                    if not (st_ok and lb_ok):
                        out["status_disagreements"].append((name, v.get("status"), got.get("status"), v.get("label"), got.get("label")))
                        ok = False
        elif case["compare"] == "path_issue_count":
            m = _PATH_ISSUES.search(text)
            out["cli_path_issues"] = int(m.group(1)) if m else 0
            sup = int(res["rows"][0][res["columns"].index("suppressed_path_issues")]) if res["rows"] else 0
            out["copilot_path_issues"] = len(res["rows"]) + sup
            ok = ok and out["cli_path_issues"] == out["copilot_path_issues"]
        out["cases"].append({"question": case["question"], "intent": res["intent"], "ok": ok})
    return out


# ---------------------------------------------------------------- independent engine parity (verify-5)
# run_parity above is circular for status/label: the verdict overlay copies `paths --exposures`
# into the copilot's answer, and the comparison reads that same output back. run_engine_parity
# turns the overlay off, so the copilot answers from its own SQL over the stored graph and
# Issues, and compares that with the engine's data: graph.Verdict per node (the Go struct, from
# `paths --exposures --format json`) and the stored path Issues (`issues --kind path --json`), by
# Issue id, band and score, not by counting lines of CLI text.
# Verification 6: "unknown" accepts only "unknown" (reading unknown as exposed hid a lax mapping).
_VERDICT_STATUS = {"reachable": {"exposed"}, "unknown": {"unknown"}, "blocked": {"blocked"}}


class _NoOverlay(SecurityCopilot):
    def engine_verdicts(self):  # the copilot's own derivation only
        return None


def run_engine_parity(db: str, exe: str, config: Optional[str] = None) -> dict[str, Any]:
    """Copilot (overlay off) vs engine data on a Go-built database. Returns {verdicts_checked,
    verdict_disagreements: [(name, engine status|group, copilot verdict)], engine_path_issues,
    copilot_path_issues, missing_issues, extra_issues, issue_field_disagreements, overlay_calls}."""
    cp = _NoOverlay(db, use_llm=False)
    out: dict[str, Any] = {"verdicts_checked": 0, "verdict_disagreements": [], "issue_field_disagreements": []}
    doc = json.loads(_cli(exe, db, config, ["paths", "--exposures", "--format", "json"]))
    res = cp.ask("what is exposed to the internet?")
    cols = res["columns"]
    got = {r[cols.index("resource_id")]: r[cols.index("verdict")] for r in res["rows"]} if "verdict" in cols else {}
    out["overlay_columns"] = [c for c in ("status", "label") if c in cols]  # must be [] (overlay off)
    seen: set[str] = set()
    for group in ("suppressed", "exposures", "entries"):
        for e in doc.get(group) or []:
            nid = e["node_id"]
            if nid in seen:
                continue
            seen.add(nid)
            out["verdicts_checked"] += 1
            if group == "suppressed":
                want, label = {"not_exposed"}, "suppressed"
            else:
                status = (e.get("verdict") or {}).get("status", "")
                want, label = _VERDICT_STATUS.get(status, {status}), status
            if got.get(nid) not in want:
                out["verdict_disagreements"].append((e.get("name") or nid, label, got.get(nid)))
    # The engine side is the traversal's own grouping (`paths --format json --grouped`), not the
    # issues table the copilot reads (Verification 6: both sides used to read the same rows).
    eng = json.loads(_cli(exe, db, config, ["paths", "--format", "json", "--grouped", "--no-dead-ends"]) or "[]")
    eng = {i["issue_id"]: i for i in eng}
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:  # an Issue that is not open (the Go store's open set: open, reopened) is in neither view
        # (state only, no scores read); verified_fixed / pending_verification are closed too
        closed = {r[0] for r in con.execute("SELECT id FROM issues WHERE kind = 'path' AND COALESCE(state, '') NOT IN ('open', 'reopened', '')")}
    finally:
        con.close()
    eng = {k: v for k, v in eng.items() if k not in closed}
    pres = cp.ask("top attack paths")
    pc = pres["columns"]
    mine = {r[pc.index("issue_id")]: dict(zip(pc, r)) for r in pres["rows"]} if "issue_id" in pc else {}
    out["engine_path_issues"], out["copilot_path_issues"] = len(eng), len(mine)
    out["missing_issues"] = sorted(set(eng) - set(mine))
    out["extra_issues"] = sorted(set(mine) - set(eng))
    for iid in set(eng) & set(mine):
        e, m = eng[iid], mine[iid]
        if (abs(float(e.get("score") or 0) - float(m.get("score") or 0)) > 1e-6
                or str(e.get("band") or e.get("severity", "")).upper() != str(m.get("band") or "").upper()
                or int(e.get("variants") or 0) != int(m.get("variants") or 0)):
            out["issue_field_disagreements"].append((iid, e.get("score"), m.get("score"), e.get("band"), m.get("band")))
    return out
