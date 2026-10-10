"""Copilot parity with the engine (delta r2 shortfall #8): offline intents answer from the
exposure verdicts (graph internet edges carrying REACH / exposure labels) and from path Issues,
never from raw findings, and "who can" is answered by the Go ``who-can --json``."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys

import pytest

from nimbus.ai.copilot import SecurityCopilot
from nimbus.store import Store

from .conftest import F

PII = "arn:aws:s3:::lab-customer-pii"
SHARED = "arn:aws:s3:::lab-shared-reports"
LEDGER = "arn:aws:rds:us-east-1:111111111111:db:lab-ledger"
ORDERS = "arn:aws:rds:us-east-1:111111111111:db:lab-orders"
SG = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"
WEB = "arn:aws:ec2:us-east-1:111111111111:instance/i-1"
JUMP = "arn:aws:ec2:us-east-1:111111111111:instance/i-2"
SFTP = "arn:aws:ec2:us-east-1:111111111111:instance/i-3"

ISSUE_COLS = ("id TEXT PRIMARY KEY, canonical_id TEXT NOT NULL, resource_id TEXT NOT NULL, provider TEXT, account TEXT, "
              "severity TEXT NOT NULL, state TEXT NOT NULL, first_seen TEXT, last_seen TEXT, resolved_at TEXT, "
              "finding_ids TEXT NOT NULL, sources TEXT NOT NULL, confidence REAL NOT NULL, kind TEXT NOT NULL, title TEXT, "
              "entry_id TEXT NOT NULL DEFAULT '', anchor_id TEXT, rule_id TEXT, secondary_key TEXT, secondary_keys TEXT, "
              "path_ids TEXT, score REAL, band TEXT, confidence_label TEXT, toxic_combination TEXT, reason TEXT, expires_at TEXT")


def _node(i, typ, cls, name, **attrs):
    return {"id": i, "type": typ, "class": cls, "name": name, "provider": "aws", "account": "111111111111",
            "attributes": attrs, "finding_ids": [f"f-{name}"]}


@pytest.fixture
def engine_db(tmp_path):
    """A Go-shaped estate: findings that *claim* exposure, graph verdicts that decide it, path Issues."""
    s = Store(tmp_path / "posture.db")
    s.upsert_findings([
        F(check_id="s3_bucket_public_access", canonical_id="S3_PUBLIC_BUCKET", title="public", severity="CRITICAL",
          resource={"id": PII, "type": "aws_s3_bucket", "name": "lab-customer-pii"}, weaknesses=["PUBLIC_DATA_STORE"]),
        F(check_id="s3_bucket_public_access", canonical_id="S3_PUBLIC_BUCKET", title="Principal * (org condition)", severity="HIGH",
          resource={"id": SHARED, "type": "aws_s3_bucket", "name": "lab-shared-reports"}, weaknesses=["PUBLIC_DATA_STORE"]),
        F(check_id="rds_instance_no_public_access", canonical_id="RDS_PUBLIC", title="public flag", severity="CRITICAL",
          resource={"id": LEDGER, "type": "aws_db_instance", "name": "lab-ledger"}, weaknesses=["PUBLIC_NETWORK_EXPOSURE", "DATABASE"]),
        F(check_id="rds_instance_no_public_access", canonical_id="RDS_PUBLIC", title="public", severity="CRITICAL",
          resource={"id": ORDERS, "type": "aws_db_instance", "name": "lab-orders"}, weaknesses=["PUBLIC_NETWORK_EXPOSURE", "DATABASE"]),
    ])
    nodes = [
        {"id": "internet", "type": "internet", "class": "internet", "name": "Internet"},
        _node(PII, "aws_s3_bucket", "datastore", "lab-customer-pii"),
        _node(SHARED, "aws_s3_bucket", "datastore", "lab-shared-reports"),
        _node(LEDGER, "aws_db_instance", "datastore", "lab-ledger", reachability="blocked",
              reach_blocker="route table rtb-1 has no route to an internet gateway"),
        _node(ORDERS, "aws_db_instance", "datastore", "lab-orders"),
        _node(SG, "aws_security_group", "network", "lab-web-open"),
        _node(WEB, "aws_instance", "compute", "lab-web-01"),
        _node(JUMP, "aws_instance", "compute", "lab-jump-01"),
        _node(SFTP, "aws_instance", "compute", "lab-sftp-01"),
    ]
    edges = [
        {"from": "internet", "to": PII, "kind": "exposes", "attr": {"reachability": "reachable", "reach_confidence": "verified"}},
        {"from": "internet", "to": SHARED, "kind": "exposes", "attr": {
            "reachability": "reachable", "exposure": "private",
            "exposure_reason": "org-conditioned (Principal * limited by aws:PrincipalOrgID)"}},
        {"from": "internet", "to": LEDGER, "kind": "exposes", "attr": {
            "reachability": "blocked", "reach_blocker": "route table rtb-1 has no route to an internet gateway"}},
        {"from": "internet", "to": ORDERS, "kind": "exposes", "attr": {
            "reachability": "unknown", "reach_unknown": "security group rules not collected"}},
        {"from": "internet", "to": SG, "kind": "exposes", "attr": {"reachability": "reachable"}},
        {"from": SG, "to": JUMP, "kind": "allows_traffic_to"},  # only reachable through the SG
        {"from": "internet", "to": SFTP, "kind": "exposes", "attr": {
            "reachability": "blocked", "reach_blocker": "NACL acl-1 rule 90 denies 22/tcp"}},
        {"from": "internet", "to": WEB, "kind": "exposes", "attr": {"reachability": "reachable"}},
    ]
    s.replace_graph(nodes, edges)
    con = sqlite3.connect(s.path)
    con.execute(f"CREATE TABLE issues ({ISSUE_COLS})")
    rows = [  # 3 open path Issues grouping 5 hop variants, 1 suppressed path Issue, 1 single Issue
        ("i-pii", "PATH", PII, "Critical", "CRITICAL", "open", 10.0, "path", "Internet → lab-customer-pii", '["p1","p2"]', "internet"),
        ("i-web", "PATH", WEB, "High", "HIGH", "open", 7.6, "path", "Internet → lab-web-role", '["p3","p4"]', "internet"),
        ("i-orders", "PATH", ORDERS, "High", "HIGH", "open", 8.0, "path", "Internet → lab-orders", '["p5"]', "internet"),
        ("i-supp", "PATH", JUMP, "Medium", "MEDIUM", "suppressed", 5.0, "path", "Internet → lab-jump-01", '["p6"]', "internet"),
        ("i-single", "RDS_PUBLIC", LEDGER, "", "CRITICAL", "open", 9.8, "single", "RDS_PUBLIC on lab-ledger", None, ""),
    ]
    for (iid, cid, rid, band, sev, state, score, kind, title, pids, entry) in rows:
        con.execute("INSERT INTO issues (id, canonical_id, resource_id, provider, account, severity, state, finding_ids, sources, "
                    "confidence, kind, title, entry_id, anchor_id, rule_id, path_ids, score, band) VALUES "
                    "(?,?,?,'aws','111111111111',?,?,'[]','[\"native\"]',1.0,?,?,?,?,'traversal',?,?,?)",
                    (iid, cid, rid, sev, state, kind, title, entry, rid, pids, score, band or None))
    # A Go-built (or Go-upgraded) database carries the Go marker (internal/store/origin.go); the
    # copilot's overlay reads it (W7-POLISH _go_built via store_meta).
    con.execute("UPDATE store_meta SET v = 'go' WHERE k = 'built_by'")
    con.commit()
    con.close()
    return s


@pytest.fixture
def cp(engine_db, monkeypatch):
    monkeypatch.setenv("CLOUD_POSTURE_BIN", "/nonexistent/cloud-posture")  # DB-only verdicts here
    return SecurityCopilot(engine_db, use_llm=False)


def verdicts(res):
    cols = res["columns"]
    return {r[cols.index("resource_name")]: r[cols.index("verdict")] for r in res["rows"]}


def test_public_buckets_answers_from_exposure_verdicts(cp):
    res = cp.ask("Which S3 buckets are public?")
    assert res["intent"] == "public_buckets" and res["mode"] == "offline"
    assert "graph_edges" in res["sql"] and "weaknesses" not in res["sql"]  # findings only feed citations
    v = verdicts(res)
    assert v["lab-customer-pii"] == "exposed"
    assert v["lab-shared-reports"] == "not_exposed"  # org-conditioned: never "public"
    head = res["answer"].split("Not exposed")[0]
    assert "lab-customer-pii" in head and "lab-shared-reports" not in head
    assert "org-conditioned" in res["answer"]


def test_public_databases_blocked_and_unknown(cp):
    res = cp.ask("show me public databases")
    v = verdicts(res)
    assert v == {"lab-ledger": "blocked", "lab-orders": "unknown"}
    assert "no route to an internet gateway" in res["answer"]
    assert "lab-ledger" not in res["answer"].split("Blocked")[0]


def test_exposure_of_one_resource(cp):
    res = cp.ask("is lab-ledger exposed to the internet?")
    assert res["intent"] == "exposure_verdict"
    assert verdicts(res) == {"lab-ledger": "blocked"}
    res = cp.ask("is lab-jump-01 reachable from the internet?")
    assert verdicts(res) == {"lab-jump-01": "exposed"}  # through the exposed security group
    assert verdicts(cp.ask("is lab-sftp-01 public?")) == {"lab-sftp-01": "blocked"}


def test_internet_exposed_resources_lists_every_verdict(cp):
    res = cp.ask("what is exposed to the internet?")
    v = verdicts(res)
    assert v["lab-web-01"] == "exposed" and v["lab-shared-reports"] == "not_exposed" and v["lab-ledger"] == "blocked"
    cols = res["columns"]
    assert "reason" in cols and "finding_ids" in cols
    assert "f-lab-ledger" in res["citations"]["finding_ids"]


def test_top_attack_paths_are_path_issues_not_variants(cp):
    res = cp.ask("top attack paths")
    assert res["intent"] == "path_issues"
    assert "FROM issues" in res["sql"] and "attack_paths" not in res["sql"]
    ids = [r[res["columns"].index("issue_id")] for r in res["rows"]]
    assert ids == ["i-pii", "i-orders", "i-web"]  # open path Issues by score; suppressed excluded
    assert "1 suppressed" in res["answer"]
    assert set(res["citations"]["issue_ids"]) == {"i-pii", "i-orders", "i-web"}


def test_attack_paths_to_databases_use_issues(cp):
    res = cp.ask("attack paths to databases")
    assert res["intent"] == "path_issues"
    ids = [r[res["columns"].index("issue_id")] for r in res["rows"]]
    assert ids == ["i-orders"]


def test_top_risks_use_issue_bands(cp):
    res = cp.ask("what are my top risks?")
    assert res["intent"] == "top_risks" and "FROM issues" in res["sql"]
    ids = [r[res["columns"].index("issue_id")] for r in res["rows"]]
    assert "i-supp" not in ids and ids[0] == "i-pii"


def _fake_who_can(tmp_path, out):
    log = tmp_path / "args.json"
    exe = tmp_path / "cloud-posture"
    exe.write_text(f"#!{sys.executable}\nimport json, sys\nopen({str(log)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
                   f"print(json.dumps({out!r}))\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe, log


def test_who_can_read_bucket_calls_go_who_can(cp, tmp_path, monkeypatch):
    rows = [{"principal": "arn:aws:iam::111111111111:role/admin", "holder": "arn:aws:iam::111111111111:role/admin",
             "decision": "allow", "statement": "AdministratorAccess#0", "confidence": "verified", "because": "admin"}]
    exe, log = _fake_who_can(tmp_path, rows)
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    res = cp.ask("who can read lab-customer-pii")
    assert res["intent"] == "who_can" and res["mode"] == "offline"
    args = json.loads(log.read_text())
    assert args[args.index("who-can") + 1:args.index("who-can") + 3] == ["s3:GetObject", PII]
    assert "--json" in args and args[args.index("--db") + 1] == cp.store.path
    assert res["rows"][0][res["columns"].index("principal")] == "arn:aws:iam::111111111111:role/admin"
    assert "1 principal" in res["answer"] and "s3:GetObject" in res["answer"]


def test_who_can_explicit_action_and_arn(cp, tmp_path, monkeypatch):
    exe, log = _fake_who_can(tmp_path, [])
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    res = cp.ask(f"who can s3:PutObject on {SHARED}?")
    args = json.loads(log.read_text())
    assert args[args.index("who-can") + 1:args.index("who-can") + 3] == ["s3:PutObject", SHARED]
    assert res["intent"] == "who_can" and res["rows"] == []


def test_who_can_without_binary_says_how(cp, monkeypatch):
    monkeypatch.setenv("CLOUD_POSTURE_BIN", "/nonexistent/cloud-posture")
    monkeypatch.setenv("PATH", "/nonexistent")
    res = cp.ask("who can access lab-customer-pii")
    assert res["intent"] == "who_can"
    assert f"cloud-posture who-can s3:GetObject {PII}" in res["answer"]


def test_llm_prompt_points_at_issues_and_verdicts():
    from nimbus.ai import copilot
    assert "issues" in copilot.SQL_SYSTEM and "reachability" in copilot.SQL_SYSTEM


def test_python_only_store_keeps_finding_intents(seeded):
    """No Go issues table: the attack-path intent still reads attack_paths (fallback)."""
    res = SecurityCopilot(seeded, use_llm=False).ask("attack paths to RDS")
    assert res["intent"] == "attack_paths"


def _fake_paths_cli(tmp_path, doc):
    log = tmp_path / "paths-args.json"
    exe = tmp_path / "cp-paths"
    exe.write_text(f"#!{sys.executable}\nimport json, sys\nopen({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                   f"print(json.dumps({doc!r}))\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe, log


def _row(nid, name, width, status, label):
    return {"node_id": nid, "name": name, "width": width, "verdict": {"node_id": nid, "status": status, "label": label}}


def test_exposure_wording_comes_from_graph_verdict_when_go_is_available(engine_db, tmp_path, monkeypatch):
    doc = {"exposures": [_row(LEDGER, "lab-ledger", "blocked", "blocked", "not exposed (blocked: rtb-1 has no IGW route)")],
           "suppressed": [_row(SHARED, "lab-shared-reports", "private", "reachable", "internet reachable (wide)")],
           "entries": [_row(ORDERS, "lab-orders", "entry", "reachable", "internet reachable (wide)"),
                       _row(PII, "lab-customer-pii", "entry", "reachable", "internet reachable (wide)")]}
    exe, log = _fake_paths_cli(tmp_path, doc)
    monkeypatch.setenv("CLOUD_POSTURE_BIN", str(exe))
    c = SecurityCopilot(engine_db, use_llm=False)
    res = c.ask("show me public databases")
    args = json.loads(log.read_text().splitlines()[0])
    assert args[args.index("paths"):] == ["paths", "--exposures", "--format", "json"] and args[args.index("--db") + 1] == c.store.path
    cols = res["columns"]
    rows = {r[cols.index("resource_name")]: dict(zip(cols, r)) for r in res["rows"]}
    # the engine verdict wins over the DB re-derivation (orders: DB unknown, graph.Verdict reachable)
    assert rows["lab-orders"]["status"] == "reachable" and rows["lab-orders"]["verdict"] == "exposed"
    assert rows["lab-ledger"]["status"] == "blocked" and rows["lab-ledger"]["verdict"] == "blocked"
    assert rows["lab-ledger"]["label"] == "not exposed (blocked: rtb-1 has no IGW route)"
    assert "not exposed (blocked: rtb-1 has no IGW route)" in res["answer"]
    assert "internet reachable (wide)" in res["answer"]
    # a suppressed (org-conditioned) exposure is never reported as public
    v = verdicts(c.ask("which s3 buckets are public?"))
    assert v["lab-shared-reports"] == "not_exposed" and v["lab-customer-pii"] == "exposed"
