"""Security copilot: natural language -> SQL over the posture DB, investigations, guidance, policy.

Offline mode recognises common intents with rules; with ANTHROPIC_API_KEY set, Claude writes the
SQL from a schema prompt and summarises the result. All SQL runs through ``sqlsafety.sanitize``
and on a read-only SQLite connection.
"""
from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from importlib import resources
from typing import Any, Optional

from .. import catalog as cat
from ..models import AttackPath, Finding
from ..store import Store
from .explain import explain_attack_path_offline, explain_finding
from .llm import complete, extract_code, llm_available
from .sqlsafety import MAX_ROWS, UnsafeSQL, sanitize

FINDING_COLS = "id, canonical_id, severity, provider, account, region, resource_id, resource_name, resource_type, title"
SEV_ORDER = ("CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END")

DATASTORE_TYPES = ("bucket", "storage", "blob", "gcs", "objectstorage")
DB_TYPES = ("db_instance", "rds", "sql", "database", "dynamodb", "cosmos", "redshift", "aurora")
COMPUTE_TYPES = ("instance", "virtual_machine", "_vm", "compute", "lambda", "function", "pod", "container")


def _weak(w: str) -> str:
    return f"weaknesses LIKE '%\"{w}\"%'"


def _type_like(words: tuple[str, ...]) -> str:
    return "(" + " OR ".join(f"lower(resource_type) LIKE '%{w}%'" for w in words) + ")"


def _fail(*conds: str, order: str = SEV_ORDER) -> str:
    where = " AND ".join(("status = 'FAIL'",) + conds)
    return f"SELECT {FINDING_COLS} FROM findings WHERE {where} ORDER BY {order}, provider, account"


@dataclass
class Intent:
    name: str
    sql: str
    params: tuple = ()
    description: str = ""


def _provider_filter(q: str) -> str:
    for p, words in (("aws", ("aws", "amazon")), ("azure", ("azure",)), ("gcp", ("gcp", "google")),
                     ("kubernetes", ("kubernetes", "k8s")), ("github", ("github",)), ("okta", ("okta",)), ("m365", ("m365", "office"))):
        if any(re.search(rf"\b{w}\b", q) for w in words):
            return f"provider = '{p}'"
    return ""


def rule_based_sql(question: str) -> Optional[Intent]:
    """Map a question to SQL with simple rules. Returns None when no intent matches."""
    q = question.lower().strip()
    prov = _provider_filter(q)
    extra = (prov,) if prov else ()

    # compliance status for a control, e.g. "compliance status for CIS 1.10", "soc2 CC6.1", "control AC-6"
    m = re.search(r"\b(cc\d\.\d|a\d\.\d|c\d\.\d|a\.\d+(?:\.\d+)*|[a-z]{2}-\d+(?:\(\d+\))?|\d+\.\d+(?:\.\d+)*|art\.\s?\d+|164\.\d+[\w().]*)\b", q)
    if m and any(k in q for k in ("control", "compliance", "cis", "soc", "nist", "pci", "iso", "hipaa", "gdpr", "status")):
        raw_ctrl = question[m.start():m.end()].strip()
        if raw_ctrl.lower().startswith("art"):
            ctrl = "Art." + re.sub(r"\D", "", raw_ctrl)
        elif raw_ctrl[0].isdigit():
            ctrl = raw_ctrl
        else:
            ctrl = raw_ctrl.upper()
        from ..compliance import weakness_mappings

        weak = sorted({w for w, m2 in weakness_mappings().items() for ctrls in m2.values() if ctrl in ctrls})
        conds = [f"EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(findings.compliance) AND findings.compliance != 'null' "
                 f"THEN findings.compliance ELSE '{{}}' END) fw, json_each(fw.value) c WHERE c.value = '{ctrl}')"]
        conds += [_weak(w) for w in weak]
        sql = (f"SELECT '{ctrl}' AS control_id, provider, account, "
               "CASE WHEN SUM(status = 'FAIL') > 0 THEN 'FAIL' WHEN SUM(status = 'PASS') > 0 THEN 'PASS' ELSE 'NOT_ASSESSED' END AS status, "
               "SUM(status = 'FAIL') AS failed, SUM(status = 'PASS') AS passed, "
               "group_concat(DISTINCT CASE WHEN status = 'FAIL' THEN canonical_id END) AS failing_checks "
               f"FROM findings WHERE ({' OR '.join(conds)}) GROUP BY provider, account ORDER BY failed DESC")
        return Intent("compliance_control_status", sql, description=f"Compliance status of control {ctrl}")

    if "attack path" in q or "attack-path" in q or "path to" in q or "paths to" in q:
        cond = ""
        if any(w in q for w in ("rds", "database", "db", "sql", "data")):
            cond = (" WHERE (lower(doc) LIKE '%database%' OR lower(doc) LIKE '%rds%' OR lower(doc) LIKE '%db_instance%' "
                    "OR lower(doc) LIKE '%sql%')")
        elif prov:
            cond = f" WHERE {prov}"
        sql = ("SELECT id, rule_id, name, json_extract(doc, '$.impact') AS impact, provider, account, severity, score, "
               f"json_array_length(doc, '$.steps') AS steps FROM attack_paths{cond} ORDER BY score DESC")
        return Intent("attack_paths", sql, description="Attack paths" + (" reaching databases" if "lower(doc)" in cond else ""))

    if re.search(r"\b(stale|unused|old|rotat\w*)\b.*\b(key|keys|credential|credentials|token)", q) or "stale key" in q:
        return Intent("stale_credentials", _fail(_weak("STALE_CREDENTIALS"), *extra), description="Stale credentials")

    if "privileged" in q and any(w in q for w in ("pod", "pods", "container", "containers")):
        sql = ("SELECT COALESCE(json_extract(doc, '$.resource.attributes.namespace'), 'default') AS namespace, "
               "resource_name AS pod, canonical_id, severity, account FROM findings WHERE status = 'FAIL' AND "
               f"({_weak('PRIVILEGED_CONTAINER')} OR {_weak('HOST_ACCESS')}) ORDER BY namespace, {SEV_ORDER}")
        return Intent("privileged_pods", sql, description="Privileged pods")

    if re.search(r"\b(mfa|2fa|multi.?factor)\b", q):
        return Intent("no_mfa", _fail(_weak("NO_MFA"), *extra), description="Identities without MFA")

    if re.search(r"\b(unencrypted|not encrypted|without encryption|no encryption|encryption)\b", q):
        conds = [f"({_weak('UNENCRYPTED_AT_REST')} OR {_weak('UNENCRYPTED_IN_TRANSIT')})"]
        if re.search(r"\b(bucket|buckets|storage|blob)\b", q):
            conds.append(_type_like(DATASTORE_TYPES))
        elif re.search(r"\b(database|databases|db|rds|sql)\b", q):
            conds.append(_type_like(DB_TYPES))
        elif re.search(r"\b(volume|volumes|disk|disks|ebs)\b", q):
            conds.append(_type_like(("volume", "disk", "ebs")))
        return Intent("unencrypted", _fail(*conds, *extra), description="Unencrypted resources")

    if re.search(r"\b(public|exposed|internet|open)\b", q):
        if re.search(r"\b(bucket|buckets|storage|blob|blobs|s3|gcs)\b", q):
            return Intent("public_buckets", _fail(f"({_weak('PUBLIC_DATA_STORE')} OR ({_weak('PUBLIC_NETWORK_EXPOSURE')} AND {_type_like(DATASTORE_TYPES)}))", *extra),
                          description="Public storage buckets")
        if re.search(r"\b(database|databases|db|dbs|rds|sql)\b", q):
            return Intent("public_databases", _fail(f"({_weak('DATABASE')} OR {_type_like(DB_TYPES)})",
                                                    f"({_weak('PUBLIC_NETWORK_EXPOSURE')} OR {_weak('PUBLIC_DATA_STORE')})", *extra),
                          description="Publicly reachable databases")
        if re.search(r"\b(instance|instances|vm|vms|server|servers|compute|ec2|machines?)\b", q):
            return Intent("public_instances", _fail(_weak("PUBLIC_NETWORK_EXPOSURE"), _type_like(COMPUTE_TYPES + ("security_group", "firewall", "nsg")),
                                                    "NOT " + _type_like(DB_TYPES), "NOT " + _weak("DATABASE"), *extra),
                          description="Internet-exposed compute")
        return Intent("public_any", _fail(f"({_weak('PUBLIC_NETWORK_EXPOSURE')} OR {_weak('PUBLIC_DATA_STORE')})", *extra),
                      description="Internet-exposed resources")

    if re.search(r"\b(top|riskiest|highest|worst|most critical|prioriti[sz]e)\b", q) and re.search(r"\b(risk|risks|issue|issues|finding|findings|critical)\b", q):
        sql = (f"SELECT f.id, f.canonical_id, f.severity, f.provider, f.account, f.resource_name, f.title, "
               "(SELECT COUNT(*) FROM attack_paths ap WHERE ap.doc LIKE '%' || f.id || '%') AS attack_paths "
               f"FROM findings f WHERE f.status = 'FAIL'{' AND f.' + prov if prov else ''} "
               f"ORDER BY {SEV_ORDER.replace('severity', 'f.severity')}, attack_paths DESC LIMIT 20")
        return Intent("top_risks", sql, description="Top risks (severity, then attack-path membership)")

    m = re.search(r"\bby (account|provider|severity|region|source|service|resource type|type|check)\b", q)
    if m or re.search(r"\b(count|how many|breakdown|summary)\b", q):
        dims = {"account": "account", "provider": "provider", "severity": "severity", "region": "region", "source": "source",
                "service": "resource_type", "resource type": "resource_type", "type": "resource_type", "check": "canonical_id"}
        dim = dims[m.group(1)] if m else "severity"
        sql = (f"SELECT {dim}, COUNT(*) AS failed, SUM(severity = 'CRITICAL') AS critical, SUM(severity = 'HIGH') AS high "
               f"FROM findings WHERE status = 'FAIL'{' AND ' + prov if prov else ''} GROUP BY {dim} ORDER BY failed DESC")
        return Intent("findings_by_" + dim, sql, description=f"Failed findings grouped by {dim}")

    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{sev}\b", q):
            return Intent("findings_by_severity", _fail(f"severity = '{sev.upper()}'", *extra), description=f"{sev.upper()} findings")
    if prov and re.search(r"\b(finding|findings|issue|issues)\b", q):
        return Intent("findings_by_provider", _fail(prov), description=f"Failed findings ({prov})")
    return None


SQL_SYSTEM = ("You translate security questions into a single SQLite SELECT statement over a cloud security posture "
              "database. Use only the tables/views listed. JSON columns (weaknesses, compliance, tags, doc) can be "
              "queried with json_extract/json_each or LIKE '%\"WEAKNESS\"%'. Failed findings have status='FAIL'. "
              "Return only the SQL in one ```sql code block.")
ANSWER_SYSTEM = ("You are a cloud security analyst. Answer the user's question from the SQL result in at most 6 "
                 "sentences, naming the most important resources and the next action. Do not invent data.")


class SecurityCopilot:
    def __init__(self, store: Store | str | None = None, use_llm: Optional[bool] = None):
        self.store = store if isinstance(store, Store) else Store(store, create=False) if store else Store()
        self.use_llm = llm_available() if use_llm is None else use_llm

    # ---------------------------------------------------------------- ask
    def nl_to_sql(self, question: str) -> tuple[str, str, str]:
        """Return (sql, intent, mode)."""
        if self.use_llm:
            text = complete(SQL_SYSTEM, f"Schema:\n{self.store.schema_text()}\n\nWeakness vocabulary: PUBLIC_DATA_STORE, "
                            "PUBLIC_NETWORK_EXPOSURE, UNENCRYPTED_AT_REST, UNENCRYPTED_IN_TRANSIT, NO_LOGGING, NO_MFA, "
                            "OVERPRIVILEGED_IDENTITY, IMDSV1_ENABLED, PRIVILEGED_CONTAINER, HOST_ACCESS, SECRET_EXPOSURE, "
                            "STALE_CREDENTIALS, CROSS_ACCOUNT_TRUST, NO_BACKUP, UNPATCHED, DATABASE, CLUSTER_ADMIN\n\n"
                            f"Question: {question}", max_tokens=2000, effort="low")
            if text:
                return extract_code(text).strip(), "llm", "llm"
        intent = rule_based_sql(question)
        if intent is None:
            return "", "unknown", "offline"
        return intent.sql, intent.name, "offline"

    def run_sql(self, sql: str) -> tuple[str, list[str], list[list[Any]]]:
        safe = sanitize(sql, MAX_ROWS)
        cols, rows = self.store.query(safe)
        return safe, cols, rows

    def ask(self, question: str) -> dict[str, Any]:
        sql, intent, mode = self.nl_to_sql(question)
        out: dict[str, Any] = {"question": question, "intent": intent, "mode": mode, "sql": sql, "columns": [], "rows": []}
        if not sql:
            out["answer"] = ("I could not map that question to a query offline. Try: 'public buckets', 'unencrypted databases', "
                             "'users without MFA', 'attack paths to RDS', 'top risks', 'findings by account', 'stale keys', "
                             "'privileged pods', or 'compliance status for CIS 1.10'. Set ANTHROPIC_API_KEY for free-form questions.")
            return out
        try:
            out["sql"], out["columns"], out["rows"] = self.run_sql(sql)
        except UnsafeSQL as exc:
            out["error"] = f"rejected unsafe SQL: {exc}"
            out["answer"] = out["error"]
            return out
        except Exception as exc:  # sqlite errors from model SQL; retry offline once
            if mode == "llm":
                intent_obj = rule_based_sql(question)
                if intent_obj:
                    out.update(intent=intent_obj.name, mode="offline")
                    out["sql"], out["columns"], out["rows"] = self.run_sql(intent_obj.sql)
                else:
                    out["error"] = str(exc)
                    out["answer"] = f"Query failed: {exc}"
                    return out
            else:
                out["error"] = str(exc)
                out["answer"] = f"Query failed: {exc}"
                return out
        out["answer"] = self._summarize(question, out)
        return out

    def _summarize(self, question: str, res: dict[str, Any]) -> str:
        cols, rows = res["columns"], res["rows"]
        if self.use_llm and res["mode"] == "llm":
            sample = [dict(zip(cols, r)) for r in rows[:50]]
            text = complete(ANSWER_SYSTEM, f"Question: {question}\nSQL: {res['sql']}\nRows ({len(rows)} total, first 50):\n"
                            + json.dumps(sample, default=str), max_tokens=1500, effort="low")
            if text:
                return text
        if not rows:
            return "No matching results - nothing currently failing for this question."
        n = len(rows)
        more = " (showing the first 200)" if n >= MAX_ROWS else ""
        preview = []
        for r in rows[:5]:
            d = dict(zip(cols, r))
            label = d.get("resource_name") or d.get("name") or d.get("pod") or d.get("control_id") or d.get(cols[0])
            bits = [str(d[k]) for k in ("severity", "canonical_id", "provider", "account", "status", "score") if d.get(k) not in (None, "")]
            preview.append(f"{label} ({', '.join(bits)})" if bits else str(label))
        return f"{n} result(s){more}. Top: " + "; ".join(preview) + "."

    # ---------------------------------------------------------------- investigate
    def blast_radius(self, start: str, max_hops: int = 4) -> dict[str, Any]:
        nodes, edges = self.store.graph()
        by_id = {n.get("id"): n for n in nodes}
        out_edges: dict[str, list[dict]] = {}
        for e in edges:
            out_edges.setdefault(e["from"], []).append(e)
        seen = {start: 0}
        via: dict[str, tuple[str, str]] = {}
        dq = deque([start])
        while dq:
            cur = dq.popleft()
            if seen[cur] >= max_hops:
                continue
            for e in out_edges.get(cur, []):
                nxt = e["to"]
                if nxt not in seen:
                    seen[nxt] = seen[cur] + 1
                    via[nxt] = (cur, e["kind"])
                    dq.append(nxt)
        reachable = []
        for nid, depth in sorted(seen.items(), key=lambda kv: (kv[1], kv[0])):
            if nid == start:
                continue
            n = by_id.get(nid, {"id": nid})
            path, cur = [], nid
            while cur in via:
                prev, kind = via[cur]
                path.append(f"{prev} -[{kind}]-> {cur}")
                cur = prev
            sensitive = bool(n.get("sensitive")) or n.get("class") == "datastore"
            reachable.append({"id": nid, "name": n.get("name", nid), "type": n.get("type", ""), "class": n.get("class", ""),
                              "hops": depth, "sensitive": sensitive, "path": list(reversed(path))})
        return {"start": start, "max_hops": max_hops, "reachable": reachable,
                "sensitive": [r for r in reachable if r["sensitive"]]}

    def investigate(self, finding_id: str) -> dict[str, Any]:
        f = self.store.finding(finding_id)
        if f is None:
            raise KeyError(f"finding {finding_id} not found")
        paths = [p for p in self.store.attack_paths() if f.id in p.finding_ids or any(s.finding_id == f.id for s in p.steps)]
        related = [x for x in self.store.findings(resource_id=f.resource.id, status="FAIL") if x.id != f.id] if f.resource.id else []
        radius = self.blast_radius(f.resource.id) if f.resource.id else {"reachable": [], "sensitive": []}
        expl = explain_finding(f, paths, use_llm=self.use_llm)
        summary = (f"{f.severity.value} {f.canonical_id} on {f.resource.name or f.resource.id}: part of {len(paths)} attack path(s); "
                   f"{len(radius['reachable'])} resource(s) reachable within 4 hops, {len(radius['sensitive'])} sensitive; "
                   f"{len(related)} other open finding(s) on the same resource.")
        return {
            "finding": f.to_doc(),
            "attack_paths": [{**p.to_doc(), "explanation": explain_attack_path_offline(p)} for p in paths],
            "related_findings": [{"id": x.id, "canonical_id": x.canonical_id, "severity": x.severity.value, "title": x.title} for x in related],
            "blast_radius": radius,
            "explanation": expl["explanation"],
            "summary": summary,
            "next_steps": [f"cloud-posture fix --finding {f.canonical_id} --generate-terraform",
                           f"nimbus explain {f.id}"],
        }

    # ---------------------------------------------------------------- guidance
    def remediation_guidance(self, canonical_id: str) -> dict[str, Any]:
        cid = canonical_id.upper()
        e = cat.entry(cid) or {}
        open_findings = self.store.findings(canonical_id=cid, status="FAIL") if self.store.exists() else []
        rem = next((f.remediation for f in open_findings if f.remediation), "")
        steps = [
            f"Identify the {len(open_findings)} affected resource(s): " + ", ".join(sorted({f.resource.name or f.resource.id for f in open_findings})[:10])
            if open_findings else "No open findings for this check in the database.",
            rem or f"Apply the secure configuration: {e.get('title', cid)} must be remediated.",
            f"Generate IaC: cloud-posture fix --finding {cid} --generate-terraform (templates: {', '.join(e.get('remediation') or []) or 'generic stub'})",
            "Re-scan to verify: cloud-posture scan, then nimbus report to refresh compliance evidence.",
        ]
        out = {"canonical_id": cid, "title": e.get("title", ""), "severity": e.get("severity", ""), "weaknesses": e.get("weaknesses", []),
               "compliance": e.get("compliance", {}), "open_findings": len(open_findings), "steps": steps, "mode": "offline"}
        if self.use_llm:
            text = complete("You are a cloud security engineer. Give concise, ordered remediation guidance with "
                            "console, CLI and IaC options, plus how to verify. Under 250 words.",
                            json.dumps({k: v for k, v in out.items() if k != "steps"} | {"remediation": rem}, default=str),
                            max_tokens=2000, effort="low")
            if text:
                out.update(guidance=text, mode="llm")
        out.setdefault("guidance", "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps)))
        return out

    # ---------------------------------------------------------------- policy
    def generate_policy(self, requirement: str) -> dict[str, Any]:
        return generate_policy(requirement, use_llm=self.use_llm)


POLICY_RULES = [
    ("cluster_admin_binding", ("cluster-admin", "cluster admin", "clusterrolebinding", "rolebinding")),
    ("privileged_pod", ("privileged", "pod", "container", "host network", "hostpid", "escalation")),
    ("public_rds", ("public rds", "publicly accessible rds", "public database", "rds public", "publicly_accessible")),
    ("unencrypted_rds", ("unencrypted rds", "rds encrypt", "encrypted rds", "database encrypt", "rds storage", "unencrypted database")),
    ("public_s3", ("s3", "bucket")),
    ("open_security_group", ("security group", "0.0.0.0", "ssh", "rdp", "ingress", "open port", "firewall")),
    ("imdsv1", ("imds", "metadata", "imdsv2", "imdsv1")),
    ("no_mfa", ("mfa", "multi-factor", "2fa", "multifactor")),
]


def policy_templates() -> dict[str, str]:
    root = resources.files("nimbus").joinpath("policies")
    return {p.name[:-5]: p.read_text(encoding="utf-8") for p in root.iterdir() if p.name.endswith(".rego")}


def match_policy_template(requirement: str) -> Optional[str]:
    q = requirement.lower()
    best, best_score = None, 0
    for name, words in POLICY_RULES:
        sc = sum(len(w) for w in words if w in q)
        if sc > best_score:
            best, best_score = name, sc
    return best


def generate_policy(requirement: str, use_llm: Optional[bool] = None) -> dict[str, Any]:
    use_llm = llm_available() if use_llm is None else use_llm
    if use_llm:
        text = complete("You write Open Policy Agent policies in Rego v1 (`import rego.v1`, `deny contains msg if { ... }`). "
                        "Target Terraform plan JSON for cloud resources and Kubernetes objects / AdmissionReview for k8s. "
                        "Return one ```rego block, then one line describing the expected input.",
                        f"Requirement: {requirement}", max_tokens=4000, effort="medium")
        if text:
            code = extract_code(text)
            if re.search(r"^\s*package\s+\S+", code, re.M):
                return {"requirement": requirement, "policy": code, "template": None, "mode": "llm",
                        "notes": text.split("```")[-1].strip()}
    tpl = match_policy_template(requirement)
    if tpl is None:
        return {"requirement": requirement, "policy": "", "template": None, "mode": "offline",
                "notes": "No offline template matches. Available: " + ", ".join(sorted(policy_templates())) +
                         ". Set ANTHROPIC_API_KEY to generate arbitrary policies."}
    return {"requirement": requirement, "policy": policy_templates()[tpl], "template": tpl, "mode": "offline",
            "notes": f"Offline template '{tpl}'. Evaluate with: opa eval -d {tpl}.rego -i input.json 'data'"}
