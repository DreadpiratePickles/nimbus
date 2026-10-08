"""Context-aware risk scoring and prioritisation.

Features are derived from the finding, the security graph (graph_nodes / graph_edges) and the
attack paths; they are combined with documented weights (``risk_weights.json``) through a
logistic function into a 0-100 score. A linear model exported as JSON may override the weights.

CLI (called by the Go binary)::

    python -m nimbus.risk --db PATH --top 50 [--json]

prints a JSON array of ``{finding_id, risk_score, severity, canonical_id, resource, reasons, ...}``.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Iterable, Optional

from .models import AttackPath, Finding, parse_time

FEATURES = ["severity", "exposure", "identity_risk", "data_sensitivity", "criticality", "vulnerability_count",
            "compliance_weight", "recent_change", "ownership", "attack_path"]

SEVERITY_BASE = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.0}
CRITICALITY = {"production": 1.0, "prod": 1.0, "staging": 0.6, "stage": 0.6, "stg": 0.6, "dev": 0.3,
               "development": 0.3, "test": 0.3, "sandbox": 0.3, "unknown": 0.5, "": 0.5}
EXPOSURE_WEAK = {"PUBLIC_NETWORK_EXPOSURE", "PUBLIC_DATA_STORE"}
IDENTITY_WEAK = {"OVERPRIVILEGED_IDENTITY", "NO_MFA", "CROSS_ACCOUNT_TRUST"}
SENSITIVE_HINTS = ("pii", "customer", "payment", "card", "billing", "secret", "prod", "patient", "hr", "finance", "backup", "users")
INTERNET_EDGES = {"exposes", "allows_traffic_to"}
# Mirror of risk_weights.json (documented there), used only if the JSON file is not packaged.
_BUILTIN_WEIGHTS = {"bias": -4.2, "weights": {"severity": 3.0, "exposure": 1.8, "identity_risk": 1.2, "data_sensitivity": 1.4,
                                              "criticality": 0.9, "vulnerability_count": 0.8, "compliance_weight": 0.6,
                                              "recent_change": 0.5, "ownership": 0.4, "attack_path": 2.2}}


def compliance_weight_for(framework: str) -> float:
    fw = framework.lower()
    if fw in ("pci_dss", "hipaa"):
        return 1.0
    if fw in ("soc2", "gdpr"):
        return 0.8
    if fw.startswith("cis") or fw.startswith("nist") or fw.startswith("iso"):
        return 0.6
    return 0.3


@dataclass
class Weights:
    bias: float
    weights: dict[str, float]

    @classmethod
    def default(cls) -> "Weights":
        try:
            raw = json.loads(resources.files("nimbus").joinpath("risk_weights.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError):  # non-editable wheels may not ship the JSON
            raw = _BUILTIN_WEIGHTS
        return cls(bias=float(raw["bias"]), weights={k: float(v) for k, v in raw["weights"].items()})

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Weights":
        """Load weights or a linear model JSON. Supported shapes:
        {"bias": b, "weights": {...}} or {"intercept": b, "coefficients": {...}} (missing features keep defaults)."""
        base = cls.default()
        path = path or os.environ.get("NIMBUS_RISK_MODEL")
        if not path:
            return base
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        bias = raw.get("intercept", raw.get("bias", base.bias))
        coefs = raw.get("coefficients", raw.get("weights", {}))
        if isinstance(coefs, list):  # sklearn-style coef_ list in FEATURES order
            coefs = dict(zip(raw.get("features", FEATURES), coefs))
        w = dict(base.weights)
        for k, v in coefs.items():
            if k in FEATURES:
                w[k] = float(v)
        return cls(bias=float(bias), weights=w)


@dataclass
class RiskResult:
    finding: Finding
    risk_score: float
    features: dict[str, float]
    reasons: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        f = self.finding
        return {
            "finding_id": f.id,
            "risk_score": self.risk_score,
            "severity": f.severity.value,
            "canonical_id": f.canonical_id,
            "resource": f.resource.id or f.resource.name,
            "resource_name": f.resource.name,
            "resource_type": f.resource.type,
            "title": f.title,
            "provider": f.provider,
            "account": f.account,
            "reasons": self.reasons,
            "features": {k: round(v, 3) for k, v in self.features.items()},
            "attack_paths": self.attack_paths,
        }


class Context:
    """Pre-indexed graph + attack-path lookups shared across findings."""

    def __init__(self, graph: Optional[tuple[list[dict], list[dict]]] = None, paths: Optional[Iterable[AttackPath | dict]] = None,
                 now: Optional[datetime] = None):
        nodes, edges = graph or ([], [])
        self.nodes = {n.get("id"): n for n in nodes if n.get("id")}
        self.internet_targets: set[str] = set()
        for e in edges:
            src = e.get("from") or e.get("from_id") or e.get("source")
            dst = e.get("to") or e.get("to_id") or e.get("target")
            if src == "internet" and (e.get("kind") in INTERNET_EDGES or not e.get("kind")):
                self.internet_targets.add(dst)
        self.paths = [p if isinstance(p, AttackPath) else AttackPath.model_validate(p) for p in (paths or [])]
        self.max_path_score = max((p.score for p in self.paths), default=0.0) or 1.0
        self.paths_by_finding: dict[str, list[AttackPath]] = {}
        for p in self.paths:
            for fid in set(p.finding_ids) | {s.finding_id for s in p.steps if s.finding_id}:
                self.paths_by_finding.setdefault(fid, []).append(p)
        self.now = now or datetime.now(timezone.utc)


def features_for(f: Finding, ctx: Context) -> tuple[dict[str, float], list[str], list[AttackPath]]:
    node = ctx.nodes.get(f.resource.id) or {}
    attrs = {**(f.resource.attributes or {}), **(node.get("attributes") or {})}
    weak = set(f.weaknesses) | set(node.get("weaknesses") or [])
    tags = {k.lower(): str(v) for k, v in (f.tags or {}).items()}
    reasons: list[str] = []
    feat: dict[str, float] = {}

    feat["severity"] = SEVERITY_BASE.get(f.severity.value, 0.0)

    exposed_by = None
    if weak & EXPOSURE_WEAK:
        exposed_by = "public exposure weakness " + "/".join(sorted(weak & EXPOSURE_WEAK))
    elif f.resource.id in ctx.internet_targets:
        exposed_by = "graph edge from the internet"
    elif str(attrs.get("internet_exposed", "")).lower() in ("true", "1") or attrs.get("public") is True:
        exposed_by = "resource attributes mark it public"
    feat["exposure"] = 1.0 if exposed_by else 0.0
    if exposed_by:
        reasons.append(f"Internet-exposed ({exposed_by})")

    idw = weak & IDENTITY_WEAK
    feat["identity_risk"] = {0: 0.0, 1: 0.6, 2: 0.85}.get(len(idw), 1.0)
    if idw:
        reasons.append("Identity risk: " + ", ".join(sorted(idw)))

    name_blob = " ".join([f.resource.name, f.resource.id, " ".join(tags.values())]).lower()
    if node.get("sensitive"):
        feat["data_sensitivity"] = 1.0
        reasons.append("Resource is marked sensitive (crown-jewel data)")
    elif "DATABASE" in weak or node.get("class") == "datastore":
        feat["data_sensitivity"] = 0.8
        reasons.append("Data store / database holds data")
    elif any(h in name_blob for h in SENSITIVE_HINTS):
        feat["data_sensitivity"] = 0.6
        reasons.append("Name or tags suggest sensitive data")
    else:
        feat["data_sensitivity"] = 0.0

    env = (node.get("criticality") or tags.get("environment") or tags.get("env") or tags.get("criticality") or "unknown").lower()
    feat["criticality"] = CRITICALITY.get(env, 0.5)
    if feat["criticality"] >= 1.0:
        reasons.append("Production environment")

    cves = int(node.get("cve_count") or attrs.get("cve_count") or 0)
    feat["vulnerability_count"] = min(1.0, math.log1p(cves) / math.log1p(50)) if cves > 0 else 0.0
    if cves:
        reasons.append(f"{cves} known CVE(s) on the resource")

    fws = [fw for fw, ctrls in (f.compliance or {}).items() if ctrls]
    feat["compliance_weight"] = max((compliance_weight_for(fw) for fw in fws), default=0.3)
    if feat["compliance_weight"] >= 1.0:
        reg = sorted(fw for fw in fws if compliance_weight_for(fw) >= 1.0)
        reasons.append("Regulated scope: " + ", ".join(reg))

    mod = parse_time(node.get("modified_at") or attrs.get("modified_at"))
    feat["recent_change"] = 0.0
    if mod:
        age_h = (ctx.now - mod).total_seconds() / 3600
        if 0 <= age_h < 24:
            feat["recent_change"] = 1.0
            reasons.append("Resource changed in the last 24h")
        elif 0 <= age_h < 168:
            feat["recent_change"] = round(1 - (age_h - 24) / 144, 3)

    owner = node.get("owner") or tags.get("owner") or tags.get("team")
    feat["ownership"] = 0.0 if owner else 0.7
    if not owner:
        reasons.append("No owner assigned")

    paths = ctx.paths_by_finding.get(f.id, [])
    if paths:
        best = max(p.score for p in paths)
        feat["attack_path"] = 0.5 * min(1.0, len(paths) / 3) + 0.5 * min(1.0, best / ctx.max_path_score)
        top = max(paths, key=lambda p: p.score)
        reasons.insert(0, f"On {len(paths)} attack path(s), e.g. '{top.name}' (score {top.score:g})")
    else:
        feat["attack_path"] = 0.0
    return feat, reasons, paths


def score(features: dict[str, float], weights: Optional[Weights] = None) -> float:
    w = weights or Weights.default()
    z = w.bias + sum(w.weights.get(k, 0.0) * v for k, v in features.items())
    return round(100.0 / (1.0 + math.exp(-z)), 1)


def score_finding(f: Finding, ctx: Optional[Context] = None, weights: Optional[Weights] = None) -> RiskResult:
    ctx = ctx or Context()
    feats, reasons, paths = features_for(f, ctx)
    sev_reason = f"{f.severity.value} severity ({f.canonical_id})"
    return RiskResult(finding=f, risk_score=score(feats, weights), features=feats, reasons=[sev_reason] + reasons,
                      attack_paths=[p.id for p in paths])


def prioritize(findings: Iterable[Finding | dict], graph: Optional[tuple[list[dict], list[dict]]] = None,
               paths: Optional[Iterable[AttackPath | dict]] = None, top: int = 50, weights: Optional[Weights] = None,
               include_passed: bool = False) -> list[RiskResult]:
    ctx = Context(graph, paths)
    weights = weights or Weights.load()
    out = []
    for f in findings:
        f = f if isinstance(f, Finding) else Finding.model_validate(f)
        if not include_passed and f.status.value != "FAIL":
            continue
        out.append(score_finding(f, ctx, weights))
    out.sort(key=lambda r: (-r.risk_score, -r.finding.severity_rank, r.finding.id))
    return out[:top] if top and top > 0 else out


def prioritize_store(store, top: int = 50, weights: Optional[Weights] = None) -> list[RiskResult]:
    return prioritize(store.findings(status="FAIL"), store.graph(), store.attack_paths(), top=top, weights=weights)


def main(argv: Optional[list[str]] = None) -> int:
    from .store import Store, default_db_path

    ap = argparse.ArgumentParser(prog="python -m nimbus.risk", description="Context-aware risk prioritisation")
    ap.add_argument("--db", default=default_db_path())
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--json", action="store_true", help="JSON output (default; kept for the Go contract)")
    ap.add_argument("--table", action="store_true", help="human-readable table instead of JSON")
    ap.add_argument("--model", help="linear model / weights JSON")
    args = ap.parse_args(argv)
    if not os.path.exists(args.db):
        print("[]")
        return 0
    store = Store(args.db, create=False)
    res = prioritize_store(store, top=args.top, weights=Weights.load(args.model))
    if args.table and not args.json:
        for r in res:
            d = r.to_dict()
            print(f"{d['risk_score']:5.1f}  {d['severity']:<8} {d['canonical_id']:<28} {d['resource']}  - {'; '.join(d['reasons'][:3])}")
    else:
        json.dump([r.to_dict() for r in res], sys.stdout, indent=None)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
