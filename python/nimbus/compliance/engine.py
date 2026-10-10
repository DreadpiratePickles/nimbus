from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml
from pydantic import BaseModel, Field

from ..models import SEVERITY_RANK, AttackPath, Finding, ScanSummary, go_time

RAW_EXCERPT_LEN = 400


class Control(BaseModel):
    id: str
    title: str = ""
    canonical_ids: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    # Canonical finding ids that assess this control (frameworks imported from Prowler). Catalog ids
    # are natively assessable; "PROWLER:<check>" ids only through ingested Prowler output.
    checks: list[str] = Field(default_factory=list)


class Framework(BaseModel):
    key: str
    name: str
    version: str = ""
    controls: dict[str, Control] = Field(default_factory=dict)
    custom: bool = False
    # Honest denominator: {"native": X, "prowler_ingest": Y, "manual": Z}, summing to len(controls).
    coverage: dict[str, int] = Field(default_factory=dict)
    # Imported frameworks: source, upstream_url, license, attribution, text_policy, reference_url...
    provenance: Optional[dict[str, str]] = None


class Evidence(BaseModel):
    finding_id: str
    canonical_id: str
    title: str
    severity: str
    status: str
    source: str
    check_id: str
    provider: str
    account: str
    region: str = ""
    resource_id: str
    resource_name: str
    resource_type: str = ""
    first_seen: str = ""
    last_seen: str = ""
    mapped_by: str = ""  # compliance | weakness:<W> | canonical_id
    raw_excerpt: str = ""


class ControlResult(BaseModel):
    id: str
    title: str = ""
    status: str = "NOT_ASSESSED"  # PASS | FAIL | NOT_ASSESSED
    failed: int = 0
    passed: int = 0
    max_severity: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class RoadmapItem(BaseModel):
    canonical_id: str
    title: str
    severity: str
    count: int
    priority: int
    controls: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    remediation: str = ""
    command: str = ""


class Report(BaseModel):
    framework: Framework
    scope: str = ""
    generated_at: str = ""
    controls: list[ControlResult] = Field(default_factory=list)
    total_controls: int = 0
    passing: int = 0
    failing: int = 0
    not_assessed: int = 0
    score_percent: float = 0.0
    assessed: int = 0  # passing + failing; "assessed of total_controls"
    coverage: dict[str, int] = Field(default_factory=dict)
    findings_evaluated: int = 0
    roadmap: list[RoadmapItem] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    monitoring: dict[str, Any] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)

    def failing_controls(self) -> list[ControlResult]:
        return [c for c in self.controls if c.status == "FAIL"]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ---------------------------------------------------------------- loading

def _coverage(controls: dict[str, Control]) -> dict[str, int]:
    """Coverage classes for frameworks without a declared one (custom frameworks)."""
    cov = {"native": 0, "prowler_ingest": 0, "manual": 0}
    for c in controls.values():
        ids = c.checks + c.canonical_ids
        if c.weaknesses or any(not i.upper().startswith("PROWLER:") for i in ids):
            cov["native"] += 1
        elif ids:
            cov["prowler_ingest"] += 1
        else:
            cov["manual"] += 1
    return cov


def _framework_from_raw(key: str, raw: dict, custom: bool = False) -> Framework:
    controls: dict[str, Control] = {}
    for cid, val in (raw.get("controls") or {}).items():
        cid = str(cid)
        if isinstance(val, dict):
            controls[cid] = Control(
                id=cid, title=str(val.get("title") or ""),
                canonical_ids=[str(x).upper() for x in val.get("canonical_ids") or []],
                weaknesses=[str(x).upper() for x in val.get("weaknesses") or []],
                checks=[str(x) for x in val.get("checks") or []],
            )
        else:
            controls[cid] = Control(id=cid, title=str(val or ""))
    cov = raw.get("coverage")
    cov = {str(k): int(v) for k, v in cov.items()} if isinstance(cov, dict) else _coverage(controls)
    prov = raw.get("provenance")
    return Framework(key=key, name=str(raw.get("name") or key), version=str(raw.get("version") or ""), controls=controls,
                     custom=custom, coverage=cov, provenance={str(k): str(v) for k, v in prov.items()} if isinstance(prov, dict) else None)


@lru_cache(maxsize=1)
def _bundled() -> dict[str, Any]:
    """The bundle generated from the Go loader (internal/compliance/gen). It is JSON (valid YAML)."""
    text = resources.files("nimbus").joinpath("frameworks/frameworks.yaml").read_text(encoding="utf-8")
    if text.lstrip().startswith("{"):
        return json.loads(text)
    return yaml.safe_load(text) or {}


@lru_cache(maxsize=1)
def _bundled_frameworks() -> dict[str, Framework]:
    data = _bundled()
    return {str(k): _framework_from_raw(str(k), v or {}) for k, v in (data.get("frameworks") or {}).items()}


def load_frameworks() -> dict[str, Framework]:
    return {k: fw.model_copy(deep=True) for k, fw in _bundled_frameworks().items()}


def weakness_mappings() -> dict[str, dict[str, list[str]]]:
    raw = _bundled().get("weakness_mappings") or {}
    return {str(w): {str(fw): [str(c) for c in ctrls or []] for fw, ctrls in (m or {}).items()} for w, m in raw.items()}


def frameworks() -> list[dict[str, Any]]:
    """Listing for CLIs/APIs: key, name, version, control count, derived-from-weaknesses flag."""
    derived = {fw for m in weakness_mappings().values() for fw in m}
    return [
        {"key": k, "name": f.name, "version": f.version, "controls": len(f.controls), "weakness_derived": k in derived,
         "coverage": dict(f.coverage), "imported": f.provenance is not None}
        for k, f in sorted(_bundled_frameworks().items())
    ]


def load_custom_framework(path: str | Path) -> Framework:
    """Custom framework YAML::

        name: Acme Cloud Baseline
        version: "1.0"
        key: acme            # optional, defaults to the slugified name
        controls:
          ACME-1:
            title: No public data stores
            canonical_ids: [S3_PUBLIC_BUCKET, GCP_BUCKET_PUBLIC]
            weaknesses: [PUBLIC_DATA_STORE]
    """
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if "frameworks" in raw and isinstance(raw["frameworks"], dict) and len(raw["frameworks"]) == 1:
        key, raw = next(iter(raw["frameworks"].items()))
    else:
        key = raw.get("key") or re.sub(r"[^a-z0-9]+", "_", str(raw.get("name", "custom")).lower()).strip("_") or "custom"
    return _framework_from_raw(str(key), raw, custom=True)


_ALIASES = {
    "cis": "cis_aws", "cis-aws": "cis_aws", "cis_aws_benchmark": "cis_aws", "cis-azure": "cis_azure",
    "cis_azure_benchmark": "cis_azure", "cis-gcp": "cis_gcp", "cis_gcp_benchmark": "cis_gcp",
    "cis-k8s": "cis_k8s", "cis_kubernetes": "cis_k8s", "cis_k8s_benchmark": "cis_k8s", "cis_github_benchmark": "cis_github",
    "nist": "nist_800_53", "nist-800-53": "nist_800_53", "nist800-53": "nist_800_53", "nist80053": "nist_800_53",
    "pci": "pci_dss", "pci-dss": "pci_dss", "pcidss": "pci_dss",
    "iso": "iso_27001", "iso27001": "iso_27001", "iso-27001": "iso_27001",
    "soc-2": "soc2", "soc_2": "soc2", "soc": "soc2",
}


def resolve_key(name: str) -> str:
    n = (name or "").strip().lower()
    return _ALIASES.get(n, n.replace("-", "_"))


# Curated headline set `report --framework all` walks unless --framework-set says otherwise; the
# CIS benchmark of each provider in scope goes in front. Must equal Go's defaultFrameworkSet
# (internal/cli/report.go; tests/test_framework_set.py checks parity).
DEFAULT_FRAMEWORK_SET = ("nist_800_53", "pci_dss", "soc2", "hipaa", "iso_27001", "gdpr")


def _cis_key(provider: str) -> str:
    """Go's ResolveKey("cis", provider)."""
    if provider in ("", "aws"):
        return "cis_aws"
    if provider == "kubernetes":
        return "cis_k8s"
    return "cis_" + provider


def framework_set(spec: Optional[str], providers: Iterable[str] = ()) -> list[str]:
    """Resolve ``--framework-set`` (default | all | comma list of keys/aliases) to framework keys.

    ``providers`` are the providers in scope (CIS benchmark selection). Unknown names raise ValueError.
    """
    all_ = _bundled_frameworks()
    provs = sorted({p for p in providers if p})
    keys: list[str] = []

    def add(k: str) -> None:
        if k not in keys:
            keys.append(k)

    s = (spec or "").strip().lower()
    if s in ("", "default"):
        for p in provs:
            if _cis_key(p) in all_:
                add(_cis_key(p))
        for k in DEFAULT_FRAMEWORK_SET:
            if k in all_:
                add(k)
        return keys
    if s == "all":
        return sorted(all_)
    unknown: list[str] = []
    for name in (n.strip() for n in s.split(",")):
        if not name:
            continue
        if name == "cis" and provs:
            found = [_cis_key(p) for p in provs if _cis_key(p) in all_]
            for k in found:
                add(k)
            if not found:
                unknown.append(name)
            continue
        k = resolve_key(name)
        if k in all_:
            add(k)
        else:
            unknown.append(name)
    if unknown:
        raise ValueError(f"--framework-set: unknown framework(s) {', '.join(unknown)} (use --framework-set all for every key)")
    if not keys:
        raise ValueError("--framework-set: no frameworks named")
    return keys


# ---------------------------------------------------------------- evaluation

def _control_sort_key(cid: str) -> list:
    parts = re.split(r"[.\-()]", cid)
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts if p != ""]


def _excerpt(raw: Any) -> str:
    if raw in (None, "", {}, []):
        return ""
    s = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True, default=str)
    return s if len(s) <= RAW_EXCERPT_LEN else s[: RAW_EXCERPT_LEN - 3] + "..."


def _check_index(fw: Framework) -> dict[str, list[str]]:
    """upper(canonical id) -> control ids whose ``checks`` list it."""
    idx: dict[str, list[str]] = defaultdict(list)
    for cid, ctl in fw.controls.items():
        for chk in ctl.checks:
            idx[chk.upper()].append(cid)
    return dict(idx)


def _mappings_for(fw: Framework, f: Finding, wmap: dict[str, dict[str, list[str]]],
                  check_index: Optional[dict[str, list[str]]] = None) -> list[tuple[str, str]]:
    """(control_id, mapped_by) pairs for a finding."""
    out: list[tuple[str, str]] = []
    if check_index is None:
        check_index = _check_index(fw)
    if fw.custom:
        for cid, ctl in fw.controls.items():
            if f.canonical_id.upper() in ctl.canonical_ids:
                out.append((cid, "canonical_id"))
            else:
                hit = next((w for w in f.weaknesses if w.upper() in ctl.weaknesses), None)
                if hit:
                    out.append((cid, f"weakness:{hit}"))
        for cid in f.compliance.get(fw.key, []):
            out.append((cid, "compliance"))
    else:
        for cid in f.compliance.get(fw.key, []):
            out.append((str(cid), "compliance"))
        for w in f.weaknesses:
            for cid in wmap.get(w, {}).get(fw.key, []):
                out.append((cid, f"weakness:{w}"))
    if f.canonical_id:
        for cid in check_index.get(f.canonical_id.upper(), []):
            out.append((cid, "canonical_id"))
    seen, uniq = set(), []
    for cid, by in out:
        if cid not in seen:
            seen.add(cid)
            uniq.append((cid, by))
    return uniq


def build_report(framework: str, findings: Iterable[Finding | dict], custom_path: Optional[str | Path] = None,
                 attack_paths: Optional[Iterable[AttackPath | dict]] = None, scan: Optional[ScanSummary | dict] = None,
                 scope: str = "", max_evidence: int = 25) -> Report:
    """Evaluate findings against a framework (built-in key/alias, or the custom YAML file)."""
    if custom_path:
        fw = load_custom_framework(custom_path)
    else:
        key = resolve_key(framework)
        fws = _bundled_frameworks()
        fw = fws[key].model_copy(deep=True) if key in fws else Framework(key=key, name=key, controls={})
    wmap = weakness_mappings()
    items = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in findings]
    cindex = _check_index(fw)

    results: dict[str, ControlResult] = {cid: ControlResult(id=cid, title=c.title) for cid, c in fw.controls.items()}
    in_scope: list[tuple[Finding, list[str]]] = []
    for f in items:
        maps = _mappings_for(fw, f, wmap, cindex)
        if not maps:
            continue
        in_scope.append((f, [c for c, _ in maps]))
        for cid, by in maps:
            cr = results.get(cid)
            if cr is None:
                cr = results[cid] = ControlResult(id=cid)
            if f.status.value == "FAIL":
                cr.failed += 1
                cr.status = "FAIL"
                cr.finding_ids.append(f.id)
                rname = f.resource.name or f.resource.id
                if rname and rname not in cr.resources:
                    cr.resources.append(rname)
                if not cr.max_severity or SEVERITY_RANK[f.severity.value] > SEVERITY_RANK.get(cr.max_severity, 0):
                    cr.max_severity = f.severity.value
                if len(cr.evidence) < max_evidence:
                    cr.evidence.append(Evidence(
                        finding_id=f.id, canonical_id=f.canonical_id, title=f.title, severity=f.severity.value,
                        status=f.status.value, source=f.source, check_id=f.check_id, provider=f.provider,
                        account=f.account, region=f.region, resource_id=f.resource.id, resource_name=rname,
                        resource_type=f.resource.type, first_seen=go_time(f.first_seen) if f.first_seen else "",
                        last_seen=go_time(f.last_seen) if f.last_seen else "", mapped_by=by, raw_excerpt=_excerpt(f.raw),
                    ))
            elif f.status.value == "PASS":
                cr.passed += 1
                if cr.status == "NOT_ASSESSED":
                    cr.status = "PASS"

    rep = Report(framework=fw, scope=scope, generated_at=go_time(datetime.now(timezone.utc).replace(microsecond=0)))
    rep.controls = sorted(results.values(), key=lambda c: _control_sort_key(c.id))
    for c in rep.controls:
        if c.status == "PASS":
            rep.passing += 1
        elif c.status == "FAIL":
            rep.failing += 1
        else:
            rep.not_assessed += 1
    rep.total_controls = len(rep.controls)
    assessed = rep.assessed = rep.passing + rep.failing
    rep.coverage = dict(fw.coverage)
    rep.score_percent = round(int(rep.passing / assessed * 1000) / 10, 1) if assessed else 0.0
    rep.findings_evaluated = len(in_scope)
    sev_counts: dict[str, int] = defaultdict(int)
    for f, _ in in_scope:
        if f.status.value == "FAIL":
            sev_counts[f.severity.value] += 1
    rep.severity_counts = dict(sev_counts)
    rep.roadmap = _roadmap(in_scope)

    paths = [p if isinstance(p, AttackPath) else AttackPath.model_validate(p) for p in (attack_paths or [])]
    scoped_ids = {f.id for f, _ in in_scope if f.status.value == "FAIL"}
    rep.attack_paths = [
        {"id": p.id, "name": p.name, "impact": p.impact, "score": p.score, "severity": p.severity.value,
         "provider": p.provider, "account": p.account, "mitre": p.mitre, "steps": len(p.steps),
         "narrative": p.narrative, "in_scope_findings": sorted(set(p.finding_ids) & scoped_ids)}
        for p in paths
    ]
    rep.monitoring = _monitoring(items, scan)
    if not rep.scope:
        accounts = sorted({f"{f.provider}:{f.account}" for f, _ in in_scope if f.account})
        rep.scope = ", ".join(accounts) if accounts else "all ingested findings"
    return rep


def _roadmap(in_scope: list[tuple[Finding, list[str]]]) -> list[RoadmapItem]:
    groups: dict[str, dict[str, Any]] = {}
    for f, ctrls in in_scope:
        if f.status.value != "FAIL":
            continue
        g = groups.setdefault(f.canonical_id, {"title": f.title, "sev": f.severity.value, "count": 0, "controls": [],
                                               "resources": [], "remediation": f.remediation})
        g["count"] += 1
        if SEVERITY_RANK[f.severity.value] > SEVERITY_RANK[g["sev"]]:
            g["sev"] = f.severity.value
        for c in ctrls:
            if c not in g["controls"]:
                g["controls"].append(c)
        r = f.resource.name or f.resource.id
        if r and r not in g["resources"]:
            g["resources"].append(r)
        if not g["remediation"] and f.remediation:
            g["remediation"] = f.remediation
    items = [
        RoadmapItem(canonical_id=cid, title=g["title"], severity=g["sev"], count=g["count"],
                    priority=SEVERITY_RANK[g["sev"]] * g["count"], controls=sorted(g["controls"], key=_control_sort_key),
                    resources=g["resources"][:10], remediation=g["remediation"],
                    command=f"cloud-posture fix --finding {cid} --generate-terraform")
        for cid, g in groups.items()
    ]
    items.sort(key=lambda i: (-i.priority, -SEVERITY_RANK[i.severity], i.canonical_id))
    return items


def _monitoring(items: list[Finding], scan: Optional[ScanSummary | dict]) -> dict[str, Any]:
    s = scan if (scan is None or isinstance(scan, ScanSummary)) else ScanSummary.model_validate(scan)
    last_seen = max((f.last_seen for f in items if f.last_seen), default=None)
    scan_ids = sorted({f.scan_id for f in items if f.scan_id})
    return {
        "scan_id": (s.scan_id if s else "") or (scan_ids[-1] if scan_ids else ""),
        "scan_started_at": go_time(s.started_at) if s and s.started_at else "",
        "scan_finished_at": go_time(s.finished_at) if s and s.finished_at else "",
        "latest_evidence_at": go_time(last_seen) if last_seen else "",
        "findings_total": len(items),
        "continuous": True,
        "note": "Evidence is refreshed on every `cloud-posture scan`; the dashboard pushes findings_updated events when the database changes.",
    }
