"""Risk prioritisation — a reader of Go's score, never a second formula.

The only risk formula is Go's ``internal/risk`` (published in ``docs/scoring.md``). Since score_version
2.0.0, Python does not compute a score. It loads Go's ranked output — ``risk_score``, ``band``,
``reasons``, ``score_version`` and ``explanation`` per finding — and joins it to findings, the graph and
the attack paths for display.

Where Go's output comes from, first match wins:

1. the ``risk=`` argument (a path, a parsed list, or ``{finding_id: record}``);
2. ``$NIMBUS_RISK_JSON``;
3. ``<db>.risk.json`` beside the store's database (Go's ``ingest`` / ``scan`` / ``prioritize`` write it; for
   example ``.cloud-posture/posture.db.risk.json``). It is per database: a shared ``risk.json`` in the
   directory is ignored because it may belong to another database.

A finding Go has not scored is reported with ``risk_score=None`` and ``band="not scored"``. It never
gets a Python-made number.

CLI (called by the Go binary)::

    python -m nimbus.risk --db PATH --top 50 [--json] [--risk-json FILE]

``--json`` prints only findings that carry a Go score, and in that mode only explicit Go output
(``--risk-json`` / ``$NIMBUS_RISK_JSON``) is read, so the legacy Go caller (``internal/cli``
``prioritizeBest``) receives ``[]`` and keeps its own ranking.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from .models import AttackPath, Finding

#: Go's factor names, in explanation order (docs/scoring.md).
FEATURES = ["exposure", "identity", "data_sensitivity", "criticality", "exploitability", "compliance_scope",
            "recent_change", "ownership", "attack_path", "compensating_controls"]
NOT_SCORED = "not scored"
# Mirror of risk_weights.json, used only if the JSON file is not packaged. Go's TestPythonScoreVersionMirror
# keeps the JSON equal to risk.ScoreVersion.
_BUILTIN_WEIGHTS = {"score_version": "2.4.0"}

RiskSource = Union[str, os.PathLike, list, dict, None]


def compliance_weight_for(framework: str) -> float:
    """Go's published compliance_scope multiplier for one framework (docs/scoring.md, weights table).

    Since score_version 2.1.0 every framework is x1.0: compliance scope is reported in the
    explanation, not weighted (docs/scoring.md changelog)."""
    fw = framework.lower()
    if fw in ("pci_dss", "hipaa"):
        return 1.0  # compliance.regulated
    if fw in ("soc2", "gdpr"):
        return 1.0  # compliance.privacy
    return 1.0


@dataclass
class Weights:
    """Compatibility shim. Weights live in Go; this object only carries the score_version Python expects."""
    score_version: str
    bias: float = 0.0
    weights: dict[str, float] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "Weights":
        try:
            raw = json.loads(resources.files("nimbus").joinpath("risk_weights.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError):  # non-editable wheels may not ship the JSON
            raw = _BUILTIN_WEIGHTS
        return cls(score_version=str(raw.get("score_version", _BUILTIN_WEIGHTS["score_version"])))

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Weights":
        """Custom weights / linear models are no longer supported: the score is Go's alone."""
        path = path or os.environ.get("NIMBUS_RISK_MODEL")
        if path:
            warnings.warn(f"risk model {path!r} ignored: nimbus scores are computed by Go internal/risk "
                          "(docs/scoring.md); Python no longer applies weights", stacklevel=2)
        return cls.default()


@dataclass
class RiskResult:
    finding: Finding
    risk_score: Optional[float]
    features: dict[str, float]
    reasons: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    band: str = NOT_SCORED
    score_version: str = ""
    explanation: Optional[dict[str, Any]] = None

    @property
    def scored(self) -> bool:
        return self.risk_score is not None

    def to_dict(self) -> dict[str, Any]:
        f = self.finding
        return {
            "finding_id": f.id,
            "risk_score": self.risk_score,
            "band": self.band,
            "score_version": self.score_version,
            "severity": f.severity.value,
            "canonical_id": f.canonical_id,
            "resource": f.resource.id or f.resource.name,
            "resource_name": f.resource.name,
            "resource_type": f.resource.type,
            "title": f.title,
            "provider": f.provider,
            "account": f.account,
            "reasons": self.reasons,
            "features": {k: round(v, 4) for k, v in self.features.items()},
            "missing": list((self.explanation or {}).get("missing") or []),
            "explanation": self.explanation,
            "attack_paths": self.attack_paths,
        }


def _finding_id(rec: dict) -> Optional[str]:
    if rec.get("finding_id"):
        return rec["finding_id"]
    f = rec.get("finding")
    return f.get("id") if isinstance(f, dict) else None


def load_go_risk(source: RiskSource) -> dict[str, dict]:
    """Index Go ranked output (``risk.Ranked`` JSON) by finding id. Missing or empty source -> {}."""
    if source is None:
        return {}
    if isinstance(source, dict):
        if all(isinstance(v, dict) for v in source.values()) and "risk_score" not in source:
            return dict(source)
        source = [source]
    if isinstance(source, (str, os.PathLike)):
        p = Path(source)
        if not p.is_file():
            return {}
        source = json.loads(p.read_text(encoding="utf-8") or "[]")
        if isinstance(source, dict):  # e.g. {"risk": [...]} from scan/dashboard JSON
            source = source.get("risk") or source.get("Risk") or []
    out: dict[str, dict] = {}
    for rec in source or []:
        if isinstance(rec, dict) and (fid := _finding_id(rec)) and rec.get("risk_score") is not None:
            out[fid] = rec
    return out


def risk_source_for(db_path: Optional[str]) -> Optional[str]:
    """``$NIMBUS_RISK_JSON``, else ``<db>.risk.json`` beside the database (when it exists)."""
    env = os.environ.get("NIMBUS_RISK_JSON")
    if env:
        return env
    if db_path:
        p = Path(db_path).resolve()
        cand = p.with_name(p.name + ".risk.json")
        if cand.is_file():
            return str(cand)
    return None


class Context:
    """Go risk records plus attack-path lookups shared across findings."""

    def __init__(self, graph: Optional[tuple[list[dict], list[dict]]] = None, paths: Optional[Iterable[AttackPath | dict]] = None,
                 now: Optional[datetime] = None, risk: RiskSource = None):
        nodes, _edges = graph or ([], [])
        self.nodes = {n.get("id"): n for n in nodes if n.get("id")}
        self.paths = [p if isinstance(p, AttackPath) else AttackPath.model_validate(p) for p in (paths or [])]
        self.paths_by_finding: dict[str, list[AttackPath]] = {}
        for p in self.paths:
            for fid in set(p.finding_ids) | {s.finding_id for s in p.steps if s.finding_id}:
                self.paths_by_finding.setdefault(fid, []).append(p)
        self.now = now or datetime.now(timezone.utc)
        self.go = load_go_risk(risk)


def features_for(f: Finding, ctx: Context) -> tuple[dict[str, float], list[str], list[AttackPath]]:
    """Go's explanation for ``f`` as ``{"base": b, factor: multiplier, ...}`` plus Go's reasons.

    Empty features (and a single "not scored" reason) when Go has not scored the finding.
    """
    paths = ctx.paths_by_finding.get(f.id, [])
    rec = ctx.go.get(f.id)
    if not rec:
        return {}, [f"{NOT_SCORED}: no Go risk output for this finding (run `cloud-posture prioritize --json`)"], paths
    exp = rec.get("explanation") or {}
    feats: dict[str, float] = {}
    if "base" in exp:
        feats["base"] = float(exp["base"])
        for fac in exp.get("factors") or []:
            name = fac.get("name", "?")
            # cap/rounding are applied once each; keep any duplicate names distinct
            key = name if name not in feats else f"{name}#{len(feats)}"
            feats[key] = float(fac.get("multiplier", 1.0))
    return feats, list(rec.get("reasons") or []), paths


def score(features: dict[str, float], weights: Optional[Weights] = None) -> Optional[float]:
    """Reproduce Go's score from its explanation: base × Π multipliers (docs/scoring.md "by hand").

    Returns None for unscored findings. This is arithmetic over Go's factors, not a second formula.
    """
    if not features or "base" not in features:
        return None
    prod = features["base"]
    for k, v in features.items():
        if k != "base":
            prod *= v
    return round(max(0.0, min(10.0, prod)), 1)


def score_finding(f: Finding, ctx: Optional[Context] = None, weights: Optional[Weights] = None) -> RiskResult:
    ctx = ctx or Context()
    feats, reasons, paths = features_for(f, ctx)
    rec = ctx.go.get(f.id)
    if not rec:
        return RiskResult(finding=f, risk_score=None, features=feats, reasons=reasons, attack_paths=[p.id for p in paths])
    return RiskResult(finding=f, risk_score=float(rec["risk_score"]), features=feats, reasons=reasons,
                      attack_paths=[p.id for p in paths], band=str(rec.get("band") or NOT_SCORED),
                      score_version=str(rec.get("score_version") or ""), explanation=rec.get("explanation"))


def _sort_key(r: RiskResult) -> tuple:
    if r.scored:
        raw = float((r.explanation or {}).get("raw") or r.risk_score or 0.0)
        return (0, -float(r.risk_score), -raw, r.finding.id)
    return (1, -r.finding.severity_rank, 0.0, r.finding.id)


def prioritize(findings: Iterable[Finding | dict], graph: Optional[tuple[list[dict], list[dict]]] = None,
               paths: Optional[Iterable[AttackPath | dict]] = None, top: int = 50, weights: Optional[Weights] = None,
               include_passed: bool = False, risk: RiskSource = None) -> list[RiskResult]:
    """Join findings to Go's scores. Scored findings first in Go's order, then unscored by severity."""
    ctx = Context(graph, paths, risk=risk)
    if weights is None:
        Weights.load()  # surfaces the NIMBUS_RISK_MODEL warning
    out = []
    for f in findings:
        f = f if isinstance(f, Finding) else Finding.model_validate(f)
        if not include_passed and f.status.value != "FAIL":
            continue
        out.append(score_finding(f, ctx))
    out.sort(key=_sort_key)
    return out[:top] if top and top > 0 else out


def prioritize_store(store, top: int = 50, weights: Optional[Weights] = None, risk: RiskSource = None) -> list[RiskResult]:
    if risk is None:
        risk = risk_source_for(getattr(store, "path", None))
    return prioritize(store.findings(status="FAIL"), store.graph(), store.attack_paths(), top=top, weights=weights, risk=risk)


def main(argv: Optional[list[str]] = None) -> int:
    from .store import Store, default_db_path

    ap = argparse.ArgumentParser(prog="python -m nimbus.risk", description="Show Go's risk ranking (docs/scoring.md)")
    ap.add_argument("--db", default=default_db_path())
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--json", action="store_true", help="JSON of Go-scored findings only (the Go caller contract)")
    ap.add_argument("--table", action="store_true", help="human-readable table instead of JSON")
    ap.add_argument("--risk-json", help="Go ranked output (cloud-posture prioritize --json); default $NIMBUS_RISK_JSON or <db>.risk.json beside --db")
    ap.add_argument("--model", help="ignored since score_version 2.0.0 (warns)")
    args = ap.parse_args(argv)
    if args.model:
        Weights.load(args.model)
    if not os.path.exists(args.db):
        print("[]")
        return 0
    store = Store(args.db, create=False)
    src: RiskSource = args.risk_json
    if src is None and not args.table:
        # Go's legacy caller (internal/cli prioritizeBest) rescales whatever we print; only explicit
        # Go output is echoed in --json mode, never an implicitly discovered risk.json.
        src = os.environ.get("NIMBUS_RISK_JSON") or []
    res = prioritize_store(store, top=0, risk=src)
    if args.table and not args.json:
        for r in res[: args.top if args.top > 0 else None]:
            d = r.to_dict()
            sc = f"{d['risk_score']:5.1f}" if d["risk_score"] is not None else "  n/s"
            print(f"{sc}  {d['band']:<10} {d['severity']:<8} {d['canonical_id']:<28} {d['resource']}  - {'; '.join(d['reasons'][:3])}")
    else:
        scored = [r.to_dict() for r in res if r.scored]
        if args.top > 0:
            scored = scored[: args.top]
        if not scored:
            print("nimbus.risk: no Go risk output found; nothing to report (Go keeps its own ranking)", file=sys.stderr)
        json.dump(scored, sys.stdout, indent=None)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
