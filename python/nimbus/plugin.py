"""Plugin SDK: write checks in Python, emit native cloud-posture findings.

Example::

    import nimbus

    @nimbus.plugin.check("acme_bucket_tagged", "Buckets carry an owner tag", "LOW", "aws",
                         weaknesses=[], compliance={"soc2": ["CC6.1"]}, resource_type="aws_s3_bucket")
    def bucket_tagged(client=None):
        yield {"resource_id": "arn:aws:s3:::b1", "status": "FAIL", "account": "123", "message": "no owner tag"}

Run it::

    python -m nimbus.plugin path/to/plugin.py --jsonl > out.jsonl
    cloud-posture ingest --source native out.jsonl

A check function may ``return`` or ``yield`` results; each result is a ``Finding`` or a dict with
any Finding field plus the shorthands ``resource_id``, ``resource_name``, ``resource_type``,
``resource_attributes``, ``message`` (-> description) and ``passed`` (bool -> status). Keyword
arguments the function declares are filled from ``run(..., **context)``.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import inspect
import json
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Optional

from .models import Finding, Resource, parse_severity


@dataclass
class CheckSpec:
    id: str
    title: str
    severity: str
    provider: str
    func: Callable[..., Any]
    weaknesses: list[str] = field(default_factory=list)
    compliance: dict[str, list[str]] = field(default_factory=dict)
    resource_type: str = ""
    canonical_id: str = ""
    source: str = "plugin"
    description: str = ""
    remediation: str = ""
    module: str = ""


REGISTRY: dict[str, CheckSpec] = {}


class SkipCheck(Exception):
    """Raise from a check to skip it (e.g. missing credentials) without emitting an ERROR finding."""


def check(id: str, title: str, severity: str = "MEDIUM", provider: str = "unknown", weaknesses: Optional[list[str]] = None,
          compliance: Optional[dict[str, list[str]]] = None, resource_type: str = "", canonical_id: str = "",
          source: str = "plugin", description: str = "", remediation: str = "") -> Callable:
    """Register a check function."""

    def deco(fn: Callable) -> Callable:
        spec = CheckSpec(id=id, title=title, severity=parse_severity(severity).value, provider=provider, func=fn,
                         weaknesses=list(weaknesses or []), compliance={k: list(v) for k, v in (compliance or {}).items()},
                         resource_type=resource_type, canonical_id=canonical_id, source=source,
                         description=description or (inspect.getdoc(fn) or ""), remediation=remediation,
                         module=getattr(fn, "__module__", ""))
        REGISTRY[id] = spec
        fn.__nimbus_check__ = spec  # type: ignore[attr-defined]
        return fn

    return deco


def _to_finding(spec: CheckSpec, item: Any) -> Finding:
    if isinstance(item, Finding):
        f = item.model_copy(deep=True)
    else:
        d = dict(item or {})
        res = d.pop("resource", None)
        if isinstance(res, str):
            res = {"id": res}
        res = dict(res or {})
        if "resource_id" in d:
            res.setdefault("id", d.pop("resource_id"))
        if "resource_name" in d:
            res.setdefault("name", d.pop("resource_name"))
        if "resource_type" in d:
            res.setdefault("type", d.pop("resource_type"))
        if "resource_attributes" in d:
            res.setdefault("attributes", d.pop("resource_attributes"))
        if "message" in d:
            d.setdefault("description", d.pop("message"))
        if "passed" in d:
            d["status"] = "PASS" if d.pop("passed") else "FAIL"
        d["resource"] = Resource.model_validate(res)
        f = Finding.model_validate(d)
    f.source = f.source or spec.source
    f.check_id = f.check_id or spec.id
    f.canonical_id = f.canonical_id or spec.canonical_id
    f.title = f.title or spec.title
    if not isinstance(item, Finding) and "severity" not in (item or {}):
        f.severity = parse_severity(spec.severity)
    f.provider = f.provider or spec.provider
    f.resource.type = f.resource.type or spec.resource_type
    f.weaknesses = f.weaknesses or list(spec.weaknesses)
    if not f.compliance:
        f.compliance = {k: list(v) for k, v in spec.compliance.items()}
    f.description = f.description or spec.description
    f.remediation = f.remediation or spec.remediation
    return f.finalize()


def _error_finding(spec: CheckSpec, exc: BaseException) -> Finding:
    f = Finding(source=spec.source, check_id=spec.id, canonical_id=spec.canonical_id, title=spec.title,
                severity=spec.severity, status="ERROR", provider=spec.provider,
                description=f"check raised {type(exc).__name__}: {exc}",
                resource=Resource(id=f"{spec.provider}:{spec.id}", type=spec.resource_type),
                raw={"traceback": traceback.format_exc()[-2000:]})
    return f.finalize()


def load(path_or_module: str | Path | ModuleType) -> ModuleType:
    if isinstance(path_or_module, ModuleType):
        return path_or_module
    p = Path(str(path_or_module))
    if p.suffix == ".py" or p.exists():
        name = "nimbus_plugin_" + p.stem
        spec = importlib.util.spec_from_file_location(name, p)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load plugin {p}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    return importlib.import_module(str(path_or_module))


def checks_in(module: ModuleType) -> list[CheckSpec]:
    out = []
    for _, obj in inspect.getmembers(module):
        spec = getattr(obj, "__nimbus_check__", None)
        if isinstance(spec, CheckSpec):
            out.append(spec)
    return sorted(out, key=lambda s: s.id)


def run(path_or_module: str | Path | ModuleType, only: Optional[Iterable[str]] = None, **context: Any) -> list[Finding]:
    """Import a plugin file/module and run its checks. Context kwargs are passed to checks that declare them."""
    mod = load(path_or_module)
    wanted = set(only or [])
    findings: list[Finding] = []
    for spec in checks_in(mod):
        if wanted and spec.id not in wanted:
            continue
        sig = inspect.signature(spec.func)
        accepts_any = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        kwargs = {k: v for k, v in context.items() if accepts_any or k in sig.parameters}
        try:
            res = spec.func(**kwargs)
            items = [] if res is None else ([res] if isinstance(res, (dict, Finding)) else list(res))
            findings.extend(_to_finding(spec, it) for it in items)
        except SkipCheck as exc:
            print(f"nimbus.plugin: skipped {spec.id}: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - surface as an ERROR finding
            findings.append(_error_finding(spec, exc))
    return findings


def dumps(findings: list[Finding], jsonl: bool = False) -> str:
    if jsonl:
        return "".join(f.to_json() + "\n" for f in findings)
    return json.dumps([f.to_doc() for f in findings], indent=2, default=str) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m nimbus.plugin", description="Run a nimbus plugin and emit native findings")
    ap.add_argument("path", help="plugin .py file or importable module")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true", help="JSON array (default)")
    g.add_argument("--jsonl", action="store_true", help="JSON lines")
    ap.add_argument("--check", action="append", help="only run these check ids")
    ap.add_argument("--out", help="write to file instead of stdout")
    args = ap.parse_args(argv)
    out = dumps(run(args.path, only=args.check), jsonl=args.jsonl)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    # Delegate to the canonical module object so the registry plugins import is the one we read.
    from nimbus import plugin as _canonical

    sys.exit(_canonical.main())
