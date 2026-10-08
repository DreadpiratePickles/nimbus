"""Discover checks by walking the package tree (``<provider>/<service>/<check_id>/<check_id>.py``)."""

from __future__ import annotations

import importlib
import inspect
import threading
from pathlib import Path
from typing import Iterable

from .base import Check

_PKG_ROOT = Path(__file__).resolve().parent
_PKG_NAME = __name__.rsplit(".", 1)[0]
_lock = threading.Lock()
_loaded: list[type[Check]] | None = None


def _check_modules(provider: str | None = None) -> list[str]:
    mods = []
    roots = [_PKG_ROOT / provider] if provider else [p for p in _PKG_ROOT.iterdir() if p.is_dir() and not p.name.startswith("_")]
    for root in roots:
        if not root.is_dir():
            continue
        for py in sorted(root.rglob("*.py")):
            if py.stem.startswith("_") or py.parent.name != py.stem:
                continue
            if not py.with_name(py.stem + ".metadata.json").exists():
                continue
            rel = py.relative_to(_PKG_ROOT).with_suffix("")
            mods.append(_PKG_NAME + "." + ".".join(rel.parts))
    return mods


def _load() -> list[type[Check]]:
    global _loaded
    with _lock:
        if _loaded is None:
            classes: list[type[Check]] = []
            for modname in _check_modules():
                mod = importlib.import_module(modname)
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(obj, Check) and obj is not Check and obj.__module__ == modname:
                        classes.append(obj)
            classes.sort(key=lambda c: c.load_metadata()["CheckID"])
            _loaded = classes
    return list(_loaded)


def all_checks() -> list[Check]:
    """Instantiate every discovered check."""
    return [cls() for cls in _load()]


def get_check(check_id: str) -> Check:
    for c in all_checks():
        if c.check_id == check_id:
            return c
    raise KeyError(check_id)


def _split(values: Iterable[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    out: list[str] = []
    for v in values:
        out.extend(x.strip() for x in str(v).split(",") if x.strip())
    return out


def _matches_compliance(check: Check, spec: str) -> bool:
    framework, _, control = spec.partition(":")
    controls = check.compliance.get(framework.strip().lower())
    if not controls:
        return False
    if not control:
        return True
    control = control.strip()
    # "1" matches 1.x, "2.1" matches 2.1.x, exact otherwise
    return any(c == control or c.startswith(control + ".") for c in controls)


def filter_checks(
    checks: list[Check] | None = None,
    ids: Iterable[str] | str | None = None,
    services: Iterable[str] | str | None = None,
    severities: Iterable[str] | str | None = None,
    compliance: Iterable[str] | str | None = None,
    provider: str | None = None,
) -> list[Check]:
    """Filter checks; every non-empty filter must match (compliance specs are OR'ed)."""
    result = list(checks if checks is not None else all_checks())
    ids_l = set(_split(ids))
    svc_l = {s.lower() for s in _split(services)}
    sev_l = {s.lower() for s in _split(severities)}
    comp_l = _split(compliance)
    if provider:
        result = [c for c in result if c.provider == provider.lower()]
    if ids_l:
        result = [c for c in result if c.check_id in ids_l]
    if svc_l:
        result = [c for c in result if c.service.lower() in svc_l or c.check_id.split("_", 1)[0] in svc_l]
    if sev_l:
        result = [c for c in result if c.severity in sev_l]
    if comp_l:
        result = [c for c in result if any(_matches_compliance(c, s) for s in comp_l)]
    return result
