"""Access to the bundled canonical check catalog (copy of internal/catalog/catalog.yaml)."""
from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any, Optional

import yaml


@lru_cache(maxsize=1)
def catalog() -> dict[str, dict[str, Any]]:
    text = resources.files("nimbus").joinpath("frameworks/catalog.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def entry(canonical_id: str) -> Optional[dict[str, Any]]:
    return catalog().get((canonical_id or "").upper())


def lookup_alias(source: str, check_id: str) -> Optional[str]:
    """Map a tool-native check id to its canonical id (None when unknown)."""
    src = (source or "").lower()
    for cid, e in catalog().items():
        for tool, ids in (e.get("aliases") or {}).items():
            if (not src or tool in src) and check_id in (ids or []):
                return cid
    return None


def weaknesses_for(canonical_id: str) -> list[str]:
    e = entry(canonical_id) or {}
    return list(e.get("weaknesses") or [])
