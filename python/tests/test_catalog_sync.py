"""Integration pass 2 item 7: the bundled Python catalog must not drift from the Go catalog.

python/nimbus/frameworks/catalog.yaml is a copy of internal/catalog/catalog.yaml (the Go
binary embeds the latter). Aliases are what map a scanner's native check id to a canonical
id, so the alias sets are compared per canonical id (and the canonical ids themselves).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
GO_CATALOG = REPO / "internal" / "catalog" / "catalog.yaml"
PY_CATALOG = REPO / "python" / "nimbus" / "frameworks" / "catalog.yaml"


def _aliases(path: Path) -> dict[str, dict[str, set[str]]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, dict[str, set[str]]] = {}
    for cid, entry in doc.items():
        tools = (entry or {}).get("aliases") or {}
        out[cid] = {tool: set(ids or []) for tool, ids in tools.items() if ids}
    return out


@pytest.mark.skipif(not GO_CATALOG.exists(), reason="Go catalog not in this checkout (installed package)")
def test_python_catalog_aliases_match_go():
    go, py = _aliases(GO_CATALOG), _aliases(PY_CATALOG)
    assert sorted(set(go) - set(py)) == [], "canonical ids missing from the Python catalog"
    assert sorted(set(py) - set(go)) == [], "canonical ids only in the Python catalog"
    drift = {cid: {"go": go[cid], "python": py[cid]} for cid in go if go[cid] != py[cid]}
    assert drift == {}, f"alias drift per canonical id: {drift}"


def test_bundled_catalog_loads():
    from nimbus import catalog

    assert catalog  # module imports; the YAML parses
    assert "S3_PUBLIC_BUCKET" in _aliases(PY_CATALOG)
