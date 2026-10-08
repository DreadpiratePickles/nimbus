"""nimbus-cspm: the Python intelligence layer of the `cloud-posture` CSPM.

Submodules are imported lazily so ``python -m nimbus.plugin`` / ``python -m nimbus.risk``
do not trigger double-import warnings, while ``import nimbus; nimbus.plugin.check(...)`` works.
"""
from __future__ import annotations

import importlib

__version__ = "0.1.0"

_LAZY = {
    "models", "store", "plugin", "risk", "compliance", "reports", "ai", "queries",
    "integrations", "server", "cli", "catalog",
}


def __getattr__(name: str):
    if name in _LAZY:
        return importlib.import_module(f"nimbus.{name}")
    raise AttributeError(f"module 'nimbus' has no attribute {name!r}")


__all__ = sorted(_LAZY) + ["__version__"]
