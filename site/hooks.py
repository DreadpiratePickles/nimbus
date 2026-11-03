"""MkDocs hooks for the nimbus site.

`<!-- include: PATH -->` on its own line is replaced by the contents of PATH (relative to the
repo root), so pages such as the check catalog are generated from the files the code ships
with instead of being copied by hand. A line inside a fenced block works too, which is how
the example config is shown verbatim.
"""
from __future__ import annotations

import os
import re

INCLUDE = re.compile(r"^<!--\s*include:\s*(\S+)\s*-->\s*$", re.M)
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _read(rel: str) -> str:
    path = os.path.abspath(os.path.join(REPO, rel))
    if not path.startswith(REPO + os.sep):
        raise ValueError(f"include outside the repo: {rel}")
    with open(path, encoding="utf-8") as fh:
        return fh.read().rstrip("\n")


def on_page_markdown(markdown: str, page, config, files) -> str:
    return INCLUDE.sub(lambda m: _read(m.group(1)), markdown)


def on_config(config):
    # Rebuild when an included source file changes during `mkdocs serve`.
    for rel in ("docs/checks.md", "cloud-posture.example.yaml"):
        config.watch.append(os.path.join(REPO, rel))
    return config
