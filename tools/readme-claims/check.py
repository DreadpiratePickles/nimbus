#!/usr/bin/env python3
"""README claim checker (plan v3 §0.2 row 0-6, §9 item 7). Python 3 stdlib only.

Every README *unit* (paragraph, list item, heading or table row) that contains a number or a
superlative must end with a claim marker whose references all resolve:

    Recall is 100% on the synthetic lab. <!-- claim: docs/benchmark.md#current-numbers-... -->

In a table row the marker goes at the end of the last cell (``... <!-- claim: ref --> |``).
A whole table can be covered by a marker on the line directly above it:

    <!-- claim-table: docs/benchmark.md#current-numbers-... -->
    | id | ... |

Reference kinds (comma- or space-separated; every one must resolve):
  * Go test      ``TestName`` / ``FuzzName`` / ``BenchmarkName`` / ``ExampleName``, optionally with a
                 directory prefix ``internal/attackpath/TestToxicFloorLab``. Resolves when
                 ``func <Name>(`` appears in a ``*_test.go`` file (under the prefix, if given).
  * pytest node  ``python/tests/test_x.py::test_name`` (``::Class::test`` and ``[param]`` allowed).
                 Resolves when the file exists and defines every named class/function.
  * doc section  ``<path>.md#<anchor>``: the Markdown file exists and has a heading whose GitHub
                 slug equals the anchor (e.g. a docs/benchmark.md section).

Ignored: fenced code blocks, inline code spans, link targets, HTML comments, ISO dates, version
identifiers (v0.2.0) and the standard names listed in NON_CLAIM (Apache-2.0, SHA-256, OCSF 1.6...).

Usage: check.py [--root DIR] [--list] [README.md]   (exit 0 = pass, 1 = unlinked claim or bad ref)
"""
from __future__ import annotations

import argparse
import dataclasses
import os
import re
import sys

SUPERLATIVES = ("every", "all", "only", "fastest", "complete", "best")
SUPERLATIVE_RE = re.compile(r"\b(" + "|".join(SUPERLATIVES) + r")\b", re.IGNORECASE)

# Tokens that contain digits but are names, not claims. Applied after code/URLs are stripped.
NON_CLAIM = [
    r"\b\d{4}-\d{2}-\d{2}\b",                      # ISO dates
    r"\bv\d+(?:\.\d+)*(?:-[0-9A-Za-z.]+)?\b",       # versions: v0.2.0, v1, v0.2.0-rc.1
    r"\bApache[- ]2\.0\b",
    r"\bSHA-?(?:1|256|512)\b",
    r"\b(?:OCSF|SARIF|SPDX|CycloneDX|OpenAPI|SLSA)(?:\s+(?:v|L)?\d+(?:\.\d+)*)?",
    r"\bNIST(?: SP)? 800-53\b",
    r"\bISO(?:/IEC)? 27001(?::2022)?\b",
    r"\bSOC ?2\b",
    r"\bM365\b",
    r"\bIMDSv[12]\b",
    r"\b[A-Za-z]+\d+[A-Za-z0-9]*\b",               # identifiers with an embedded digit: S3, EC2, boto3, Neo4j
    r"\bOAuth ?2(?:\.\d)?\b",
    r"\bk8s\b",
    r"\b(?:amd64|arm64|x86_64)\b",
    r"§\s?\d+(?:\.\d+)*",                           # plan / strategy section refs
    r"\bPhase \d\b",
    r"\b(?:O|P0|P1|P2|P3)-?\d+\b",                  # owner actions O1..O7, track ids
    r"\b[PFSW]\d{2}\b",                             # lab label ids P01, F01, S01, W01
    r"\b0-\d\b",                                    # plan §0.2 row ids
    r"^\s*\d+\.\s",                                 # ordered-list numbering
]
NON_CLAIM_RE = re.compile("|".join(NON_CLAIM))
DIGIT_RE = re.compile(r"\d")

_BODY = r"((?:(?!-->).)*?)"  # marker body: never crosses a closing -->
MARKER_RE = re.compile(r"<!--\s*claim:\s*" + _BODY + r"\s*-->\s*$")
ROW_MARKER_RE = re.compile(r"<!--\s*claim:\s*" + _BODY + r"\s*-->\s*\|?\s*$")  # table rows: inside the last cell
TABLE_MARKER_RE = re.compile(r"^\s*<!--\s*claim-table:\s*(.*?)\s*-->\s*$")
COMMENT_RE = re.compile(r"<!--.*?-->")
INLINE_CODE_RE = re.compile(r"`+[^`]*`+")
LINK_TARGET_RE = re.compile(r"\]\([^)]*\)")
AUTOLINK_RE = re.compile(r"<https?://[^>]+>|https?://\S+")
GO_REF_RE = re.compile(r"^(?:(?P<dir>[\w.\-/]+)/)?(?P<name>(?:Test|Fuzz|Benchmark|Example)\w*)$")
PY_REF_RE = re.compile(r"^(?P<file>[\w.\-/]+\.py)::(?P<rest>[\w:]+?)(?:\[[^\]]*\])?$")
DOC_REF_RE = re.compile(r"^(?P<file>[\w.\-/]+\.md)#(?P<anchor>[\w\-]+)$")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "bin", ".cloud-posture"}


@dataclasses.dataclass
class Unit:
    line: int          # 1-based line of the unit's last line (where its marker lives)
    text: str          # cleaned text
    refs: list[str]
    triggers: list[str]


@dataclasses.dataclass
class BadRef:
    line: int
    ref: str
    why: str


@dataclasses.dataclass
class Result:
    claims: list[Unit]
    unlinked: list[Unit]
    bad_refs: list[BadRef]


def clean(text: str) -> str:
    text = COMMENT_RE.sub(" ", text)
    text = INLINE_CODE_RE.sub(" ", text)
    text = LINK_TARGET_RE.sub("]", text)
    text = AUTOLINK_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


TERMS_RE = re.compile(r"\b(?:read|write|append)-only\b", re.IGNORECASE)  # technical terms, not superlatives


def triggers(text: str) -> list[str]:
    found = [m.group(0) for m in SUPERLATIVE_RE.finditer(TERMS_RE.sub(" ", text))]
    residue = NON_CLAIM_RE.sub(" ", text)
    for tok in re.findall(r"\S*\d\S*", residue):
        found.append(tok)
    return found


def split_refs(raw: str) -> list[str]:
    return [r for r in re.split(r"[,\s]+", raw.strip()) if r]


def github_slug(heading: str) -> str:
    s = heading.strip().lower()
    s = INLINE_CODE_RE.sub(lambda m: m.group(0).strip("`"), s)
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


class Resolver:
    def __init__(self, root: str):
        self.root = root
        self._go_index: dict[str, list[str]] | None = None

    def _go(self) -> dict[str, list[str]]:
        if self._go_index is None:
            idx: dict[str, list[str]] = {}
            pat = re.compile(r"^func\s+((?:Test|Fuzz|Benchmark|Example)\w*)\s*\(", re.MULTILINE)
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fn in filenames:
                    if fn.endswith("_test.go"):
                        path = os.path.join(dirpath, fn)
                        try:
                            with open(path, encoding="utf-8", errors="replace") as fh:
                                body = fh.read()
                        except OSError:
                            continue
                        rel = os.path.relpath(path, self.root).replace(os.sep, "/")
                        for name in pat.findall(body):
                            idx.setdefault(name, []).append(rel)
            self._go_index = idx
        return self._go_index

    def resolve(self, ref: str) -> str | None:
        """Return None when ref resolves, else the reason it does not."""
        m = DOC_REF_RE.match(ref)
        if m:
            path = os.path.join(self.root, m.group("file"))
            if not os.path.isfile(path):
                return f"no such file {m.group('file')}"
            slugs = set()
            in_fence = False
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.lstrip().startswith("```"):
                        in_fence = not in_fence
                        continue
                    if not in_fence and re.match(r"^#{1,6}\s", line):
                        slugs.add(github_slug(line.lstrip("#")))
            return None if m.group("anchor") in slugs else f"no heading with anchor #{m.group('anchor')}"
        m = PY_REF_RE.match(ref)
        if m:
            path = os.path.join(self.root, m.group("file"))
            if not os.path.isfile(path):
                return f"no such file {m.group('file')}"
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            for part in m.group("rest").split("::"):
                if not re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(part)}\b", body, re.MULTILINE):
                    return f"{part} not defined in {m.group('file')}"
            return None
        m = GO_REF_RE.match(ref)
        if m:
            files = self._go().get(m.group("name"), [])
            if m.group("dir"):
                prefix = m.group("dir").rstrip("/") + "/"
                files = [f for f in files if f.startswith(prefix)]
            return None if files else f"no func {m.group('name')} in *_test.go" + (f" under {m.group('dir')}" if m.group("dir") else "")
        return "unknown reference kind (want a Go test name, a pytest node id or <file>.md#<anchor>)"


def units(lines: list[str]):
    """Yield (last_line_no, raw_text, kind, table_refs) for every checkable unit."""
    in_fence = False
    buf: list[str] = []
    buf_end = 0
    table_refs: list[str] | None = None
    table_marker_line = 0
    pending_table_marker: tuple[int, list[str]] | None = None

    def flush():
        nonlocal buf
        if buf:
            out = (buf_end, " ".join(buf), "para", None)
            buf = []
            return out
        return None

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            f = flush()
            if f:
                yield f
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        tm = TABLE_MARKER_RE.match(line)
        if tm:
            f = flush()
            if f:
                yield f
            pending_table_marker = (i, split_refs(tm.group(1)))
            continue
        if stripped.startswith("|"):
            f = flush()
            if f:
                yield f
            if pending_table_marker is not None:
                table_marker_line, table_refs = pending_table_marker
                pending_table_marker = None
            if re.match(r"^\|?\s*:?-{2,}", stripped):  # separator row
                continue
            yield (i, line, "row", (table_marker_line, table_refs) if table_refs is not None else None)
            continue
        table_refs = None
        pending_table_marker = None
        if not stripped:
            f = flush()
            if f:
                yield f
            continue
        if stripped.startswith("#"):
            f = flush()
            if f:
                yield f
            yield (i, line, "heading", None)
            continue
        if re.match(r"^\s*(?:[-*+]|\d+\.)\s", line):
            f = flush()
            if f:
                yield f
        if stripped.startswith("<!--") and stripped.endswith("-->") and not MARKER_RE.search(line):
            continue
        buf.append(line.rstrip("\n"))
        buf_end = i
    f = flush()
    if f:
        yield f


def check_file(readme: str, root: str) -> Result:
    with open(readme, encoding="utf-8") as fh:
        lines = fh.readlines()
    resolver = Resolver(root)
    res = Result(claims=[], unlinked=[], bad_refs=[])
    checked_table_markers: set[int] = set()
    for line_no, raw, kind, table in units(lines):
        refs: list[str] = []
        ref_line = line_no
        # A marker quoted inside an inline code span is documentation, not a marker.
        m = (ROW_MARKER_RE if kind == "row" else MARKER_RE).search(INLINE_CODE_RE.sub(" ", raw))
        if m:
            refs = split_refs(m.group(1))
            if not refs:
                res.bad_refs.append(BadRef(line_no, "", "empty claim marker"))
        elif table is not None:
            ref_line, refs = table
            if not refs and ref_line not in checked_table_markers:
                res.bad_refs.append(BadRef(ref_line, "", "empty claim-table marker"))
        text = clean(raw)
        trig = triggers(text)
        unit = Unit(line_no, text, refs, trig)
        if refs:
            if not (table is not None and not m and ref_line in checked_table_markers):
                for ref in refs:
                    why = resolver.resolve(ref)
                    if why:
                        res.bad_refs.append(BadRef(ref_line, ref, why))
                if table is not None and not m:
                    checked_table_markers.add(ref_line)
            if trig:
                res.claims.append(unit)
        elif trig:
            res.unlinked.append(unit)
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("readme", nargs="?", default="README.md")
    ap.add_argument("--root", default=None, help="repository root (default: the README's directory)")
    ap.add_argument("--list", action="store_true", help="print every claim with its references")
    args = ap.parse_args(argv)
    readme = os.path.abspath(args.readme)
    root = os.path.abspath(args.root or os.path.dirname(readme))
    res = check_file(readme, root)
    name = os.path.relpath(readme, root)
    if args.list:
        for u in res.claims:
            print(f"{name}:{u.line}: {u.text[:110]}")
            print(f"    -> {', '.join(u.refs)}")
    for u in res.unlinked:
        print(f"{name}:{u.line}: unlinked claim (triggers: {', '.join(dict.fromkeys(u.triggers))}): {u.text[:160]}")
    for b in res.bad_refs:
        print(f"{name}:{b.line}: unresolved reference {b.ref!r}: {b.why}")
    ok = not res.unlinked and not res.bad_refs
    print(f"readme-claims: {len(res.claims)} linked claim(s), {len(res.unlinked)} unlinked, "
          f"{len(res.bad_refs)} unresolved reference(s): {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
