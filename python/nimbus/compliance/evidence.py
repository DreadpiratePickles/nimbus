"""Reader for nimbus-evidence/v2 packages (``cloud-posture report --evidence-zip``; W7-VERIFY r5 #9).

The Go CLI writes ``manifest.json`` (SHA-256 of every entry, the audit period, per control its
kind and "effective X of Y days" from scan history) and signs it with cosign into
``manifest.json.sigstore.json``. This reader re-checks every digest and refuses a package whose
manifest passes a manual control, so the HTML/PDF report quotes the same evidence. It does not
verify the signature: that is cosign's job (``cloud-posture verify --evidence <zip> --key
cosign.pub`` or ``cosign verify-blob``); ``signed`` only says the package claims one.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

FORMAT = "nimbus-evidence/v2"
MANIFEST = "manifest.json"
BUNDLE = "manifest.json.sigstore.json"
_MAX_ENTRY = 256 << 20


class EvidenceError(ValueError):
    """The file is not a readable nimbus-evidence/v2 package."""


@dataclass
class EvidencePackage:
    framework: str
    period_days: int
    scans: int
    signed: bool
    statements: dict[str, str] = field(default_factory=dict)
    manual: list[str] = field(default_factory=list)
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unlisted: list[str] = field(default_factory=list)
    manifest: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Every digest matches and nothing is missing or unlisted (signature not checked here)."""
        return not (self.mismatched or self.missing or self.unlisted)


def read_evidence(path: str | Path) -> EvidencePackage:
    entries: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.file_size > _MAX_ENTRY:
                    raise EvidenceError(f"{info.filename}: entry over {_MAX_ENTRY} bytes")
                if info.filename in entries:
                    raise EvidenceError(f"duplicate zip entry {info.filename}")
                entries[info.filename] = z.read(info)
    except zipfile.BadZipFile as e:
        raise EvidenceError(f"{path}: not a zip ({e})") from e
    if MANIFEST not in entries:
        raise EvidenceError(f"{Path(path).name} has no {MANIFEST} (a v1 package carries only MANIFEST.sha256.json)")
    try:
        m = json.loads(entries[MANIFEST])
    except ValueError as e:
        raise EvidenceError(f"{MANIFEST}: {e}") from e
    if m.get("format") != FORMAT:
        raise EvidenceError(f"{MANIFEST}: format {m.get('format')!r}, want {FORMAT!r}")
    period = m.get("period") or {}
    pkg = EvidencePackage(framework=str(m.get("framework", "")), period_days=int(period.get("days", 0)),
                          scans=int(period.get("scans", 0)), signed=bool(m.get("signed")), manifest=m)
    files = m.get("files") or {}
    for name, want in sorted(files.items()):
        if name not in entries:
            pkg.missing.append(name)
        elif hashlib.sha256(entries[name]).hexdigest() != want:
            pkg.mismatched.append(name)
    pkg.unlisted = sorted(n for n in entries if n not in files and n not in (MANIFEST, BUNDLE))
    for c in m.get("controls") or []:
        cid = str(c.get("id", ""))
        if c.get("kind") == "manual":
            if c.get("status") == "PASS" or int(c.get("effective_days", 0)) > 0:
                raise EvidenceError(f"manual control {cid} is marked passing: a manual control is never passed automatically")
            pkg.manual.append(cid)
            continue
        pkg.statements[cid] = str(c.get("statement", ""))
    return pkg
