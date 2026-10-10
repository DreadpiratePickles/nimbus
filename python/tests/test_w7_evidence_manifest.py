"""W7-VERIFY r5 #9: the Python layer reads a nimbus-evidence/v2 package the Go CLI writes —
digests re-checked, per-control period statements, manual controls never passing — so the
HTML/PDF audit report can quote the same evidence. Signature checking stays with cosign / the Go
`verify --evidence` (the reader says whether the package claims a signature)."""
import hashlib
import json
import zipfile

import pytest

from nimbus.compliance.evidence import EvidenceError, read_evidence


def _write(path, files, manifest_edit=None, extra=None):
    digests = {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}
    manifest = {
        "format": "nimbus-evidence/v2", "framework": "cis_7.0_aws", "framework_name": "CIS AWS", "version": "7.0",
        "period": {"from": "2026-07-01T00:00:00Z", "to": "2026-07-10T23:00:00Z", "days": 10, "scans": 9, "source": "scan history"},
        "files": digests, "signed": True,
        "signing": {"method": "cosign sign-blob", "key_ref": "cosign.key", "bundle": "manifest.json.sigstore.json", "verify": "..."},
        "controls": [
            {"id": "2.10", "kind": "native", "status": "PASS", "effective_days": 7, "failing_days": 2, "untested_days": 1,
             "period_days": 10, "statement": "effective 7 of 10 days (2 failing, 1 untested)"},
            {"id": "1.1", "kind": "manual", "status": "MANUAL", "effective_days": 0, "failing_days": 0, "untested_days": 10,
             "period_days": 10, "statement": "manual control: ..."},
        ],
    }
    if manifest_edit:
        manifest_edit(manifest)
    with zipfile.ZipFile(path, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)
        z.writestr("manifest.json", json.dumps(manifest))
        z.writestr("manifest.json.sigstore.json", b"{}")
        for n in extra or []:
            z.writestr(n, b"{}")


def test_reads_a_v2_package(tmp_path):
    p = tmp_path / "ev.zip"
    _write(p, {"report.md": b"# r", "report.json": b"{}"})
    ev = read_evidence(p)
    assert ev.ok and ev.signed and not ev.mismatched
    assert ev.period_days == 10 and ev.scans == 9
    assert ev.statements["2.10"] == "effective 7 of 10 days (2 failing, 1 untested)"
    assert ev.manual == ["1.1"]


def test_tampered_unlisted_and_manual_pass(tmp_path):
    p = tmp_path / "t.zip"
    files = {"report.md": b"# r"}
    _write(p, files, extra=["controls/x/evidence.json"])
    ev = read_evidence(p)
    assert not ev.ok and ev.unlisted == ["controls/x/evidence.json"]

    q = tmp_path / "m.zip"

    def tamper(m):
        m["files"]["report.md"] = "0" * 64
    _write(q, files, manifest_edit=tamper)
    assert read_evidence(q).mismatched == ["report.md"]

    r = tmp_path / "pass.zip"

    def manual_pass(m):
        m["controls"][1]["status"] = "PASS"
    _write(r, files, manifest_edit=manual_pass)
    with pytest.raises(EvidenceError, match="manual control 1.1"):
        read_evidence(r)


def test_not_v2(tmp_path):
    p = tmp_path / "v1.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("MANIFEST.sha256.json", "{}")
    with pytest.raises(EvidenceError, match="manifest.json"):
        read_evidence(p)
