from nimbus.compliance import build_report, frameworks, load_frameworks, weakness_mappings
from nimbus.models import Finding

from .conftest import F, sample_findings, sample_paths


def test_bundled_frameworks():
    fws = load_frameworks()
    assert {"soc2", "iso_27001", "cis_aws", "nist_800_53", "pci_dss", "hipaa", "gdpr"} <= set(fws)
    assert {"CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC6.8", "CC7.1", "CC7.2", "CC7.3", "CC8.1", "A1.2", "C1.1"} <= set(fws["soc2"].controls)
    assert {"A.5.15", "A.8.5", "A.8.24", "A.8.32"} <= set(fws["iso_27001"].controls)
    wm = weakness_mappings()
    assert len(wm) == 21 and wm["NO_MFA"]["soc2"] == ["CC6.1", "CC6.2"]
    listing = {f["key"]: f for f in frameworks()}
    assert listing["soc2"]["weakness_derived"] and not listing["cis_aws"]["weakness_derived"]


def test_cis_report_status_and_score():
    rep = build_report("cis", sample_findings())
    c = {x.id: x for x in rep.controls}
    assert c["1.10"].status == "FAIL" and c["1.10"].failed == 1 and c["1.10"].passed == 1
    assert c["3.1"].status == "NOT_ASSESSED"
    assert rep.failing == len([x for x in rep.controls if x.status == "FAIL"])
    assert rep.score_percent == 0.0  # every assessed CIS control has a failure in the sample


def test_soc2_derived_from_weaknesses():
    fs = sample_findings()
    assert not any("soc2" in f.compliance for f in fs)  # no explicit soc2 mapping on any finding
    rep = build_report("soc2", fs, attack_paths=sample_paths(fs))
    c = {x.id: x for x in rep.controls}
    assert c["CC6.2"].status == "FAIL"  # NO_MFA (alice)
    assert c["CC6.6"].status == "FAIL"  # PUBLIC_NETWORK_EXPOSURE
    assert c["C1.1"].status == "FAIL"   # PUBLIC_DATA_STORE / UNENCRYPTED_AT_REST
    assert c["CC8.1"].status == "NOT_ASSESSED"
    ev = c["CC6.2"].evidence[0]
    assert ev.mapped_by == "weakness:NO_MFA" and ev.source == "prowler" and ev.first_seen.endswith("Z")
    pii = c["C1.1"].evidence
    assert any(len(e.raw_excerpt) <= 400 and e.raw_excerpt.endswith("...") for e in pii)
    # roadmap ordered by severity x count with the fix command
    assert rep.roadmap[0].priority >= rep.roadmap[-1].priority
    assert rep.roadmap[0].command.startswith("cloud-posture fix --finding ")
    assert rep.attack_paths and rep.monitoring["scan_id"] == ""
    # a PASS-only control
    only_pass = build_report("soc2", [F(check_id="x", canonical_id="BRANCH", status="PASS", weaknesses=["BRANCH_UNPROTECTED"], resource={"id": "r"})])
    assert {x.id: x for x in only_pass.controls}["CC8.1"].status == "PASS" and only_pass.score_percent == 100.0


def test_iso_alias_and_custom_framework(tmp_path):
    rep = build_report("iso", sample_findings())
    assert rep.framework.key == "iso_27001"
    assert {x.id: x for x in rep.controls}["A.8.5"].status == "FAIL"
    custom = tmp_path / "acme.yaml"
    custom.write_text("""
name: Acme Cloud Baseline
version: "1.0"
controls:
  ACME-1:
    title: No public data stores
    canonical_ids: [S3_PUBLIC_BUCKET]
  ACME-2:
    title: Databases are encrypted
    weaknesses: [UNENCRYPTED_AT_REST]
  ACME-3:
    title: Branches protected
    canonical_ids: [GH_BRANCH_UNPROTECTED]
""")
    rep = build_report("ignored", sample_findings(), custom_path=custom)
    assert rep.framework.name == "Acme Cloud Baseline" and rep.framework.custom
    c = {x.id: x for x in rep.controls}
    assert c["ACME-1"].status == "FAIL" and c["ACME-1"].evidence[0].mapped_by == "canonical_id"
    assert c["ACME-2"].failed == 2
    assert c["ACME-3"].status == "NOT_ASSESSED"
    assert rep.total_controls == 3


def test_finding_dicts_accepted():
    rep = build_report("pci_dss", [f.to_doc() for f in sample_findings()])
    assert any(x.id == "1.3.6" and x.status == "FAIL" for x in rep.controls)
    assert isinstance(rep.controls[0], object) and Finding
