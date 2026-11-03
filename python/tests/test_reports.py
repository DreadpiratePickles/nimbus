import json

import pytest

from nimbus.compliance import build_report
from nimbus.reports import build_from_store, executive_summary_html, gauge_svg, render, render_html, render_markdown, render_pdf

from .conftest import sample_findings, sample_paths


def test_html_report_contains_score_and_sections():
    fs = sample_findings()
    rep = build_report("soc2", fs, attack_paths=sample_paths(fs))
    html = render_html(rep)
    assert f"{rep.score_percent:.1f}%" in html
    for section in ("Executive summary", "Control status", "Remediation roadmap", "Attack-path summary", "Methodology", "Evidence appendix"):
        assert section in html
    assert "<svg" in html and "CC6.2" in html and "cloud-posture fix --finding" in html
    assert "<script" not in html and "http://" not in html.replace("http://www.w3.org/2000/svg", "")  # self-contained
    assert "@media print" in html


def test_markdown_json_pdf(tmp_path, seeded):
    rep = build_from_store(seeded, "cis_aws")
    md = render_markdown(rep)
    assert md.startswith("# CIS Amazon Web Services") and "| 1.10 |" in md
    data = json.loads(render(rep, "json"))
    assert data["framework"]["key"] == "cis_aws" and data["monitoring"]["scan_id"] == "scan-1"
    pytest.importorskip("reportlab")
    out = render_pdf(rep, tmp_path / "r.pdf")
    assert out.read_bytes()[:4] == b"%PDF"


def test_gauge_and_executive():
    svg = gauge_svg(72.5)
    assert "72.5%" in svg and "Needs work" in svg
    reps = [build_report(k, sample_findings()) for k in ("soc2", "pci_dss")]
    html = executive_summary_html(reps, findings_total=12)
    assert "SOC 2" in html and "PCI DSS" in html


CWM_TOKENS = ("--root:#2b1d14", "--win:#efe4cf", "--ink:#2a1a10", "--idle:#6b4e36")


def test_html_outputs_use_cwm_brown_theme():
    from nimbus.server import BUILTIN_HTML

    fs = sample_findings()
    pages = {
        "report": render_html(build_report("soc2", fs)),
        "executive": executive_summary_html([build_report("soc2", fs)], findings_total=len(fs)),
        "server": BUILTIN_HTML,
    }
    for name, page in pages.items():
        for tok in CWM_TOKENS:
            assert tok in page, f"{name} missing {tok}"
        assert "border-radius" not in page and "box-shadow" not in page, f"{name} has modern chrome"
        assert "monospace" in page, f"{name} not monospace"
