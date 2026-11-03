from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from jinja2 import Environment, PackageLoader, select_autoescape

from ..compliance import Report, build_report, weakness_mappings
from ..models import go_time

_env = Environment(loader=PackageLoader("nimbus", "templates"), autoescape=select_autoescape(["html", "j2"]))

GOOD, WARN, CRIT, TRACK, INK, INK2 = "#5f7a2a", "#b8860b", "#a8321e", "#cdb995", "#2a1a10", "#5a4330"
MONO = "Spleen,Terminus,fixed,ui-monospace,Menlo,monospace"


def _score_color(score: float) -> tuple[str, str]:
    if score >= 80:
        return GOOD, "Good"
    if score >= 50:
        return WARN, "Needs work"
    return CRIT, "At risk"


def gauge_svg(score: float, label: str = "Compliance score", size: int = 180) -> str:
    """Inline SVG semicircle gauge. The number and status label are text (never colour alone)."""
    score = max(0.0, min(100.0, float(score)))
    color, status = _score_color(score)
    r, cx, cy, w = 70, 90, 88, 14
    start = (cx - r, cy)
    ang = math.pi * (1 - score / 100)
    end = (cx + r * math.cos(ang), cy - r * math.sin(ang))
    track = f"M {start[0]} {start[1]} A {r} {r} 0 0 1 {cx + r} {cy}"
    value = f"M {start[0]} {start[1]} A {r} {r} 0 0 1 {end[0]:.2f} {end[1]:.2f}" if score > 0 else ""
    h = int(size * 0.72)
    return (
        f'<svg class="gauge" role="img" aria-label="{html.escape(label)}: {score:.1f}% ({status})" width="{size}" height="{h}" '
        f'viewBox="0 0 180 130" xmlns="http://www.w3.org/2000/svg">'
        f'<path d="{track}" fill="none" stroke="{TRACK}" stroke-width="{w}" stroke-linecap="butt"/>'
        + (f'<path d="{value}" fill="none" stroke="{color}" stroke-width="{w}" stroke-linecap="butt"/>' if value else "")
        + f'<text x="90" y="80" text-anchor="middle" font-size="30" font-weight="700" fill="{INK}" '
        f'font-family="{MONO}">{score:.1f}%</text>'
        f'<text x="90" y="104" text-anchor="middle" font-size="12" fill="{INK2}" '
        f'font-family="{MONO}">{html.escape(status)} · {html.escape(label)}</text>'
        "</svg>"
    )


def _summary_text(r: Report) -> str:
    fw = r.framework.name
    if r.passing + r.failing == 0:
        return f"No automated evidence maps to {fw} controls yet. Run a scan covering the in-scope accounts."
    s = (f"{fw}: {r.score_percent}% of assessed controls pass ({r.passing} of {r.passing + r.failing}); "
         f"{r.not_assessed} control(s) need manual evidence.")
    if r.roadmap:
        top = r.roadmap[0]
        s += (f" Highest-priority fix: {top.title} ({top.canonical_id}, {top.severity}, {top.count} resource(s)), "
              f"affecting controls {', '.join(top.controls[:4])}.")
    crit = r.severity_counts.get("CRITICAL", 0)
    if crit:
        s += f" {crit} CRITICAL finding(s) are open."
    if r.attack_paths:
        s += f" {len(r.attack_paths)} attack path(s) chain these weaknesses into breach scenarios."
    return s


def render_html(report: Report) -> str:
    derived = any(report.framework.key in m for m in weakness_mappings().values())
    return _env.get_template("report.html.j2").render(
        r=report, gauge=gauge_svg(report.score_percent), summary_text=_summary_text(report), weakness_derived=derived)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str) + "\n"


def render_markdown(report: Report) -> str:
    r = report
    out = [f"# {r.framework.name} {r.framework.version} compliance report", "",
           f"Generated {r.generated_at} - scope: {r.scope}" + (f" - scan `{r.monitoring.get('scan_id')}`" if r.monitoring.get("scan_id") else ""), "",
           "## Executive summary", "", _summary_text(r), "",
           "| Score | Passing | Failing | Not assessed |", "|---|---|---|---|",
           f"| {r.score_percent}% | {r.passing} | {r.failing} | {r.not_assessed} |", "",
           "## Control status", "", "| Control | Title | Status | Failed | Passed | Max severity | Failing resources |",
           "|---|---|---|---|---|---|---|"]
    for c in r.controls:
        res = ", ".join(c.resources)
        res = res if len(res) <= 80 else res[:77] + "..."
        out.append(f"| {c.id} | {c.title} | {c.status} | {c.failed} | {c.passed} | {c.max_severity} | {res} |")
    out += ["", "## Remediation roadmap", ""]
    if r.roadmap:
        out += ["| # | Check | Severity | Resources | Controls | Command |", "|---|---|---|---|---|---|"]
        for i, it in enumerate(r.roadmap, 1):
            out.append(f"| {i} | {it.title} (`{it.canonical_id}`) | {it.severity} | {it.count} | {', '.join(it.controls)} | `{it.command}` |")
    else:
        out.append("No failing checks in scope.")
    out += ["", "## Attack paths", ""]
    if r.attack_paths:
        for p in r.attack_paths:
            out.append(f"- **{p['name']}** -> {p['impact']} ({p['severity']}, score {p['score']:.1f}, {p['provider']}:{p['account']})")
    else:
        out.append("No attack paths detected.")
    out += ["", "## Evidence", ""]
    for c in r.failing_controls():
        out.append(f"### {c.id} {c.title}")
        for e in c.evidence:
            out.append(f"- `{e.finding_id}` {e.severity} {e.title} - `{e.resource_id}` ({e.source}/{e.check_id}, first {e.first_seen}, last {e.last_seen}, via {e.mapped_by})")
        out.append("")
    out += ["## Methodology", "",
            "FAIL = a failing finding maps to the control; PASS = only passing checks map; NOT_ASSESSED = no automated coverage. "
            "Score = passing / (passing + failing).", "",
            f"Continuous monitoring: {r.monitoring.get('note', '')}", ""]
    return "\n".join(out)


def render_pdf(report: Report, out_path: str | Path) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError("PDF output needs reportlab: pip install 'nimbus-cspm[pdf]' (or use --format html and print to PDF)") from exc

    r = report
    out_path = Path(out_path)
    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8, leading=10)
    esc = lambda s: html.escape(str(s))  # noqa: E731
    story: list[Any] = [
        Paragraph(esc(f"{r.framework.name} {r.framework.version} - compliance report"), styles["Title"]),
        Paragraph(esc(f"Generated {r.generated_at} · scope: {r.scope}"), styles["BodyText"]),
        Spacer(1, 6 * mm),
        Paragraph(f"<b>Score: {r.score_percent}%</b> ({_score_color(r.score_percent)[1]}) - {r.passing} passing, "
                  f"{r.failing} failing, {r.not_assessed} not assessed", styles["Heading2"]),
        Paragraph(esc(_summary_text(r)), styles["BodyText"]), Spacer(1, 4 * mm),
        Paragraph("Control status", styles["Heading2"]),
    ]
    status_color = {"PASS": colors.HexColor(GOOD), "FAIL": colors.HexColor(CRIT), "NOT_ASSESSED": colors.HexColor("#8a8984")}
    rows = [["Control", "Title", "Status", "Failed", "Passed", "Max sev."]]
    for c in r.controls:
        rows.append([c.id, Paragraph(esc(c.title), small), c.status.replace("_", " "), str(c.failed), str(c.passed), c.max_severity])
    t = Table(rows, colWidths=[22 * mm, 80 * mm, 26 * mm, 14 * mm, 14 * mm, 20 * mm], repeatRows=1)
    ts = [("FONTSIZE", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0efea")),
          ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d8d7d0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, c in enumerate(r.controls, 1):
        ts.append(("TEXTCOLOR", (2, i), (2, i), status_color.get(c.status, colors.black)))
    t.setStyle(TableStyle(ts))
    story += [t, PageBreak(), Paragraph("Remediation roadmap", styles["Heading2"])]
    if r.roadmap:
        rr = [["#", "Check", "Sev.", "Count", "Command"]]
        for i, it in enumerate(r.roadmap, 1):
            rr.append([str(i), Paragraph(esc(f"{it.title} ({it.canonical_id})"), small), it.severity, str(it.count), Paragraph(esc(it.command), small)])
        t2 = Table(rr, colWidths=[8 * mm, 70 * mm, 20 * mm, 14 * mm, 64 * mm], repeatRows=1)
        t2.setStyle(TableStyle(ts[:4]))
        story.append(t2)
    else:
        story.append(Paragraph("No failing checks in scope.", styles["BodyText"]))
    story.append(Paragraph("Attack paths", styles["Heading2"]))
    for p in r.attack_paths or []:
        story.append(Paragraph(esc(f"{p['name']} -> {p['impact']} ({p['severity']}, score {p['score']:.1f})"), styles["BodyText"]))
    if not r.attack_paths:
        story.append(Paragraph("No attack paths detected.", styles["BodyText"]))
    story += [PageBreak(), Paragraph("Evidence appendix", styles["Heading2"])]
    for c in r.failing_controls():
        story.append(Paragraph(esc(f"{c.id} {c.title}"), styles["Heading3"]))
        for e in c.evidence:
            story.append(Paragraph(esc(f"[{e.severity}] {e.title} - {e.resource_id} ({e.provider}:{e.account}) "
                                       f"source {e.source}/{e.check_id}, first {e.first_seen}, last {e.last_seen}, id {e.finding_id}"), small))
            if e.raw_excerpt:
                story.append(Paragraph("<font face='Courier'>" + esc(e.raw_excerpt) + "</font>", small))
    story += [Spacer(1, 6 * mm), Paragraph("Methodology", styles["Heading2"]),
              Paragraph("FAIL = a failing finding maps to the control; PASS = only passing checks map; NOT ASSESSED = no automated "
                        "coverage (collect manual evidence). Score = passing / (passing + failing). " + esc(r.monitoring.get("note", "")),
                        styles["BodyText"])]
    SimpleDocTemplate(str(out_path), pagesize=A4, title=f"{r.framework.name} compliance report",
                      leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm).build(story)
    return out_path


def executive_summary_html(reports: Iterable[Report], findings_total: int = 0) -> str:
    items = [{"r": r, "gauge": gauge_svg(r.score_percent, r.framework.key, size=160)} for r in reports]
    return _env.get_template("executive.html.j2").render(
        reports=items, findings_total=findings_total, generated_at=go_time(datetime.now(timezone.utc).replace(microsecond=0)))


def build_from_store(store, framework: str, custom_path: Optional[str] = None) -> Report:
    return build_report(framework, store.findings(), custom_path=custom_path, attack_paths=store.attack_paths(), scan=store.last_scan())


def render(report: Report, fmt: str, out: Optional[str | Path] = None) -> Optional[str]:
    """Render to a string (html/md/json) or a file (pdf requires ``out``)."""
    fmt = fmt.lower()
    if fmt == "pdf":
        if not out:
            raise ValueError("PDF output needs an output path")
        render_pdf(report, out)
        return None
    text = {"html": render_html, "md": render_markdown, "markdown": render_markdown, "json": render_json}[fmt](report)
    if out:
        Path(out).write_text(text, encoding="utf-8")
    return text
