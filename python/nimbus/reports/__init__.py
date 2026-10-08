"""Audit-ready compliance reports: HTML (Jinja2, self-contained, print-friendly), PDF (reportlab),
Markdown and JSON, plus a multi-framework executive summary."""
from .render import (  # noqa: F401
    build_from_store, executive_summary_html, gauge_svg, render, render_html, render_json, render_markdown, render_pdf,
)
