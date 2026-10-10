"""`nimbus` command line (typer app named ``app``)."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, List, Optional


# Flipped to True by the release that publishes the package to PyPI. Until then (r5 #12: no
# "nimbus-cspm" package is published) install hints are the from-source command.
PYPI_PUBLISHED = False
_REPO_URL = "https://github.com/DreadpiratePickles/nimbus"


def _install_target(checkout: Optional[Path]) -> str:
    """pip's argument for installing this layer: ``-e "<checkout>"`` in a source checkout, the
    published package once PYPI_PUBLISHED, otherwise the git+https form (subdirectory python).
    The ``[ai]`` extra (the anthropic SDK) only when ANTHROPIC_API_KEY is set: the offline copilot
    runs on the base package (W7-POLISH, r5 #12)."""
    import os

    extra = "[ai]" if os.environ.get("ANTHROPIC_API_KEY", "").strip() else ""
    if checkout is not None:
        return f'-e "{checkout}{extra}"'
    if PYPI_PUBLISHED:
        return f'"nimbus-cspm{extra}"'
    return f'"nimbus-cspm{extra} @ git+{_REPO_URL}@main#subdirectory=python"'


def _missing_dependency(exc: ImportError) -> None:
    """A fresh clone without `pip install`: one actionable line, never a traceback (r4 #6 / N2)."""
    name = getattr(exc, "name", None) or str(exc)
    src = Path(__file__).resolve().parents[1]
    target = _install_target(src if (src / "pyproject.toml").exists() else None)
    sys.stderr.write(f"nimbus: the Python layer is missing the dependency {name!r}. Install the copilot's dependencies with:\n"
                     f"  {sys.executable} -m pip install {target}\n"
                     "(scanning, scoring and paths are Go-native and need none of this; `cloud-posture ask` is the only command that does)\n")
    raise SystemExit(3)


try:
    import typer
except ImportError as _exc:  # pragma: no cover - exercised by a subprocess test
    _missing_dependency(_exc)

from . import __version__

app = typer.Typer(name="nimbus", help="nimbus - intelligence layer for cloud-posture (compliance, AI copilot, risk, reports, API).",
                  no_args_is_help=True, add_completion=False)
plugin_app = typer.Typer(help="Run nimbus plugins (Python checks emitting native findings).", no_args_is_help=True)
app.add_typer(plugin_app, name="plugin")

DB_OPT = typer.Option(None, "--db", envvar="CLOUD_POSTURE_DB", help="SQLite DB (default ./.cloud-posture/posture.db)")


def _store(db: Optional[str]):
    from .store import Store, default_db_path

    path = db or default_db_path()
    if not Path(path).exists():
        typer.secho(f"database {path} not found - run `cloud-posture scan` first (or pass --db)", fg="red", err=True)
        raise typer.Exit(2)
    return Store(path, create=False)


def _dump(obj: Any) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str))


ASK_MAX_ROWS = 20
ASK_MAX_BYTES = 2048
_CELL = 60


def _ask_table(cols: list[str], rows: list[list[Any]], full: bool = False) -> str:
    """The rows behind an answer as plain aligned text: at most ASK_MAX_ROWS rows and
    ASK_MAX_BYTES bytes with cells cut at 60 characters, unless ``full`` (r4 #6 / N3: the
    who-can answer was a 40 KB wrapped table at non-TTY width)."""
    def cell(v: Any) -> str:
        t = "" if v is None else " ".join(str(v).split())
        return t if full or len(t) <= _CELL else t[:_CELL - 1] + "…"

    body = [[cell(v) for v in r] for r in rows]
    shown = body if full else body[:ASK_MAX_ROWS]
    widths = [len(str(c)) for c in cols]
    for r in shown:
        widths = [max(w, len(v)) for w, v in zip(widths, r)] + widths[len(r):]
    fmt = lambda r: "  ".join(v.ljust(w) for v, w in zip(r, widths)).rstrip()  # noqa: E731
    lines = [fmt([str(c) for c in cols]), fmt(["-" * w for w in widths])]
    size, n = sum(len(x.encode()) + 1 for x in lines), 0
    for r in shown:
        ln = fmt(r)
        if not full and size + len(ln.encode()) + 1 > ASK_MAX_BYTES:
            break
        lines.append(ln)
        size += len(ln.encode()) + 1
        n += 1
    if n < len(rows):
        lines.append(f"… showing {n} of {len(rows)} rows (--full prints every row and whole cells; --json for machine output)")
    return "\n".join(lines)


def _table(cols: list[str], rows: list[list[Any]], max_rows: int = 200) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError as exc:  # pragma: no cover
        _missing_dependency(exc)

    t = Table(show_lines=False)
    for c in cols:
        t.add_column(str(c), overflow="fold")
    for r in rows[:max_rows]:
        t.add_row(*["" if v is None else str(v) for v in r])
    Console().print(t)
    if len(rows) > max_rows:
        typer.echo(f"... {len(rows) - max_rows} more rows")


@app.command()
def version() -> None:
    """Print the nimbus version."""
    typer.echo(f"nimbus {__version__}")


@app.command()
def ask(question: str = typer.Argument(..., help="natural-language question"), db: Optional[str] = DB_OPT,
        as_json: bool = typer.Option(False, "--json"),
        show_sql: bool = typer.Option(False, "--show-sql", help="print the SQL that ran (once, under Sources:)"),
        full: bool = typer.Option(False, "--full", help="print every row of the answer's table (default: 20 rows, 2 KB)")) -> None:
    """Ask the security copilot (NL -> SQL -> answer). The answer ends with a Sources: block; the
    SQL itself is printed only with --show-sql (it is always in --json)."""
    from .ai.copilot import SecurityCopilot

    res = SecurityCopilot(_store(db), show_sql=show_sql).ask(question)
    if as_json:
        _dump(res)
        return
    typer.secho(res.get("answer", ""), bold=True)
    if res.get("columns"):
        typer.echo(_ask_table(res["columns"], res["rows"], full=full))


@app.command()
def explain(finding_id: str, db: Optional[str] = DB_OPT, as_json: bool = typer.Option(False, "--json")) -> None:
    """Explain a finding (or attack path id) in plain language."""
    from .ai.explain import explain_attack_path, explain_finding

    s = _store(db)
    f = s.finding(finding_id)
    if f is not None:
        res = explain_finding(f, [p for p in s.attack_paths() if f.id in p.finding_ids])
    else:
        p = next((p for p in s.attack_paths() if p.id == finding_id), None)
        if p is None:
            typer.secho(f"no finding or attack path {finding_id}", fg="red", err=True)
            raise typer.Exit(1)
        res = explain_attack_path(p, {x.id: x for x in s.findings()})
    _dump(res) if as_json else typer.echo(res["explanation"])


@app.command()
def investigate(finding_id: str, db: Optional[str] = DB_OPT, as_json: bool = typer.Option(False, "--json")) -> None:
    """Finding + attack paths + blast radius (<=4 hops over the security graph)."""
    from .ai.copilot import SecurityCopilot

    try:
        res = SecurityCopilot(_store(db)).investigate(finding_id)
    except KeyError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    if as_json:
        _dump(res)
        return
    typer.secho(res["summary"], bold=True)
    typer.echo("\n" + res["explanation"])
    for p in res["attack_paths"]:
        typer.echo(f"\n[path] {p['name']} (score {p['score']}): {p['explanation']}")
    sens = res["blast_radius"]["sensitive"]
    if sens:
        typer.echo("\nSensitive resources reachable:")
        for r in sens:
            typer.echo(f"  {r['hops']} hop(s): {r['name']}  via {' / '.join(r['path'])}")
    typer.echo("\nNext: " + " ; ".join(res["next_steps"]))


@app.command()
def guidance(canonical_id: str, db: Optional[str] = DB_OPT, as_json: bool = typer.Option(False, "--json")) -> None:
    """Remediation guidance for a canonical check id."""
    from .ai.copilot import SecurityCopilot
    from .store import Store, default_db_path

    path = db or default_db_path()
    res = SecurityCopilot(Store(path, create=False) if Path(path).exists() else Store(path)).remediation_guidance(canonical_id)
    _dump(res) if as_json else typer.echo(res["guidance"])


@app.command()
def policy(requirement: str, out: Optional[Path] = typer.Option(None, "--out"), as_json: bool = typer.Option(False, "--json")) -> None:
    """Generate an OPA/Rego policy from a plain-language requirement."""
    from .ai.copilot import generate_policy

    res = generate_policy(requirement)
    if not res["policy"]:
        typer.secho(res["notes"], fg="red", err=True)
        raise typer.Exit(1)
    if out:
        out.write_text(res["policy"], encoding="utf-8")
        typer.echo(f"wrote {out} ({res['mode']}{', template ' + res['template'] if res['template'] else ''})")
    elif as_json:
        _dump(res)
    else:
        typer.echo(res["policy"])
        typer.secho(f"# {res['notes']}", fg="cyan", err=True)


@app.command()
def fix(finding_id: str, fmt: str = typer.Option("terraform", "--format", "-f", help="terraform|cloudformation|bicep|kubernetes"),
        current: Optional[Path] = typer.Option(None, "--current", help="existing IaC file to patch"),
        framework: Optional[str] = typer.Option(None, "--framework"), db: Optional[str] = DB_OPT,
        as_json: bool = typer.Option(False, "--json")) -> None:
    """Generate an IaC fix for a finding."""
    from .ai.fix import generate_fix

    f = _store(db).finding(finding_id)
    if f is None:
        typer.secho(f"finding {finding_id} not found", fg="red", err=True)
        raise typer.Exit(1)
    res = generate_fix(f, fmt, current_code=current.read_text() if current else None, framework=framework)
    if as_json:
        _dump(res)
    else:
        typer.echo(res["code"])
        typer.secho(res["explanation"], fg="cyan", err=True)


@app.command()
def query(sql: Optional[str] = typer.Argument(None, help="read-only SQL"), named: Optional[str] = typer.Option(None, "--named"),
          list_: bool = typer.Option(False, "--list"), db: Optional[str] = DB_OPT,
          output: str = typer.Option("table", "--output", "-o", help="table|json|csv")) -> None:
    """Run a named compliance query or ad-hoc read-only SQL."""
    from . import queries as qlib
    from .ai.sqlsafety import UnsafeSQL

    if list_:
        for q in qlib.index():
            fws = ", ".join(q.get("frameworks") or [])
            typer.echo(f"{q['name']:<38} {q['description']}" + (f"  [{fws}]" if fws else ""))
        return
    if not named and not sql:
        typer.secho("give SQL, --named NAME or --list", fg="red", err=True)
        raise typer.Exit(2)
    s = _store(db)
    try:
        cols, rows = qlib.run_named(s, named) if named else qlib.run_sql(s, sql or "")
    except (KeyError, UnsafeSQL) as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    if output == "json":
        _dump([dict(zip(cols, r)) for r in rows])
    elif output == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(cols)
        w.writerows(rows)
    else:
        _table(cols, rows)


@app.command()
def frameworks() -> None:
    """List compliance frameworks."""
    from .compliance import frameworks as fw

    for f in fw():
        typer.echo(f"{f['key']:<14} {f['name']} {f['version']}  ({f['controls']} controls{', weakness-derived' if f['weakness_derived'] else ''})")


@app.command()
def report(framework: str = typer.Option("all", "--framework", help="framework key, alias, or 'all' for the executive summary"),
           framework_set_spec: Optional[str] = typer.Option(
               None, "--framework-set",
               help="with --framework all: default (CIS for the providers in scope + NIST 800-53, PCI DSS, SOC 2, HIPAA, "
                    "ISO 27001, GDPR) | all | comma list of keys"),
           fmt: str = typer.Option("html", "--format", help="html|pdf|md|json"),
           out: Optional[Path] = typer.Option(None, "--out", help="output file (stdout for html/md/json when omitted)"),
           custom: Optional[Path] = typer.Option(None, "--custom", help="custom framework YAML"), db: Optional[str] = DB_OPT) -> None:
    """Build an audit-ready compliance report."""
    from .compliance import build_report, framework_set, load_frameworks
    from .reports import build_from_store, executive_summary_html, render

    multi = framework == "all" and not custom
    if framework_set_spec is not None and not multi:
        typer.secho(f"--framework-set selects several frameworks; use it with --framework all, not --framework {framework}",
                    fg="red", err=True)
        raise typer.Exit(2)
    s = _store(db)
    if multi:
        fs, paths, scan = s.findings(), s.attack_paths(), s.last_scan()
        try:
            keys = framework_set(framework_set_spec, [f.provider for f in fs])
        except ValueError as exc:
            typer.secho(str(exc), fg="red", err=True)
            raise typer.Exit(2)
        total = len(load_frameworks())
        if framework_set_spec is None:
            typer.echo(f"{len(keys)} of {total} frameworks (framework-set default); use --framework-set all for every framework", err=True)
        else:
            typer.echo(f"{len(keys)} of {total} frameworks (framework-set {framework_set_spec})", err=True)
        reps = [build_report(k, fs, attack_paths=paths, scan=scan) for k in keys]
        if fmt == "json":
            text = json.dumps([r.to_dict() for r in reps], indent=2, default=str)
        else:
            text = executive_summary_html(reps, findings_total=len(fs))
        out.write_text(text, encoding="utf-8") if out else typer.echo(text)
        if out:
            typer.echo(f"wrote {out}", err=True)
        return
    rep = build_from_store(s, framework, custom_path=str(custom) if custom else None)
    try:
        text = render(rep, fmt, out)
    except RuntimeError as exc:
        typer.secho(str(exc), fg="red", err=True)
        raise typer.Exit(1)
    except (KeyError, ValueError) as exc:
        typer.secho(f"bad format/output: {exc}", fg="red", err=True)
        raise typer.Exit(2)
    if out:
        typer.echo(f"wrote {out} - {rep.framework.name}: {rep.score_percent}% ({rep.passing} pass / {rep.failing} fail / {rep.not_assessed} n/a)", err=True)
    elif text is not None:
        typer.echo(text)


@app.command()
def risk(top: int = typer.Option(50, "--top"), db: Optional[str] = DB_OPT, as_json: bool = typer.Option(False, "--json"),
         model: Optional[str] = typer.Option(None, "--model", help="weights / linear model JSON")) -> None:
    """Context-aware risk prioritisation."""
    from .risk import Weights, prioritize_store

    res = [r.to_dict() for r in prioritize_store(_store(db), top=top, weights=Weights.load(model))]
    if as_json:
        typer.echo(json.dumps(res))
        return
    _table(["risk", "severity", "check", "resource", "reasons"],
           [[r["risk_score"], r["severity"], r["canonical_id"], r["resource"], "; ".join(r["reasons"][:3])] for r in res])


@app.command()
def alert(finding: List[str] = typer.Option(..., "--finding", help="finding id (repeatable)"),
          target: List[str] = typer.Option(..., "--target", help="slack|teams|jira|github|datadog|pagerduty"),
          db: Optional[str] = DB_OPT) -> None:
    """Send findings to alert targets configured via environment variables."""
    from .integrations import dispatch

    s = _store(db)
    fs = [f for f in (s.finding(i) for i in finding) if f]
    _dump([r.to_dict() for r in dispatch(fs, target, s.attack_paths())])


@app.command()
def ingest(path: Path, db: Optional[str] = DB_OPT) -> None:
    """Load native findings (JSON array or JSON lines) into the DB (Python-side equivalent of `cloud-posture ingest`)."""
    from .models import load_findings
    from .store import Store, default_db_path

    n = Store(db or default_db_path()).upsert_findings(load_findings(path.read_text(encoding="utf-8")))
    typer.echo(f"ingested {n} findings")


@app.command()
def serve(host: str = typer.Option("127.0.0.1", "--host"), port: int = typer.Option(8765, "--port"), db: Optional[str] = DB_OPT,
          allowed_host: List[str] = typer.Option([], "--allowed-host", help="Extra Host header values to accept (repeatable); also $NIMBUS_ALLOWED_HOSTS")) -> None:
    """Run the dashboard API (FastAPI + WebSocket)."""
    from .server import serve as _serve

    _serve(host, port, db, allowed_hosts=allowed_host)


@plugin_app.command("run")
def plugin_run(path: str, jsonl: bool = typer.Option(False, "--jsonl"), out: Optional[Path] = typer.Option(None, "--out"),
               ingest_db: Optional[str] = typer.Option(None, "--ingest", help="also upsert into this DB")) -> None:
    """Run a plugin file/module and print native findings."""
    from . import plugin as P

    findings = P.run(path)
    text = P.dumps(findings, jsonl=jsonl)
    if out:
        out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if ingest_db:
        from .store import Store

        Store(ingest_db).upsert_findings(findings)


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    app()
