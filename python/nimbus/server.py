"""FastAPI dashboard API over the posture database.

``create_app(db_path)`` returns the app; ``nimbus serve`` runs it with uvicorn. The WebSocket at
``/ws`` pushes ``{"type": "findings_updated", "scan_id": ...}`` whenever the database file (or its
WAL) changes; the poll interval is ``NIMBUS_WS_POLL`` seconds (default 2).
"""
from __future__ import annotations

import asyncio
import hmac
import html
import ipaddress
import os
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel

from . import __version__
from . import queries as qlib
from .ai.copilot import SecurityCopilot
from .ai.explain import explain_finding
from .ai.fix import generate_fix
from .ai.sqlsafety import UnsafeSQL
from .compliance import frameworks as list_frameworks
from .integrations import dispatch
from .integrations.clients import CLIENTS as ALERT_CHANNELS
from .reports import build_from_store, render_html, render_json, render_markdown, render_pdf
from .risk import prioritize_store
from .store import QueryTimeout, Store, default_db_path


class SQLBody(BaseModel):
    sql: str


class QuestionBody(BaseModel):
    question: str


class FindingBody(BaseModel):
    finding_id: str


class FixBody(BaseModel):
    finding_id: str
    format: str = "terraform"
    current_code: Optional[str] = None
    framework: Optional[str] = None


class AlertBody(BaseModel):
    finding_ids: list[str]
    # Names of server-configured channels only (e.g. "slack"); destinations, URLs and credentials
    # come from the server's environment, never from the request (inventory defect 2).
    targets: list[Any]


def _alert_targets(targets: list[Any]) -> list[str]:
    names = []
    for t in targets:
        if not isinstance(t, str) or t.lower() not in ALERT_CHANNELS:
            raise HTTPException(400, f"targets must be names of server-configured channels ({', '.join(sorted(ALERT_CHANNELS))}); "
                                     "destinations are never taken from the request")
        names.append(t.lower())
    return names


def _require_token(authorization: Optional[str]) -> None:
    token = os.environ.get("CLOUD_POSTURE_TOKEN", "").strip()  # same trim rule as the Go server
    if not token:
        raise HTTPException(501, "alert dispatch over HTTP is disabled: set CLOUD_POSTURE_TOKEN on the server to enable it")
    if not authorization or not hmac.compare_digest(authorization.encode(), f"Bearer {token}".encode()):
        raise HTTPException(401, "unauthorized")


# ---------------------------------------------------------------- Host allowlist + CSRF (same rules as the Go server)

_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
# Starlette's in-process TestClient host; accepted only when create_app() was not given a bind host,
# i.e. never by a listening `nimbus serve` (serve() always passes one).
_IN_PROCESS_HOST = "testserver"


def _hostname(hostport: str) -> str:
    """Lower-cased host part of a Host header value or host[:port] entry, without brackets or a trailing dot."""
    h = (hostport or "").strip().lower()
    if h.startswith("["):
        end = h.find("]")
        h = h[1:end] if end > 0 else ""
    elif h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _is_unspecified(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return host == ""


def allowed_host_names(bind_host: Optional[str], allowed_hosts: Iterable[str] = ()) -> set[str]:
    """Host names this server answers to: loopback names, the bound host (unless 0.0.0.0/::),
    ``allowed_hosts`` and the comma-separated ``$NIMBUS_ALLOWED_HOSTS``."""
    names = set(_LOOPBACK_NAMES)
    if bind_host is None:
        names.add(_IN_PROCESS_HOST)
    elif not _is_unspecified(_hostname(bind_host)):
        names.add(_hostname(bind_host))
    extra = list(allowed_hosts or []) + os.environ.get("NIMBUS_ALLOWED_HOSTS", "").split(",")
    names.update(_hostname(a) for a in extra if a.strip())
    names.discard("")
    return names


def _origin_allowed(origin: str, host_header: str) -> bool:
    """An Origin is ours when its host[:port] equals the request's Host header."""
    try:
        netloc = urlsplit(origin.strip()).netloc
    except ValueError:
        return False
    return bool(netloc) and netloc.lower() == (host_header or "").strip().lower()


def cross_site_rejected(method: str, headers: Any) -> bool:
    """State-changing requests are accepted only same-origin (Sec-Fetch-Site) or with our own Origin;
    clients that send neither header (curl, scripts) are not browsers and cannot be CSRF vectors."""
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return False
    origin = headers.get("origin") or ""
    origin_ok = bool(origin) and _origin_allowed(origin, headers.get("host") or "")
    site = (headers.get("sec-fetch-site") or "").lower()
    if site in ("same-origin", "none"):
        return False
    if site == "":
        return bool(origin) and not origin_ok
    return not origin_ok


def cytoscape(nodes: list[dict], edges: list[dict]) -> dict[str, list[dict]]:
    ids = {n.get("id") for n in nodes}
    els_n = [{"data": {"id": n["id"], "label": n.get("name") or n["id"], "class": n.get("class", ""), "type": n.get("type", ""),
                       "provider": n.get("provider", ""), "account": n.get("account", ""), "sensitive": bool(n.get("sensitive")),
                       "weaknesses": n.get("weaknesses") or [], "findings": len(n.get("finding_ids") or [])}}
             for n in nodes if n.get("id")]
    for e in edges:  # dangling endpoints still render
        for end in (e["from"], e["to"]):
            if end not in ids:
                ids.add(end)
                els_n.append({"data": {"id": end, "label": end, "class": "internet" if end == "internet" else "unknown"}})
    els_e = [{"data": {"id": f"{e['from']}->{e['to']}:{e['kind']}", "source": e["from"], "target": e["to"], "kind": e["kind"]}} for e in edges]
    return {"nodes": els_n, "edges": els_e}


def summary(store: Store) -> dict[str, Any]:
    fs = store.findings()
    failed = [f for f in fs if f.status.value == "FAIL"]
    scan = store.last_scan()
    paths = store.attack_paths()
    return {
        "total": len(fs), "failed": len(failed), "passed": sum(1 for f in fs if f.status.value == "PASS"),
        "by_severity": dict(Counter(f.severity.value for f in failed)), "by_provider": dict(Counter(f.provider for f in failed)),
        "by_account": dict(Counter(f"{f.provider}:{f.account}" for f in failed)), "attack_paths": len(paths),
        "critical_paths": sum(1 for p in paths if p.severity.value == "CRITICAL"),
        "resources": len({f.resource.id for f in fs if f.resource.id}),
        "last_scan": scan.to_doc() if scan else None, "db": store.path, "version": __version__,
    }


BUILTIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>cloud-posture</title><style>
body{margin:0;background:#fcfcfb;color:#0b0b0b;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0}.sub{color:#52514e}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:16px 0}
.tile{background:#fff;border:1px solid #e4e3de;border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:22px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;background:#fff}th,td{padding:6px 8px;border-bottom:1px solid #e4e3de;text-align:left;font-size:13px}
th{color:#52514e;font-size:12px;text-transform:uppercase}code{font-size:12px}
</style></head><body><main><h1>cloud-posture</h1><div class="sub">nimbus __VERSION__ · <span id="live">live</span></div>
<div class="grid">__TILES__</div><h2>Top risks</h2><div class="wrap"><table><thead><tr><th>Risk</th><th>Severity</th><th>Check</th><th>Resource</th><th>Why</th></tr></thead>
<tbody>__ROWS__</tbody></table></div>
<p class="sub">API: <code>/api/summary</code>, <code>/api/findings</code>, <code>/api/graph</code>, <code>/api/risk/top</code>, <code>/api/compliance/soc2</code>, <code>/docs</code></p>
<script>try{const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws');
ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='findings_updated')location.reload()};
ws.onclose=()=>{document.getElementById('live').textContent='offline'}}catch(e){}</script></main></body></html>"""


def builtin_page(store: Store) -> str:
    s = summary(store)
    tiles = "".join(f'<div class="tile">{html.escape(k)}<b>{v}</b></div>' for k, v in (
        ("Failed findings", s["failed"]), ("Critical", s["by_severity"].get("CRITICAL", 0)), ("High", s["by_severity"].get("HIGH", 0)),
        ("Attack paths", s["attack_paths"]), ("Resources", s["resources"])))
    rows = "".join(
        f"<tr><td>{r['risk_score']}</td><td>{html.escape(r['severity'])}</td><td><code>{html.escape(r['canonical_id'])}</code></td>"
        f"<td>{html.escape(str(r['resource']))}</td><td>{html.escape('; '.join(r['reasons'][:3]))}</td></tr>"
        for r in (x.to_dict() for x in prioritize_store(store, top=15))) or '<tr><td colspan="5">No open findings.</td></tr>'
    return BUILTIN_HTML.replace("__VERSION__", __version__).replace("__TILES__", tiles).replace("__ROWS__", rows)


def create_app(db_path: Optional[str] = None, *, bind_host: Optional[str] = None,
               allowed_hosts: Iterable[str] = ()) -> FastAPI:
    """Build the API. Every request must carry an allowed Host (else 421, DNS-rebinding defence) and
    state-changing requests must not be cross-site (else 403). ``bind_host`` is the listen host
    (``serve()`` always passes it); ``allowed_hosts`` / ``$NIMBUS_ALLOWED_HOSTS`` add names."""
    path = db_path or default_db_path()
    app = FastAPI(title="nimbus cloud-posture API", version=__version__)
    app.state.db_path = path
    hosts = allowed_host_names(bind_host, allowed_hosts)
    app.state.allowed_hosts = hosts

    @app.middleware("http")
    async def _guards(request: Request, call_next: Any) -> Response:
        host = request.headers.get("host") or ""
        if _hostname(host) not in hosts:
            return JSONResponse({"detail": f"host {host!r} is not served here (set NIMBUS_ALLOWED_HOSTS)"}, status_code=421)
        if cross_site_rejected(request.method, request.headers):
            return JSONResponse({"detail": "cross-site request rejected"}, status_code=403)
        return await call_next(request)

    def store() -> Store:
        return Store(path, create=not Path(path).exists())

    def copilot() -> SecurityCopilot:
        return SecurityCopilot(store())

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        custom = os.environ.get("CLOUD_POSTURE_DASHBOARD_HTML")
        if custom and Path(custom).is_file():
            return HTMLResponse(Path(custom).read_text(encoding="utf-8"))
        return HTMLResponse(builtin_page(store()))

    @app.get("/api/summary")
    def api_summary() -> dict[str, Any]:
        return summary(store())

    @app.get("/api/findings")
    def api_findings(status: Optional[str] = None, severity: Optional[str] = None, provider: Optional[str] = None,
                     account: Optional[str] = None, canonical_id: Optional[str] = None,
                     limit: int = Query(500, ge=1, le=10000)) -> list[dict[str, Any]]:
        return [f.to_doc() for f in store().findings(status=status, severity=severity, provider=provider, account=account,
                                                     canonical_id=canonical_id, limit=limit)]

    @app.get("/api/findings/{finding_id}")
    def api_finding(finding_id: str) -> dict[str, Any]:
        f = store().finding(finding_id)
        if f is None:
            raise HTTPException(404, f"finding {finding_id} not found")
        paths = [p.to_doc() for p in store().attack_paths() if f.id in p.finding_ids]
        return {**f.to_doc(), "attack_paths": paths}

    @app.get("/api/attack-paths")
    def api_paths() -> list[dict[str, Any]]:
        return [p.to_doc() for p in store().attack_paths()]

    @app.get("/api/graph")
    def api_graph() -> dict[str, list[dict]]:
        nodes, edges = store().graph()
        return cytoscape(nodes, edges)

    @app.get("/api/risk/top")
    def api_risk(n: int = Query(50, ge=1, le=1000)) -> list[dict[str, Any]]:
        return [r.to_dict() for r in prioritize_store(store(), top=n)]

    @app.get("/api/frameworks")
    def api_frameworks() -> list[dict[str, Any]]:
        return list_frameworks()

    @app.get("/api/compliance/{framework}")
    def api_compliance(framework: str) -> dict[str, Any]:
        return build_from_store(store(), framework).to_dict()

    @app.get("/api/reports/{name}")
    def api_report(name: str) -> Response:
        framework, _, ext = name.rpartition(".")
        if not framework or ext not in ("html", "pdf", "md", "json"):
            raise HTTPException(400, "use /api/reports/<framework>.<html|pdf|md|json>")
        rep = build_from_store(store(), framework)
        if ext == "html":
            return HTMLResponse(render_html(rep))
        if ext == "md":
            return PlainTextResponse(render_markdown(rep), media_type="text/markdown")
        if ext == "json":
            return Response(render_json(rep), media_type="application/json")
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / f"{framework}.pdf"
            try:
                render_pdf(rep, out)
            except RuntimeError as exc:
                raise HTTPException(501, str(exc)) from exc
            data = out.read_bytes()
        return Response(data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{framework}.pdf"'})

    @app.get("/api/queries")
    def api_queries() -> list[dict[str, Any]]:
        return [{"name": q["name"], "description": q["description"], "frameworks": q.get("frameworks", []), "sql": q["sql_text"]}
                for q in qlib.index()]

    @app.get("/api/queries/{name}")
    def api_named_query(name: str) -> dict[str, Any]:
        try:
            cols, rows = qlib.run_named(store(), name)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        return {"name": name, "columns": cols, "rows": rows}

    @app.post("/api/query")
    def api_query(body: SQLBody) -> dict[str, Any]:
        try:
            cols, rows = qlib.run_sql(store(), body.sql)
        except QueryTimeout as exc:
            raise HTTPException(408, str(exc)) from exc
        except UnsafeSQL as exc:
            raise HTTPException(400, f"rejected: {exc}") from exc
        except Exception as exc:  # sqlite errors
            raise HTTPException(400, f"query failed: {exc}") from exc
        return {"columns": cols, "rows": rows}

    @app.post("/api/copilot")
    def api_copilot(body: QuestionBody) -> dict[str, Any]:
        return copilot().ask(body.question)

    @app.post("/api/explain")
    def api_explain(body: FindingBody) -> dict[str, Any]:
        s = store()
        f = s.finding(body.finding_id)
        if f is None:
            raise HTTPException(404, f"finding {body.finding_id} not found")
        return explain_finding(f, [p for p in s.attack_paths() if f.id in p.finding_ids])

    @app.post("/api/investigate")
    def api_investigate(body: FindingBody) -> dict[str, Any]:
        try:
            return copilot().investigate(body.finding_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/fix")
    def api_fix(body: FixBody) -> dict[str, Any]:
        f = store().finding(body.finding_id)
        if f is None:
            raise HTTPException(404, f"finding {body.finding_id} not found")
        try:
            return generate_fix(f, body.format, current_code=body.current_code, framework=body.framework)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/alerts")
    def api_alerts(body: AlertBody, authorization: Optional[str] = Header(None)) -> dict[str, Any]:
        _require_token(authorization)
        targets = _alert_targets(body.targets)
        s = store()
        fs = [f for f in (s.finding(i) for i in body.finding_ids) if f is not None]
        try:
            results = dispatch(fs, targets, s.attack_paths())
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        for r in results:
            if r.ref and not r.error:
                try:
                    s.mark_alerted(r.finding_id, r.channel, r.ref)
                except Exception:  # read-only DB: alerts still delivered
                    pass
        return {"results": [r.to_dict() for r in results], "missing": sorted(set(body.finding_ids) - {f.id for f in fs})}

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        origin = socket.headers.get("origin") or ""
        if _hostname(socket.headers.get("host") or "") not in hosts or (origin and not _origin_allowed(origin, socket.headers.get("host") or "")):
            await socket.close(code=1008)
            return
        await socket.accept()
        interval = float(os.environ.get("NIMBUS_WS_POLL", "2"))
        s = Store(path, create=False)
        last = s.mtime()
        try:
            while True:
                await asyncio.sleep(interval)
                cur = s.mtime()
                if cur != last:
                    last = cur
                    scan = None
                    try:
                        ls = s.last_scan()
                        scan = ls.scan_id if ls else None
                    except Exception:
                        pass
                    await socket.send_json({"type": "findings_updated", "scan_id": scan})
        except (WebSocketDisconnect, RuntimeError):
            return

    @app.exception_handler(UnsafeSQL)
    async def _unsafe(_req, exc: UnsafeSQL) -> JSONResponse:
        return JSONResponse({"detail": f"rejected: {exc}"}, status_code=400)

    return app


def serve(host: str = "127.0.0.1", port: int = 8765, db: Optional[str] = None, allowed_hosts: Iterable[str] = ()) -> None:
    import uvicorn

    uvicorn.run(create_app(db, bind_host=host, allowed_hosts=allowed_hosts), host=host, port=port, log_level="info")
