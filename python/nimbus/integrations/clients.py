from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional

import httpx

from ..models import AttackPath, Finding, go_time

SLACK_EMOJI = {"CRITICAL": ":rotating_light:", "HIGH": ":red_circle:", "MEDIUM": ":large_orange_circle:",
               "LOW": ":large_yellow_circle:", "INFO": ":white_circle:"}


@dataclass
class Result:
    channel: str
    finding_id: str
    ref: str = ""
    error: str = ""
    skipped: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in ("", False) or k in ("channel", "finding_id")}


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def fix_command(f: Finding) -> str:
    return f"cloud-posture fix --finding {f.canonical_id} --generate-terraform"


def event(f: Finding, paths: Iterable[AttackPath] = ()) -> dict[str, Any]:
    """Flat SIEM event (same field names as integrations.Event in Go)."""
    ev: dict[str, Any] = {
        "event_type": "cloud_posture.finding", "finding_id": f.id, "canonical_id": f.canonical_id, "source": f.source,
        "check_id": f.check_id, "title": f.title, "severity": f.severity.value, "status": f.status.value,
        "provider": f.provider, "account": f.account, "region": f.region, "resource_id": f.resource.id,
        "resource_type": f.resource.type, "resource_name": f.resource.name, "weaknesses": f.weaknesses,
        "compliance": f.compliance, "first_seen": go_time(f.first_seen), "last_seen": go_time(f.last_seen),
        "remediation": f.remediation,
    }
    if f.file:
        ev["file"], ev["line"] = f.file, f.line_start
    paths = list(paths)
    if paths:
        ev["attack_paths"] = [{"id": p.id, "name": p.name, "impact": p.impact, "score": p.score, "mitre": p.mitre} for p in paths]
    return ev


def issue_body(f: Finding, paths: Iterable[AttackPath] = ()) -> str:
    """Markdown body (same layout as integrations.IssueBody in Go)."""
    b = [f"## {f.title}", "", "| | |", "|---|---|", f"| Severity | **{f.severity.value}** |", f"| Canonical ID | `{f.canonical_id}` |",
         f"| Source | {f.source} (`{f.check_id}`) |", f"| Provider / Account | {f.provider} / {f.account} |",
         f"| Region | {f.region} |", f"| Resource | `{f.resource.id}` |"]
    if f.file:
        b.append(f"| File | `{f.file}:{f.line_start}` |")
    if f.description:
        b += ["", "### Risk", f.description]
    if f.remediation:
        b += ["", "### Remediation", f.remediation]
    b += ["", "```bash", fix_command(f), "```"]
    paths = list(paths)
    if paths:
        b += ["", "### Attack paths this finding enables"]
        b += [f"- **{p.name}** → {p.impact} (score {p.score:.1f}, MITRE {', '.join(p.mitre)})" for p in paths]
    if f.compliance:
        b += ["", "### Compliance"] + [f"- {fw}: {', '.join(c)}" for fw, c in f.compliance.items()]
    b.append(f"\n<!-- cloud-posture:{f.id} -->")
    return "\n".join(b) + "\n"


class _Base:
    name = "base"

    def __init__(self, client: Optional[httpx.Client] = None, timeout: float = 15.0):
        self._client = client
        self._timeout = timeout

    @property
    def http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def configured(self) -> bool:
        return True

    def send(self, f: Finding, paths: Iterable[AttackPath] = ()) -> Result:
        if not self.configured():
            return Result(self.name, f.id, error=f"{self.name} not configured", skipped=True)
        try:
            ref = self._send(f, list(paths))
            return Result(self.name, f.id, ref=ref)
        except httpx.HTTPError as exc:
            return Result(self.name, f.id, error=str(exc))
        except RuntimeError as exc:
            return Result(self.name, f.id, error=str(exc))

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def _check(resp: httpx.Response, what: str) -> httpx.Response:
        if resp.status_code >= 300:
            raise RuntimeError(f"{what} responded {resp.status_code}: {resp.text.strip()[:300]}")
        return resp


class Slack(_Base):
    name = "slack"

    def __init__(self, webhook_url: Optional[str] = None, channel: str = "", **kw):
        super().__init__(**kw)
        self.webhook_url = webhook_url if webhook_url is not None else os.environ.get("SLACK_WEBHOOK_URL", "")
        self.channel = channel

    def configured(self) -> bool:
        return bool(self.webhook_url)

    def payload(self, f: Finding, paths: list[AttackPath]) -> dict[str, Any]:
        text = (f"{SLACK_EMOJI.get(f.severity.value, '')} *{f.severity.value}* `{f.canonical_id}`\n*{f.title}* in `{f.provider}` / "
                f"{f.account} {f.region}\nResource: `{f.resource.id}`")
        blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
        if paths:
            names = "\n".join(f"• {p.name} → _{p.impact}_ (score {p.score:.1f})" for p in paths)
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ":crossed_swords: *Part of attack paths*\n" + names}})
        if f.remediation:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": ":wrench: " + _truncate(f.remediation, 400)}]})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"source: {f.source} · check: {f.check_id} · fix: `{fix_command(f)}`"}]})
        p: dict[str, Any] = {"text": f"[{f.severity.value}] {f.title} on {f.resource.name}", "blocks": blocks}
        if self.channel:
            p["channel"] = self.channel
        return p

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        self._check(self.http.post(self.webhook_url, json=self.payload(f, paths)), "slack")
        return "sent"


class Teams(_Base):
    name = "teams"

    def __init__(self, webhook_url: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.webhook_url = webhook_url if webhook_url is not None else os.environ.get("TEAMS_WEBHOOK_URL", "")

    def configured(self) -> bool:
        return bool(self.webhook_url)

    def payload(self, f: Finding, paths: list[AttackPath]) -> dict[str, Any]:
        facts = [{"title": k, "value": v} for k, v in (("Severity", f.severity.value), ("Canonical ID", f.canonical_id),
                                                      ("Account", f"{f.provider} / {f.account}"), ("Resource", f.resource.id))]
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": f"[{f.severity.value}] {f.title}", "wrap": True},
            {"type": "FactSet", "facts": facts},
        ]
        if paths:
            body.append({"type": "TextBlock", "wrap": True, "text": "Attack paths: " + "; ".join(f"{p.name} → {p.impact}" for p in paths)})
        if f.remediation:
            body.append({"type": "TextBlock", "wrap": True, "text": "Fix: " + _truncate(f.remediation, 400)})
        body.append({"type": "TextBlock", "wrap": True, "fontType": "Monospace", "text": fix_command(f)})
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}}]}

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        self._check(self.http.post(self.webhook_url, json=self.payload(f, paths)), "teams")
        return "sent"


class Jira(_Base):
    name = "jira"
    PRIORITY = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Lowest"}

    def __init__(self, base_url: Optional[str] = None, email: Optional[str] = None, token: Optional[str] = None,
                 project: Optional[str] = None, issue_type: str = "Bug", **kw):
        super().__init__(**kw)
        self.base_url = (base_url or os.environ.get("JIRA_URL", "")).rstrip("/")
        self.email = email or os.environ.get("JIRA_EMAIL", "")
        self.token = token or os.environ.get("JIRA_API_TOKEN", "")
        self.project = project or os.environ.get("JIRA_PROJECT", "")
        self.issue_type = issue_type

    def configured(self) -> bool:
        return all((self.base_url, self.email, self.token, self.project))

    def payload(self, f: Finding, paths: list[AttackPath]) -> dict[str, Any]:
        text = issue_body(f, paths)
        doc = {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in text.splitlines() if line.strip()]}
        return {"fields": {
            "project": {"key": self.project}, "issuetype": {"name": self.issue_type},
            "summary": _truncate(f"[{f.severity.value}] {f.title} - {f.resource.name}", 250),
            "description": doc, "priority": {"name": self.PRIORITY.get(f.severity.value, "Medium")},
            "labels": ["cloud-posture", f.provider, f.canonical_id.lower().replace(":", "_")],
        }}

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        r = self._check(self.http.post(f"{self.base_url}/rest/api/3/issue", json=self.payload(f, paths), auth=(self.email, self.token)), "jira")
        key = r.json().get("key", "")
        return f"{self.base_url}/browse/{key}" if key else "created"


class GitHubIssues(_Base):
    name = "github"

    def __init__(self, repo: Optional[str] = None, token: Optional[str] = None, labels: Optional[list[str]] = None,
                 api_url: str = "https://api.github.com", **kw):
        super().__init__(**kw)
        self.repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.labels = labels or ["security", "cloud-posture"]
        self.api_url = api_url.rstrip("/")

    def configured(self) -> bool:
        return bool(self.repo and self.token)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        marker = f"cloud-posture:{f.id}"
        s = self.http.get(f"{self.api_url}/search/issues", params={"q": f'repo:{self.repo} is:issue is:open "{marker}" in:body'},
                          headers=self._headers())
        if s.status_code < 300:
            items = s.json().get("items") or []
            if items:
                return items[0].get("html_url", "existing")
        r = self._check(self.http.post(f"{self.api_url}/repos/{self.repo}/issues", headers=self._headers(), json={
            "title": _truncate(f"[{f.severity.value}] {f.title} ({f.resource.name})", 250), "body": issue_body(f, paths), "labels": self.labels}), "github")
        return r.json().get("html_url", "created")


class Datadog(_Base):
    name = "datadog"

    def __init__(self, api_key: Optional[str] = None, site: Optional[str] = None, service: str = "cloud-posture", **kw):
        super().__init__(**kw)
        self.api_key = api_key or os.environ.get("DD_API_KEY", "")
        self.site = site or os.environ.get("DD_SITE", "datadoghq.com")
        self.service = service

    def configured(self) -> bool:
        return bool(self.api_key)

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        ev = event(f, paths)
        body = [{"ddsource": "cloud-posture", "service": self.service, "hostname": f.account or "cloud-posture",
                 "ddtags": f"provider:{f.provider},severity:{f.severity.value.lower()},canonical_id:{f.canonical_id}",
                 "message": f"[{f.severity.value}] {f.title} on {f.resource.id}", **ev}]
        self._check(self.http.post(f"https://http-intake.logs.{self.site}/api/v2/logs", json=body,
                                   headers={"DD-API-KEY": self.api_key}), "datadog")
        return "accepted"


class PagerDuty(_Base):
    name = "pagerduty"
    SEV = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info", "INFO": "info"}

    def __init__(self, routing_key: Optional[str] = None, **kw):
        super().__init__(**kw)
        self.routing_key = routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY", "")

    def configured(self) -> bool:
        return bool(self.routing_key)

    def payload(self, f: Finding, paths: list[AttackPath]) -> dict[str, Any]:
        return {"routing_key": self.routing_key, "event_action": "trigger", "dedup_key": f"cloud-posture-{f.id}",
                "payload": {"summary": _truncate(f"[{f.severity.value}] {f.title} on {f.resource.name}", 1024),
                            "source": f"{f.provider}:{f.account}", "severity": self.SEV.get(f.severity.value, "info"),
                            "component": f.resource.type or f.resource.id, "group": f.canonical_id, "class": ",".join(f.weaknesses),
                            "custom_details": event(f, paths)}}

    def _send(self, f: Finding, paths: list[AttackPath]) -> str:
        r = self._check(self.http.post("https://events.pagerduty.com/v2/enqueue", json=self.payload(f, paths)), "pagerduty")
        return r.json().get("dedup_key", "enqueued")


CLIENTS = {"slack": Slack, "teams": Teams, "jira": Jira, "github": GitHubIssues, "datadog": Datadog, "pagerduty": PagerDuty}


def client_from_env(target: str | dict, http: Optional[httpx.Client] = None) -> _Base:
    """Build a client from a name (config from env vars) or a dict ``{"type": "slack", "webhook_url": ...}``."""
    if isinstance(target, dict):
        cfg = dict(target)
        kind = cfg.pop("type")
    else:
        kind, cfg = target, {}
    cls = CLIENTS.get(kind.lower())
    if cls is None:
        raise ValueError(f"unknown alert target {kind!r} (choose from {', '.join(CLIENTS)})")
    return cls(client=http, **cfg)


def dispatch(findings: Iterable[Finding | dict], targets: Iterable[str | dict], paths: Iterable[AttackPath | dict] = (),
             http: Optional[httpx.Client] = None) -> list[Result]:
    """Send every finding to every target; attack paths that include a finding are attached to it."""
    fs = [f if isinstance(f, Finding) else Finding.model_validate(f) for f in findings]
    ps = [p if isinstance(p, AttackPath) else AttackPath.model_validate(p) for p in paths]
    clients = [client_from_env(t, http) for t in targets]
    out: list[Result] = []
    for f in fs:
        mine = [p for p in ps if f.id in p.finding_ids]
        for c in clients:
            out.append(c.send(f, mine))
    return out
