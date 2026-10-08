import json

import httpx

from nimbus.integrations import Datadog, GitHubIssues, Jira, PagerDuty, Slack, Teams, dispatch, event, issue_body
from nimbus.models import AttackPath

from .conftest import sample_findings, sample_paths


class Recorder:
    def __init__(self, responses=None):
        self.requests: list[httpx.Request] = []
        self.responses = responses or {}

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        for key, resp in self.responses.items():
            if key in str(req.url):
                return resp() if callable(resp) else resp
        return httpx.Response(200, json={})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


def _rds():
    fs = sample_findings()
    f = next(x for x in fs if x.canonical_id == "RDS_PUBLIC")
    return f, [AttackPath.model_validate(p) for p in sample_paths(fs) if f.id in p["finding_ids"]]


def test_slack_payload_matches_go_shape():
    rec = Recorder()
    f, paths = _rds()
    r = Slack("https://hooks.slack.test/x", client=rec.client()).send(f, paths)
    assert r.ref == "sent" and not r.error
    body = json.loads(rec.requests[0].content)
    assert body["text"] == "[CRITICAL] RDS instance is publicly accessible on orders"
    assert ":rotating_light:" in body["blocks"][0]["text"]["text"]
    assert "Part of attack paths" in body["blocks"][1]["text"]["text"]
    assert "cloud-posture fix --finding RDS_PUBLIC --generate-terraform" in json.dumps(body)


def test_teams_jira_github_datadog_pagerduty():
    f, paths = _rds()
    rec = Recorder({
        "/rest/api/3/issue": httpx.Response(201, json={"key": "SEC-7"}),
        "/search/issues": httpx.Response(200, json={"items": []}),
        "/repos/acme/infra/issues": httpx.Response(201, json={"html_url": "https://github.com/acme/infra/issues/3"}),
        "events.pagerduty.com": httpx.Response(202, json={"dedup_key": "cloud-posture-x"}),
        "http-intake.logs": httpx.Response(202, json={}),
    })
    c = rec.client()
    assert Teams("https://teams.test/hook", client=c).send(f, paths).ref == "sent"
    assert Jira("https://acme.atlassian.net", "a@b.c", "tok", "SEC", client=c).send(f, paths).ref == "https://acme.atlassian.net/browse/SEC-7"
    assert GitHubIssues("acme/infra", "ghtok", client=c).send(f, paths).ref.endswith("/issues/3")
    assert Datadog("ddkey", client=c).send(f, paths).ref == "accepted"
    assert PagerDuty("rk", client=c).send(f, paths).ref == "cloud-posture-x"
    by_host = {r.url.host + r.url.path: r for r in rec.requests}
    jira = json.loads(by_host["acme.atlassian.net/rest/api/3/issue"].content)
    assert jira["fields"]["priority"]["name"] == "Highest" and jira["fields"]["project"]["key"] == "SEC"
    assert by_host["acme.atlassian.net/rest/api/3/issue"].headers["Authorization"].startswith("Basic ")
    gh = json.loads(by_host["api.github.com/repos/acme/infra/issues"].content)
    assert f"cloud-posture:{f.id}" in gh["body"] and gh["labels"] == ["security", "cloud-posture"]
    pd = json.loads(by_host["events.pagerduty.com/v2/enqueue"].content)
    assert pd["payload"]["severity"] == "critical" and pd["dedup_key"] == f"cloud-posture-{f.id}"
    dd = json.loads(by_host["http-intake.logs.datadoghq.com/api/v2/logs"].content)
    assert dd[0]["event_type"] == "cloud_posture.finding" and dd[0]["attack_paths"][0]["id"] == "ap-db"
    teams = json.loads(by_host["teams.test/hook"].content)
    assert teams["attachments"][0]["content"]["type"] == "AdaptiveCard"


def test_github_dedupes_existing_issue():
    f, _ = _rds()
    rec = Recorder({"/search/issues": httpx.Response(200, json={"items": [{"html_url": "https://github.com/acme/infra/issues/1"}]})})
    r = GitHubIssues("acme/infra", "t", client=rec.client()).send(f)
    assert r.ref.endswith("/issues/1") and len(rec.requests) == 1


def test_dispatch_errors_and_unconfigured(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    fs = sample_findings()[:2]
    rec = Recorder({"hooks.slack": httpx.Response(500, text="boom")})
    res = dispatch(fs, [{"type": "slack", "webhook_url": "https://hooks.slack.test/x"}, "pagerduty"], sample_paths(sample_findings()), http=rec.client())
    assert len(res) == 4
    slack = [r for r in res if r.channel == "slack"]
    assert all("500" in r.error for r in slack)
    pdr = [r for r in res if r.channel == "pagerduty"]
    assert all(r.skipped for r in pdr)


def test_event_and_issue_body():
    f, paths = _rds()
    ev = event(f, paths)
    assert ev["resource_id"] == f.resource.id and ev["first_seen"].endswith("Z")
    body = issue_body(f, paths)
    assert body.startswith("## RDS instance is publicly accessible") and "### Compliance" in body
