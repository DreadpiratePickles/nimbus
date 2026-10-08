"""Thin alert clients (Slack, Teams, Jira Cloud, GitHub Issues, Datadog Logs, PagerDuty) and ``dispatch``.

Payload shapes follow internal/integrations/integrations.go so Go- and Python-sent alerts look alike.
Every client accepts an optional ``httpx.Client`` (tests inject ``httpx.MockTransport``).
"""
from .clients import (  # noqa: F401
    CLIENTS, Datadog, GitHubIssues, Jira, PagerDuty, Result, Slack, Teams, client_from_env, dispatch, event, issue_body,
)
