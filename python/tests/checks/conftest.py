"""Fixtures for native check tests: moto-backed AuditContext plus helpers."""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from nimbus.checks.context import AuditContext  # noqa: E402
from nimbus.checks.registry import get_check  # noqa: E402

REGION = "us-east-1"
ACCOUNT = "123456789012"

CRED_HEADER = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,"
               "mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,"
               "access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
               "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated").split(",")


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {
        "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION, "MOTO_IAM_LOAD_MANAGED_POLICIES": "false",
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def managed_policies(monkeypatch):
    """Load AWS managed policies into moto (slow; read when the IAM backend is first created)."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")


@pytest.fixture
def ctx():
    with mock_aws():
        yield AuditContext(session=boto3.Session(region_name=REGION), regions=[REGION], max_workers=2)


def run(check_id: str, ctx):
    return get_check(check_id).execute(ctx)


def by_id(results, resource_id: str):
    matches = [r for r in results if r.resource_id == resource_id or r.resource_arn == resource_id or r.resource_name == resource_id]
    assert matches, f"no result for {resource_id}: {[(r.resource_id, r.status) for r in results]}"
    return matches[0]


def status_of(results, resource_id: str) -> str:
    return by_id(results, resource_id).status


def iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def cred_row(user: str, **fields) -> dict:
    arn = f"arn:aws:iam::{ACCOUNT}:root" if user == "<root_account>" else f"arn:aws:iam::{ACCOUNT}:user/{user}"
    row = {k: "N/A" for k in CRED_HEADER}
    row.update({"user": user, "arn": arn, "user_creation_time": iso(400), "password_enabled": "false", "mfa_active": "false",
                "access_key_1_active": "false", "access_key_2_active": "false", "cert_1_active": "false", "cert_2_active": "false"})
    row.update({k: str(v).lower() if isinstance(v, bool) else v for k, v in fields.items()})
    return row


def set_credential_report(monkeypatch, ctx, rows):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CRED_HEADER)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    content = buf.getvalue().encode()
    iam = ctx.client("iam")
    monkeypatch.setattr(iam, "generate_credential_report", lambda: {"State": "COMPLETE"})
    monkeypatch.setattr(iam, "get_credential_report", lambda: {"Content": content, "ReportFormat": "text/csv"})


def policy_json(statements) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": statements})
