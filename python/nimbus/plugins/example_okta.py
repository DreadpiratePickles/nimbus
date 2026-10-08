"""Example nimbus plugin: Okta administrators without MFA factors.

Environment:
  OKTA_ORG_URL    e.g. https://acme.okta.com
  OKTA_API_TOKEN  read-only API token (sent as ``Authorization: SSWS <token>``)

Run::

    python -m nimbus.plugin nimbus/plugins/example_okta.py --jsonl > okta.jsonl
    cloud-posture ingest --source native okta.jsonl
"""
from __future__ import annotations

import os
from typing import Iterator, Optional
from urllib.parse import urlparse

import httpx

import nimbus.plugin
from nimbus.plugin import SkipCheck

ADMIN_ROLE_TYPES = {"SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN", "HELP_DESK_ADMIN", "READ_ONLY_ADMIN",
                    "MOBILE_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "REPORT_ADMIN", "GROUP_MEMBERSHIP_ADMIN", "CUSTOM"}


def _client() -> httpx.Client:
    org = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    token = os.environ.get("OKTA_API_TOKEN", "")
    if not org or not token:
        raise SkipCheck("OKTA_ORG_URL and OKTA_API_TOKEN must be set")
    return httpx.Client(base_url=org, headers={"Authorization": f"SSWS {token}", "Accept": "application/json"}, timeout=30)


def _paginate(client: httpx.Client, url: str, params: Optional[dict] = None) -> Iterator[dict]:
    resp = client.get(url, params=params)
    while True:
        resp.raise_for_status()
        yield from resp.json()
        nxt = resp.links.get("next", {}).get("url")
        if not nxt:
            return
        resp = client.get(nxt)


@nimbus.plugin.check(
    "okta_admin_user_mfa_enrolled",
    "Okta administrator without MFA enrolled",
    severity="CRITICAL",
    provider="okta",
    weaknesses=["NO_MFA", "OVERPRIVILEGED_IDENTITY"],
    compliance={"nist_800_53": ["IA-2(1)", "AC-6"], "pci_dss": ["8.3.1"], "soc2": ["CC6.1"], "iso_27001": ["A.8.5"]},
    resource_type="okta_user",
    canonical_id="OKTA_ADMIN_NO_MFA",
    source="okta-plugin",
    remediation="Enroll every administrator in a phishing-resistant factor (Okta Verify FastPass / WebAuthn) and require MFA in the admin console sign-on policy.",
)
def okta_admin_user_mfa_enrolled(client: Optional[httpx.Client] = None) -> Iterator[dict]:
    """Every user holding an Okta admin role must have at least one ACTIVE MFA factor."""
    own = client is None
    client = client or _client()
    account = urlparse(str(client.base_url)).hostname or "okta"
    try:
        for user in _paginate(client, "/api/v1/users", {"filter": 'status eq "ACTIVE"', "limit": 200}):
            uid = user["id"]
            roles = client.get(f"/api/v1/users/{uid}/roles")
            roles.raise_for_status()
            admin_roles = sorted({r.get("type", "") for r in roles.json() if r.get("type") in ADMIN_ROLE_TYPES})
            if not admin_roles:
                continue
            factors = client.get(f"/api/v1/users/{uid}/factors")
            factors.raise_for_status()
            active = [f.get("factorType") for f in factors.json() if f.get("status") == "ACTIVE"]
            login = (user.get("profile") or {}).get("login", uid)
            yield {
                "resource_id": uid,
                "resource_name": login,
                "resource_attributes": {"roles": admin_roles, "factors": active},
                "account": account,
                "passed": bool(active),
                "message": (f"Administrator {login} ({', '.join(admin_roles)}) has active factors: {', '.join(active)}"
                            if active else f"Administrator {login} ({', '.join(admin_roles)}) has no active MFA factor"),
                "raw": {"user": {"id": uid, "status": user.get("status"), "login": login}, "roles": admin_roles, "factors": active},
            }
    finally:
        if own:
            client.close()
