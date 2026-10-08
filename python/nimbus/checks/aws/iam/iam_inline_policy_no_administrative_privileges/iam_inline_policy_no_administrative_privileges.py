"""Ensure IAM inline policies that allow full '*:*' administrative privileges are not associated to IAM identities (CIS AWS 3.0 1.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamInlinePolicyNoAdministrativePrivileges(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for p in lib.inline_policies(ctx):
            rid = f"{p['entity_arn']}/inline/{p['policy_name']}"
            label = f"Inline policy {p['policy_name']} on {p['entity_type']} {p['entity_name']}"
            if lib.is_admin_policy(p["document"]):
                out.append(CheckResult("FAIL", f"{label} grants full *:* administrative privileges.", rid, rid, p["policy_name"], ctx.home_region,
                                       {"entity_type": p["entity_type"], "entity_name": p["entity_name"]}, [p["entity_arn"]]))
            else:
                out.append(CheckResult("PASS", f"{label} does not grant full *:* administrative privileges.", rid, rid, p["policy_name"], ctx.home_region,
                                       {"entity_type": p["entity_type"], "entity_name": p["entity_name"]}, [p["entity_arn"]]))
        return out
