"""Ensure a support role has been created to manage incidents with AWS Support (CIS AWS 3.0 1.17)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamSupportRoleCreated(Check):
    def execute(self, ctx) -> list[CheckResult]:
        arn = f"arn:{ctx.partition}:iam::aws:policy/AWSSupportAccess"
        try:
            roles = [r["RoleName"] for r in ctx.client("iam").list_entities_for_policy(PolicyArn=arn, EntityFilter="Role").get("PolicyRoles", [])]
        except lib.ClientError as exc:
            if lib.error_code(exc) != "NoSuchEntity":
                raise
            roles = []
        if roles:
            return [CheckResult("PASS", f"AWSSupportAccess policy is attached to role(s): {', '.join(roles)}.", "AWSSupportAccess", arn, "AWSSupportAccess", ctx.home_region, {"roles": roles}, roles)]
        return [CheckResult("FAIL", "No IAM role has the AWSSupportAccess policy attached.", "AWSSupportAccess", arn, "AWSSupportAccess", ctx.home_region)]
