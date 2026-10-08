"""Ensure no customer managed IAM policies allow actions that may lead to privilege escalation (CIS AWS 3.0 1.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamPolicyAllowsPrivilegeEscalation(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for pol in lib.iam_policies(ctx, "Local", only_attached=False):
            found = lib.privilege_escalation_actions(lib.policy_default_document(ctx, pol))
            if found:
                out.append(CheckResult("FAIL", f"Customer-managed policy {pol['PolicyName']} allows privilege escalation using: {', '.join(found)}.",
                                       pol["PolicyName"], pol["Arn"], pol["PolicyName"], ctx.home_region, {"escalation_actions": found}))
            else:
                out.append(CheckResult("PASS", f"Customer-managed policy {pol['PolicyName']} does not allow privilege escalation.",
                                       pol["PolicyName"], pol["Arn"], pol["PolicyName"], ctx.home_region))
        return out
