"""Ensure IAM customer-managed policies that allow full '*:*' administrative privileges are not attached (CIS AWS 3.0 1.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamCustomerAttachedPolicyNoAdministrativePrivileges(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for pol in lib.iam_policies(ctx, "Local", only_attached=True):
            doc = lib.policy_default_document(ctx, pol)
            if lib.is_admin_policy(doc):
                ents = lib.attached_policy_entities(ctx, pol["Arn"])
                out.append(CheckResult("FAIL", f"Customer-managed policy {pol['PolicyName']} grants full *:* administrative privileges and is attached.",
                                       pol["PolicyName"], pol["Arn"], pol["PolicyName"], ctx.home_region, {"attached_to": ents}, ents))
            else:
                out.append(CheckResult("PASS", f"Customer-managed policy {pol['PolicyName']} does not grant full *:* administrative privileges.",
                                       pol["PolicyName"], pol["Arn"], pol["PolicyName"], ctx.home_region))
        return out
