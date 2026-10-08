"""Ensure IAM password policy requires minimum length of 14 or greater (CIS AWS 3.0 1.8)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamPasswordPolicyMinimumLength14(Check):
    def execute(self, ctx) -> list[CheckResult]:
        policy = lib.password_policy(ctx)
        if policy is None:
            return [lib.account_result(ctx, "FAIL", "Account has no IAM password policy.", resource_id="password-policy")]
        length = int(policy.get("MinimumPasswordLength", 0))
        status = "PASS" if length >= 14 else "FAIL"
        verb = "requires" if status == "PASS" else "does not require"
        return [lib.account_result(ctx, status, f"IAM password policy {verb} a minimum length of 14 characters (current: {length}).",
                                   details={"MinimumPasswordLength": length}, resource_id="password-policy")]
