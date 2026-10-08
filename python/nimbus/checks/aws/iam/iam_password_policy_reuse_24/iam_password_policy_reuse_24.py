"""Ensure IAM password policy prevents password reuse (CIS AWS 3.0 1.9)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamPasswordPolicyReuse24(Check):
    def execute(self, ctx) -> list[CheckResult]:
        policy = lib.password_policy(ctx)
        if policy is None:
            return [lib.account_result(ctx, "FAIL", "Account has no IAM password policy.", resource_id="password-policy")]
        reuse = int(policy.get("PasswordReusePrevention", 0))
        status = "PASS" if reuse >= 24 else "FAIL"
        verb = "prevents" if status == "PASS" else "does not prevent"
        return [lib.account_result(ctx, status, f"IAM password policy {verb} reuse of the last 24 passwords (current: {reuse}).",
                                   details={"PasswordReusePrevention": reuse}, resource_id="password-policy")]
