"""Ensure MFA is enabled for the root account (CIS AWS 3.0 1.5)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamRootMfaEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        summary = lib.account_summary(ctx)
        enabled = int(summary.get("AccountMFAEnabled", 0)) == 1
        if enabled:
            return [lib.account_result(ctx, "PASS", "MFA is enabled for the root account.", details={"AccountMFAEnabled": 1})]
        return [lib.account_result(ctx, "FAIL", "MFA is not enabled for the root account.", details={"AccountMFAEnabled": 0})]
