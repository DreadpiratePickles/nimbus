"""Avoid the use of the root account (CIS AWS 3.0 1.7)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamAvoidRootUsage(Check):
    def execute(self, ctx) -> list[CheckResult]:
        row = lib.root_row(ctx)
        if row is None:
            return [lib.account_result(ctx, "MANUAL", "Root account row not present in the credential report; verify root usage manually.")]
        recent = {}
        for field in ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date"):
            days = lib.days_since(row.get(field))
            if days is not None and days < 1:
                recent[field] = row.get(field)
        if recent:
            return [lib.account_result(ctx, "FAIL", f"Root account was used within the last day ({', '.join(recent)}).", details=recent)]
        return [lib.account_result(ctx, "PASS", "Root account has not been used in the last day.",
                                   details={"password_last_used": row.get("password_last_used")})]
