"""Ensure MFA is enabled for all IAM users that have a console password (CIS AWS 3.0 1.10)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamUserMfaEnabledConsoleAccess(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for row in lib.user_rows(ctx):
            name, arn = row["user"], row["arn"]
            if not lib.is_true(row.get("password_enabled")):
                out.append(CheckResult("PASS", f"User {name} does not have console access.", name, arn, name, ctx.home_region, {"password_enabled": False}))
            elif lib.is_true(row.get("mfa_active")):
                out.append(CheckResult("PASS", f"User {name} has console access and MFA enabled.", name, arn, name, ctx.home_region, {"password_enabled": True, "mfa_active": True}))
            else:
                out.append(CheckResult("FAIL", f"User {name} has console access enabled but MFA is not enabled.", name, arn, name, ctx.home_region, {"password_enabled": True, "mfa_active": False}))
        return out
