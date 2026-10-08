"""Ensure unused user console access for 45 days or more is disabled (CIS AWS 3.0 1.12)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamUserConsoleAccessUnused(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for row in lib.user_rows(ctx):
            name, arn = row["user"], row["arn"]
            if not lib.is_true(row.get("password_enabled")):
                out.append(CheckResult("PASS", f"User {name} does not have console access.", name, arn, name, ctx.home_region))
                continue
            age = lib.days_since(row.get("password_last_used"))
            if age is None:
                age = lib.days_since(row.get("password_last_changed")) or lib.days_since(row.get("user_creation_time"))
            if age is not None and age >= 45:
                out.append(CheckResult("FAIL", f"User {name} has not used console access for {age} days (45 days or more).", name, arn, name, ctx.home_region, {"unused_days": age}))
            else:
                out.append(CheckResult("PASS", f"User {name} has used console access within the last 45 days.", name, arn, name, ctx.home_region, {"unused_days": age}))
        return out
