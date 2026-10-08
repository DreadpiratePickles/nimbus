"""Ensure access keys unused for 45 days or more are disabled (CIS AWS 3.0 1.12)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamUserAccesskeyUnused(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for row in lib.user_rows(ctx):
            name, arn = row["user"], row["arn"]
            stale, active = {}, 0
            for n in ("1", "2"):
                if not lib.is_true(row.get(f"access_key_{n}_active")):
                    continue
                active += 1
                last = row.get(f"access_key_{n}_last_used_date")
                age = lib.days_since(last)
                if age is None:  # never used: measure from creation/rotation
                    age = lib.days_since(row.get(f"access_key_{n}_last_rotated"))
                if age is not None and age >= 45:
                    stale[f"access_key_{n}"] = age
            if not active:
                out.append(CheckResult("PASS", f"User {name} does not have active access keys.", name, arn, name, ctx.home_region))
            elif stale:
                out.append(CheckResult("FAIL", f"User {name} has active access key(s) unused for 45 days or more: " + ", ".join(f"{k} ({v} days)" for k, v in stale.items()) + ".",
                                       name, arn, name, ctx.home_region, {"unused_days": stale}))
            else:
                out.append(CheckResult("PASS", f"User {name} has no access keys unused for 45 days or more.", name, arn, name, ctx.home_region))
        return out
