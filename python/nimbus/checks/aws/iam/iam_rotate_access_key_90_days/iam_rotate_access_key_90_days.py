"""Ensure access keys are rotated every 90 days or less (CIS AWS 3.0 1.14)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamRotateAccessKey90Days(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for row in lib.user_rows(ctx):
            name, arn = row["user"], row["arn"]
            old, active = {}, 0
            for n in ("1", "2"):
                if lib.is_true(row.get(f"access_key_{n}_active")):
                    active += 1
                    age = lib.days_since(row.get(f"access_key_{n}_last_rotated"))
                    if age is not None and age > 90:
                        old[f"access_key_{n}"] = age
            if not active:
                out.append(CheckResult("PASS", f"User {name} does not have active access keys.", name, arn, name, ctx.home_region))
            elif old:
                out.append(CheckResult("FAIL", f"User {name} has access key(s) not rotated in over 90 days: " + ", ".join(f"{k} ({v} days)" for k, v in old.items()) + ".",
                                       name, arn, name, ctx.home_region, {"key_age_days": old}))
            else:
                out.append(CheckResult("PASS", f"User {name} access keys were rotated within 90 days.", name, arn, name, ctx.home_region))
        return out
