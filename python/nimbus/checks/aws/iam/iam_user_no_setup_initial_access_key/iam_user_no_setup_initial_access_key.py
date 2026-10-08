"""Do not setup access keys during initial user setup for all IAM users that have a console password (CIS AWS 3.0 1.11)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamUserNoSetupInitialAccessKey(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for row in lib.user_rows(ctx):
            name, arn = row["user"], row["arn"]
            unused = [f"access_key_{n}" for n in ("1", "2")
                      if lib.is_true(row.get("password_enabled")) and lib.is_true(row.get(f"access_key_{n}_active"))
                      and lib.parse_date(row.get(f"access_key_{n}_last_used_date")) is None]
            if unused:
                out.append(CheckResult("FAIL", f"User {name} has console access and never-used active access key(s): {', '.join(unused)}.", name, arn, name, ctx.home_region, {"unused_keys": unused}))
            else:
                out.append(CheckResult("PASS", f"User {name} does not have never-used access keys created at setup.", name, arn, name, ctx.home_region))
        return out
