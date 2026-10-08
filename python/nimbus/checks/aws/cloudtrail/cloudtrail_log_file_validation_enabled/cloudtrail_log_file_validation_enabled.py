"""Ensure CloudTrail log file validation is enabled (CIS AWS 3.0 3.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailLogFileValidationEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)
        if not trails:
            return [lib.account_result(ctx, "FAIL", "No CloudTrail trails are configured in the account.")]
        out = []
        for t in trails:
            name, arn, region = t["Name"], t["TrailARN"], t["HomeRegion"]

            if t.get("LogFileValidationEnabled"):
                out.append(CheckResult("PASS", f"Trail {name} has log file validation enabled.", name, arn, name, region))
            else:
                out.append(CheckResult("FAIL", f"Trail {name} does not have log file validation enabled.", name, arn, name, region))
        return out
