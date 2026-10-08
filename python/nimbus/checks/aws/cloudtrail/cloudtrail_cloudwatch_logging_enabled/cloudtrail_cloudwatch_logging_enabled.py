"""Ensure CloudTrail trails are integrated with CloudWatch Logs (CIS AWS 3.0 3.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailCloudwatchLoggingEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)
        if not trails:
            return [lib.account_result(ctx, "FAIL", "No CloudTrail trails are configured in the account.")]
        out = []
        for t in trails:
            name, arn, region = t["Name"], t["TrailARN"], t["HomeRegion"]

            lg = t.get("CloudWatchLogsLogGroupArn")
            if not lg:
                out.append(CheckResult("FAIL", f"Trail {name} is not integrated with CloudWatch Logs.", name, arn, name, region))
                continue
            age = lib.days_since(t.get("Status", {}).get("LatestCloudWatchLogsDeliveryTime"))
            if age is not None and age >= 1:
                out.append(CheckResult("FAIL", f"Trail {name} is integrated with CloudWatch Logs but has not delivered in the last 24 hours.", name, arn, name, region, {"log_group": lg}))
            else:
                out.append(CheckResult("PASS", f"Trail {name} is integrated with CloudWatch Logs.", name, arn, name, region, {"log_group": lg}))
        return out
