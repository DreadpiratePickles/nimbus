"""Check if IAM Access Analyzer is enabled (CIS AWS 3.0 1.20)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class AccessanalyzerEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            analyzers = ctx.client("accessanalyzer", region).list_analyzers().get("analyzers", [])
            active = [a for a in analyzers if a.get("status") == "ACTIVE"]
            if active:
                a = active[0]
                return [CheckResult("PASS", f"IAM Access Analyzer {a['name']} is enabled in {region}.", a["name"], a["arn"], a["name"], region, {"type": a.get("type")})]
            rid = f"analyzer/{ctx.account_id}"
            arn = f"arn:{ctx.partition}:access-analyzer:{region}:{ctx.account_id}:analyzer/unknown"
            return [CheckResult("FAIL", f"IAM Access Analyzer is not enabled in {region}.", rid, arn, rid, region,
                                {"analyzers": [a.get("name") for a in analyzers]})]

        return lib.regional_results(ctx, per_region)
