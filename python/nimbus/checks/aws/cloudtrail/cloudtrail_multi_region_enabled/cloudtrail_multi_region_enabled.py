"""Ensure CloudTrail is enabled in all regions (CIS AWS 3.0 3.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailMultiRegionEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)

        def per_region(region):
            covering = [t for t in trails if lib.trail_is_logging(t) and (t.get("IsMultiRegionTrail") or t.get("HomeRegion") == region)]
            if covering:
                t = sorted(covering, key=lambda x: (not x.get("IsMultiRegionTrail"), x["Name"]))[0]
                kind = "multi-region" if t.get("IsMultiRegionTrail") else "single-region"
                return [CheckResult("PASS", f"Trail {t['Name']} is logging and is {kind}, covering {region}.", t["Name"], t["TrailARN"], t["Name"], region,
                                    {"is_multi_region": bool(t.get("IsMultiRegionTrail")), "home_region": t.get("HomeRegion")})]
            rid = f"trail/{ctx.account_id}"
            arn = f"arn:{ctx.partition}:cloudtrail:{region}:{ctx.account_id}:trail"
            return [CheckResult("FAIL", f"No CloudTrail trail is logging in {region}.", rid, arn, rid, region,
                                {"trails": [t["Name"] for t in trails]})]

        return lib.regional_results(ctx, per_region)
