"""Check if GuardDuty is enabled (CIS AWS 3.0 4.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class GuarddutyIsEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            gd = ctx.client("guardduty", region)
            ids = gd.list_detectors().get("DetectorIds", [])
            for did in ids:
                det = gd.get_detector(DetectorId=did)
                arn = f"arn:{ctx.partition}:guardduty:{region}:{ctx.account_id}:detector/{did}"
                if det.get("Status") == "ENABLED":
                    return [CheckResult("PASS", f"GuardDuty detector {did} is enabled in {region}.", did, arn, did, region)]
            if ids:
                did = ids[0]
                return [CheckResult("FAIL", f"GuardDuty detector {did} exists in {region} but is suspended.", did,
                                    f"arn:{ctx.partition}:guardduty:{region}:{ctx.account_id}:detector/{did}", did, region)]
            rid = f"detector/{ctx.account_id}"
            return [CheckResult("FAIL", f"GuardDuty is not enabled in {region}.", rid, f"arn:{ctx.partition}:guardduty:{region}:{ctx.account_id}:detector", rid, region)]

        return lib.regional_results(ctx, per_region)
