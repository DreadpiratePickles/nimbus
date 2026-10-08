"""Ensure AWS Config is enabled in all regions (CIS AWS 3.0 3.3)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class ConfigRecorderAllRegionsEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            cfg = ctx.client("config", region)
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            statuses = {s["name"]: s for s in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])}
            for r in recorders:
                st = statuses.get(r["name"], {})
                arn = f"arn:{ctx.partition}:config:{region}:{ctx.account_id}:recorder/{r['name']}"
                if st.get("recording") and str(st.get("lastStatus", "")).upper() != "FAILURE":
                    return [CheckResult("PASS", f"AWS Config recorder {r['name']} is enabled and recording in {region}.", r["name"], arn, r["name"], region,
                                        {"all_supported": r.get("recordingGroup", {}).get("allSupported")})]
                return [CheckResult("FAIL", f"AWS Config recorder {r['name']} in {region} is not recording or its last status is failure.", r["name"], arn, r["name"], region,
                                    {"recording": st.get("recording"), "last_status": st.get("lastStatus")})]
            rid = f"config-recorder/{ctx.account_id}"
            arn = f"arn:{ctx.partition}:config:{region}:{ctx.account_id}:recorder"
            return [CheckResult("FAIL", f"No AWS Config recorder exists in {region}.", rid, arn, rid, region)]

        return lib.regional_results(ctx, per_region)
