"""Ensure that Object-level logging for read events is enabled for S3 buckets (CIS AWS 3.0 3.9)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailS3DataeventsReadEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)

        def logs_s3_reads(t):
            for s in t.get("EventSelectors") or []:
                if s.get("ReadWriteType", "All") not in ("All", "ReadOnly"):
                    continue
                for dr in s.get("DataResources", []):
                    if dr.get("Type") == "AWS::S3::Object" and any(v.rstrip("/") in ("arn:aws:s3", "arn:aws:s3:::", "arn:aws:s3::") or v in ("arn:aws:s3:::*",) for v in dr.get("Values", [])):
                        return True
            for a in t.get("AdvancedEventSelectors") or []:
                fields = {f.get("Field"): f for f in a.get("FieldSelectors", [])}
                if "Data" in fields.get("eventCategory", {}).get("Equals", []) and "AWS::S3::Object" in fields.get("resources.type", {}).get("Equals", []):
                    if "false" not in fields.get("readOnly", {}).get("Equals", []) and "resources.ARN" not in fields:
                        return True
            return False

        good = [t for t in trails if logs_s3_reads(t)]
        if good:
            t = good[0]
            return [CheckResult("PASS", f"Trail {t['Name']} records S3 object-level read events for all buckets.", t["Name"], t["TrailARN"], t["Name"], t["HomeRegion"])]
        return [lib.account_result(ctx, "FAIL", "No CloudTrail trail records S3 object-level read events for all buckets.", details={"trails": [t["Name"] for t in trails]})]
