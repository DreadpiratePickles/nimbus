"""Ensure the S3 bucket CloudTrail logs to is not publicly accessible (CIS AWS 3.0 2.1.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailLogsS3BucketIsNotPubliclyAccessible(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)
        if not trails:
            return [lib.account_result(ctx, "FAIL", "No CloudTrail trails are configured in the account.")]
        out = []
        for t in trails:
            name, arn, region = t["Name"], t["TrailARN"], t["HomeRegion"]

            bucket_name = t.get("S3BucketName")
            if not bucket_name:
                out.append(CheckResult("FAIL", f"Trail {name} does not deliver logs to an S3 bucket.", name, arn, name, region))
                continue
            bucket = next((b for b in lib.s3_buckets(ctx) if b["Name"] == bucket_name), None)
            if bucket is None:
                out.append(CheckResult("MANUAL", f"Trail {name} logs to bucket {bucket_name} in another account; check it manually.", name, arn, name, region, {"bucket": bucket_name}))
                continue
            public, reason = lib.bucket_is_public(ctx, bucket)
            if public:
                out.append(CheckResult("FAIL", f"S3 bucket {bucket_name} used by trail {name} is publicly accessible: {reason}.", name, arn, name, region, {"bucket": bucket_name, "reason": reason}, [bucket["Arn"]]))
            else:
                out.append(CheckResult("PASS", f"S3 bucket {bucket_name} used by trail {name} is not publicly accessible.", name, arn, name, region, {"bucket": bucket_name}, [bucket["Arn"]]))
        return out
