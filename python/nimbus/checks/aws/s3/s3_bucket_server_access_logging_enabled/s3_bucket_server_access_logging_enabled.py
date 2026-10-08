"""Check if S3 buckets have server access logging enabled (CIS AWS 3.0 3.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketServerAccessLoggingEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            logging = lib.s3_client_for(ctx, b).get_bucket_logging(Bucket=name).get("LoggingEnabled")
            if logging:
                out.append(CheckResult("PASS", f"S3 bucket {name} has server access logging enabled to {logging.get('TargetBucket')}.", name, arn, name, region, {"target_bucket": logging.get("TargetBucket")}))
            else:
                out.append(CheckResult("FAIL", f"S3 bucket {name} has server access logging disabled.", name, arn, name, region))
        return out
