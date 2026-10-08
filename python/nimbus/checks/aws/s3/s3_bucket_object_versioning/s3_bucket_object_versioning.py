"""Check if S3 buckets have object versioning enabled (CIS AWS 3.0 2.1.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketObjectVersioning(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            resp = lib.s3_client_for(ctx, b).get_bucket_versioning(Bucket=name)
            status = resp.get("Status", "Disabled")
            mfa = resp.get("MFADelete", "Disabled")
            if status == "Enabled":
                out.append(CheckResult("PASS", f"S3 bucket {name} has versioning enabled.", name, arn, name, region, {"versioning": status, "mfa_delete": mfa}))
            else:
                out.append(CheckResult("FAIL", f"S3 bucket {name} has versioning {status.lower()}.", name, arn, name, region, {"versioning": status, "mfa_delete": mfa}))
        return out
