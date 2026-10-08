"""Ensure there are no S3 buckets open to Everyone or Any AWS user (CIS AWS 3.0 2.1.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketPublicAccess(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            public, reason = lib.bucket_is_public(ctx, b)
            status = "FAIL" if public else "PASS"
            msg = f"S3 bucket {name} is publicly accessible: {reason}." if public else f"S3 bucket {name} is not publicly accessible ({reason})."
            out.append(CheckResult(status, msg, name, arn, name, region, {"reason": reason}))
        return out
