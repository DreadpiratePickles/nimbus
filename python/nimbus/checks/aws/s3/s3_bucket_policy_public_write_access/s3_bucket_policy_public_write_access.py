"""Check if S3 buckets have policies which allow WRITE access (CIS AWS 3.0 2.1.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketPolicyPublicWriteAccess(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            policy = lib.bucket_policy(ctx, b)
            if policy is None:
                out.append(CheckResult("PASS", f"S3 bucket {name} does not have a bucket policy.", name, arn, name, region))
                continue
            acct, pab = lib.account_public_access_block(ctx), lib.bucket_public_access_block(ctx, b)
            stmts = lib.public_policy_statements(policy, write_only=True)
            if stmts and not (acct.get("RestrictPublicBuckets") or pab.get("RestrictPublicBuckets")):
                sids = [s.get("Sid", "") for s in stmts]
                out.append(CheckResult("FAIL", f"S3 bucket {name} has a bucket policy allowing public write access.", name, arn, name, region, {"statements": sids}))
            else:
                out.append(CheckResult("PASS", f"S3 bucket {name} bucket policy does not allow public write access.", name, arn, name, region))
        return out
