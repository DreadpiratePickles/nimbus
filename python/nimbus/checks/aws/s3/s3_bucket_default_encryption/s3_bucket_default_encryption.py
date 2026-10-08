"""Check if S3 buckets have default encryption (SSE) enabled or use a bucket policy to enforce it (CIS AWS 3.0 2.1.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketDefaultEncryption(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            try:
                rules = lib.s3_client_for(ctx, b).get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"].get("Rules", [])
            except lib.ClientError as exc:
                if lib.error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
                    raise
                rules = []
            algos = [r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for r in rules]
            algos = [a for a in algos if a]
            if algos:
                out.append(CheckResult("PASS", f"S3 bucket {name} has default server-side encryption ({', '.join(algos)}).", name, arn, name, region, {"sse_algorithms": algos}))
            else:
                out.append(CheckResult("FAIL", f"S3 bucket {name} does not have default server-side encryption.", name, arn, name, region))
        return out
