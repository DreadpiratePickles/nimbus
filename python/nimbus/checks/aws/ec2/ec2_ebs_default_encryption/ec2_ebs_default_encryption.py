"""Check if EBS Default Encryption is activated (CIS AWS 3.0 2.2.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2EbsDefaultEncryption(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            enabled = ctx.client("ec2", region).get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
            arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}"
            rid = f"ebs-default-encryption/{region}"
            if enabled:
                return [CheckResult("PASS", f"EBS default encryption is enabled in {region}.", rid, arn, rid, region)]
            return [CheckResult("FAIL", f"EBS default encryption is not enabled in {region}.", rid, arn, rid, region)]

        return lib.regional_results(ctx, per_region)
