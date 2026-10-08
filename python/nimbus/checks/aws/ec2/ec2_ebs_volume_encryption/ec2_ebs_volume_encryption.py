"""Ensure there are no EBS Volumes unencrypted (CIS AWS 3.0 2.2.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2EbsVolumeEncryption(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for v in lib.describe_all(ctx.client("ec2", region), "describe_volumes", "Volumes"):
                vid = v["VolumeId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:volume/{vid}"
                attached = [a.get("InstanceId") for a in v.get("Attachments", []) if a.get("InstanceId")]
                details = {"size_gb": v.get("Size"), "state": v.get("State"), "kms_key_id": v.get("KmsKeyId")}
                if v.get("Encrypted"):
                    out.append(CheckResult("PASS", f"EBS volume {vid} is encrypted.", vid, arn, vid, region, details, attached))
                else:
                    out.append(CheckResult("FAIL", f"EBS volume {vid} is unencrypted.", vid, arn, vid, region, details, attached))
            return out

        return lib.regional_results(ctx, per_region)
