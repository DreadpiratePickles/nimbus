"""Check if EFS protects sensitive data with encryption at rest (CIS AWS 3.0 2.4.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class EfsEncryptionAtRestEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for fs in lib.describe_all(ctx.client("efs", region), "describe_file_systems", "FileSystems"):
                fid = fs["FileSystemId"]
                arn = fs.get("FileSystemArn") or f"arn:{ctx.partition}:elasticfilesystem:{region}:{ctx.account_id}:file-system/{fid}"
                name = fs.get("Name") or fid
                if fs.get("Encrypted"):
                    out.append(CheckResult("PASS", f"EFS {fid} has encryption at rest enabled.", fid, arn, name, region, {"kms_key_id": fs.get("KmsKeyId")}))
                else:
                    out.append(CheckResult("FAIL", f"EFS {fid} does not have encryption at rest enabled.", fid, arn, name, region))
            return out

        return lib.regional_results(ctx, per_region)
