"""Check if RDS instances storage is encrypted (CIS AWS 3.0 2.3.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class RdsInstanceStorageEncrypted(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for db in lib.describe_all(ctx.client("rds", region), "describe_db_instances", "DBInstances"):
                if db.get("Engine", "").startswith(("docdb", "neptune")):
                    continue
                name, arn = db["DBInstanceIdentifier"], db["DBInstanceArn"]
                sgs = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])]

                if db.get("StorageEncrypted"):
                    out.append(CheckResult("PASS", f"RDS instance {name} storage is encrypted.", name, arn, name, region, {"kms_key_id": db.get("KmsKeyId"), "engine": db.get("Engine")}, sgs))
                else:
                    out.append(CheckResult("FAIL", f"RDS instance {name} storage is not encrypted.", name, arn, name, region, {"engine": db.get("Engine")}, sgs))

            return out

        return lib.regional_results(ctx, per_region)
