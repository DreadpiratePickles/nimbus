"""Ensure RDS instances have minor version upgrade enabled (CIS AWS 3.0 2.3.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class RdsInstanceMinorVersionUpgradeEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for db in lib.describe_all(ctx.client("rds", region), "describe_db_instances", "DBInstances"):
                if db.get("Engine", "").startswith(("docdb", "neptune")):
                    continue
                name, arn = db["DBInstanceIdentifier"], db["DBInstanceArn"]
                sgs = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])]

                if db.get("AutoMinorVersionUpgrade"):
                    out.append(CheckResult("PASS", f"RDS instance {name} has automatic minor version upgrade enabled.", name, arn, name, region, {"engine_version": db.get("EngineVersion")}, sgs))
                else:
                    out.append(CheckResult("FAIL", f"RDS instance {name} does not have automatic minor version upgrade enabled.", name, arn, name, region, {"engine_version": db.get("EngineVersion")}, sgs))

            return out

        return lib.regional_results(ctx, per_region)
