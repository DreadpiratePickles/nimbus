"""Ensure there are no Public Accessible RDS instances (CIS AWS 3.0 2.3.3)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class RdsInstanceNoPublicAccess(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for db in lib.describe_all(ctx.client("rds", region), "describe_db_instances", "DBInstances"):
                if db.get("Engine", "").startswith(("docdb", "neptune")):
                    continue
                name, arn = db["DBInstanceIdentifier"], db["DBInstanceArn"]
                sgs = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])]

                endpoint = (db.get("Endpoint") or {}).get("Address")
                if db.get("PubliclyAccessible"):
                    out.append(CheckResult("FAIL", f"RDS instance {name} is set as publicly accessible (endpoint {endpoint}).", name, arn, name, region, {"endpoint": endpoint, "security_groups": sgs}, sgs))
                else:
                    out.append(CheckResult("PASS", f"RDS instance {name} is not publicly accessible.", name, arn, name, region, {"endpoint": endpoint}, sgs))

            return out

        return lib.regional_results(ctx, per_region)
