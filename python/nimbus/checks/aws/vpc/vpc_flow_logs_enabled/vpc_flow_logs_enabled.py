"""Ensure VPC Flow Logging is Enabled in all VPCs (CIS AWS 3.0 3.7)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class VpcFlowLogsEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            ec2 = ctx.client("ec2", region)
            logs = lib.describe_all(ec2, "describe_flow_logs", "FlowLogs")
            by_vpc = {}
            for fl in logs:
                if fl.get("FlowLogStatus", "ACTIVE") == "ACTIVE":
                    by_vpc.setdefault(fl.get("ResourceId"), []).append(fl.get("FlowLogId"))
            out = []
            for vpc in lib.describe_all(ec2, "describe_vpcs", "Vpcs"):
                vid = vpc["VpcId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:vpc/{vid}"
                details = {"cidr": vpc.get("CidrBlock"), "default": vpc.get("IsDefault", False)}
                if by_vpc.get(vid):
                    out.append(CheckResult("PASS", f"VPC {vid} has flow logs enabled.", vid, arn, vid, region, {**details, "flow_logs": by_vpc[vid]}))
                else:
                    out.append(CheckResult("FAIL", f"VPC {vid} does not have flow logs enabled.", vid, arn, vid, region, details))
            return out

        return lib.regional_results(ctx, per_region)
