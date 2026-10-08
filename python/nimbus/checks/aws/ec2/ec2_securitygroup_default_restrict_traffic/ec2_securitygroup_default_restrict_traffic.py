"""Ensure the default security group of every VPC restricts all traffic (CIS AWS 3.0 5.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2SecuritygroupDefaultRestrictTraffic(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for sg in lib.security_groups(ctx, region):
                if sg.get("GroupName") != "default":
                    continue
                gid = sg["GroupId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:security-group/{gid}"
                n_in, n_out = len(sg.get("IpPermissions", [])), len(sg.get("IpPermissionsEgress", []))
                details = {"vpc_id": sg.get("VpcId"), "ingress_rules": n_in, "egress_rules": n_out}
                related = [sg["VpcId"]] if sg.get("VpcId") else []
                if n_in or n_out:
                    out.append(CheckResult("FAIL", f"Default security group {gid} in VPC {sg.get('VpcId')} has {n_in} inbound and {n_out} outbound rule(s).", gid, arn, "default", region, details, related))
                else:
                    out.append(CheckResult("PASS", f"Default security group {gid} in VPC {sg.get('VpcId')} restricts all traffic.", gid, arn, "default", region, details, related))
            return out

        return lib.regional_results(ctx, per_region)
