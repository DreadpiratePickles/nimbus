"""Check for EC2 Instances with a Public IP (CIS AWS 3.0 5.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2InstancePublicIp(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for i in lib.instances(ctx, region):
                iid = i["InstanceId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:instance/{iid}"
                ip = i.get("PublicIpAddress")
                sgs = [g["GroupId"] for g in i.get("SecurityGroups", [])]
                if ip:
                    out.append(CheckResult("FAIL", f"EC2 instance {iid} has public IP address {ip}.", iid, arn, iid, region, {"public_ip": ip, "subnet_id": i.get("SubnetId")}, sgs))
                else:
                    out.append(CheckResult("PASS", f"EC2 instance {iid} does not have a public IP address.", iid, arn, iid, region, {"subnet_id": i.get("SubnetId")}, sgs))
            return out

        return lib.regional_results(ctx, per_region)
