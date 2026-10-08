"""Check if there is any unassigned Elastic IP (CIS AWS 3.0 5.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2ElasticIpUnassigned(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for a in ctx.client("ec2", region).describe_addresses().get("Addresses", []):
                aid = a.get("AllocationId") or a.get("PublicIp")
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:eip-allocation/{aid}"
                details = {"public_ip": a.get("PublicIp"), "domain": a.get("Domain")}
                if a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"):
                    out.append(CheckResult("PASS", f"Elastic IP {a.get('PublicIp')} is associated.", aid, arn, a.get("PublicIp", aid), region, details,
                                           [x for x in (a.get("InstanceId"), a.get("NetworkInterfaceId")) if x]))
                else:
                    out.append(CheckResult("FAIL", f"Elastic IP {a.get('PublicIp')} is not associated with any instance or network interface.", aid, arn, a.get("PublicIp", aid), region, details))
            return out

        return lib.regional_results(ctx, per_region)
