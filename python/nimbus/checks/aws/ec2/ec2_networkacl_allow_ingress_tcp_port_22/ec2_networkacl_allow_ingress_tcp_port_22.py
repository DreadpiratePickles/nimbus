"""Ensure no Network ACLs allow ingress from 0.0.0.0/0 to SSH port 22 (CIS AWS 3.0 5.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2NetworkaclAllowIngressTcpPort22(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def covers(entry, port=22):
            proto = str(entry.get("Protocol", "-1"))
            if proto == "-1":
                return True
            if proto != "6":
                return False
            pr = entry.get("PortRange")
            return pr is None or pr.get("From", 0) <= port <= pr.get("To", 65535)

        def per_region(region):
            out = []
            for acl in lib.describe_all(ctx.client("ec2", region), "describe_network_acls", "NetworkAcls"):
                aid = acl["NetworkAclId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:network-acl/{aid}"
                open_srcs = []
                for family in ("CidrBlock", "Ipv6CidrBlock"):
                    internet = lib.INTERNET_V4 if family == "CidrBlock" else lib.INTERNET_V6
                    for e in sorted((e for e in acl.get("Entries", []) if not e.get("Egress")), key=lambda e: e.get("RuleNumber", 32767)):
                        if e.get(family) != internet or not covers(e):
                            continue
                        if e.get("RuleAction") == "allow":
                            open_srcs.append(internet)
                        break  # first matching rule wins
                related = [acl["VpcId"]] if acl.get("VpcId") else []
                if open_srcs:
                    out.append(CheckResult("FAIL", f"Network ACL {aid} allows ingress from {', '.join(open_srcs)} to TCP port 22.", aid, arn, aid, region, {"vpc_id": acl.get("VpcId"), "default": acl.get("IsDefault")}, related))
                else:
                    out.append(CheckResult("PASS", f"Network ACL {aid} does not allow ingress from the internet to TCP port 22.", aid, arn, aid, region, {"vpc_id": acl.get("VpcId"), "default": acl.get("IsDefault")}, related))
            return out

        return lib.regional_results(ctx, per_region)
