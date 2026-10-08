"""Ensure EKS cluster control plane endpoint is not publicly accessible (CIS AWS 3.0 5.2)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class EksControlPlaneEndpointAccessPubliclyAccessible(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            eks = ctx.client("eks", region)
            out = []
            for name in lib.describe_all(eks, "list_clusters", "clusters"):
                c = eks.describe_cluster(name=name)["cluster"]
                vpc = c.get("resourcesVpcConfig", {}) or {}
                cidrs = vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]
                details = {"endpoint_public_access": vpc.get("endpointPublicAccess"), "endpoint_private_access": vpc.get("endpointPrivateAccess"), "public_access_cidrs": cidrs}
                related = list(vpc.get("securityGroupIds") or []) + ([vpc["vpcId"]] if vpc.get("vpcId") else [])
                if vpc.get("endpointPublicAccess", True) and "0.0.0.0/0" in cidrs:
                    out.append(CheckResult("FAIL", f"EKS cluster {name} has a publicly accessible API endpoint open to 0.0.0.0/0.", name, c["arn"], name, region, details, related))
                else:
                    out.append(CheckResult("PASS", f"EKS cluster {name} API endpoint is not publicly accessible from the internet.", name, c["arn"], name, region, details, related))
            return out

        return lib.regional_results(ctx, per_region)
