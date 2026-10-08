"""Check if EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required (CIS AWS 3.0 5.6)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2InstanceImdsv2Enabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            out = []
            for i in lib.instances(ctx, region):
                iid = i["InstanceId"]
                arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:instance/{iid}"
                mo = i.get("MetadataOptions", {}) or {}
                tokens, endpoint = mo.get("HttpTokens", "optional"), mo.get("HttpEndpoint", "enabled")
                details = {"http_tokens": tokens, "http_endpoint": endpoint, "state": i.get("State", {}).get("Name")}
                if endpoint == "disabled":
                    out.append(CheckResult("PASS", f"EC2 instance {iid} has the metadata service disabled.", iid, arn, iid, region, details))
                elif tokens == "required":
                    out.append(CheckResult("PASS", f"EC2 instance {iid} has IMDSv2 enabled and required.", iid, arn, iid, region, details))
                else:
                    out.append(CheckResult("FAIL", f"EC2 instance {iid} does not require IMDSv2 (HttpTokens={tokens}).", iid, arn, iid, region, details))
            return out

        return lib.regional_results(ctx, per_region)
