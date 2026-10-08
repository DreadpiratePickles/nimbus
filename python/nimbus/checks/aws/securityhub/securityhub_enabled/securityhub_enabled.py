"""Ensure AWS Security Hub is enabled (CIS AWS 3.0 4.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class SecurityhubEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            sh = ctx.client("securityhub", region)
            try:
                hub = sh.describe_hub()
            except lib.ClientError as exc:
                if lib.error_code(exc) in ("InvalidAccessException", "ResourceNotFoundException"):
                    rid = f"hub/{ctx.account_id}"
                    return [CheckResult("FAIL", f"Security Hub is not enabled in {region}.", rid,
                                        f"arn:{ctx.partition}:securityhub:{region}:{ctx.account_id}:hub/default", rid, region)]
                raise
            arn = hub.get("HubArn") or f"arn:{ctx.partition}:securityhub:{region}:{ctx.account_id}:hub/default"
            return [CheckResult("PASS", f"Security Hub is enabled in {region}.", arn.split(":")[-1], arn, "default", region, {"subscribed_at": hub.get("SubscribedAt")})]

        return lib.regional_results(ctx, per_region)
