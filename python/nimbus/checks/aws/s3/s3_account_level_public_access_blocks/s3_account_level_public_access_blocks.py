"""Check S3 Account Level Public Access Block (CIS AWS 3.0 2.1.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3AccountLevelPublicAccessBlocks(Check):
    def execute(self, ctx) -> list[CheckResult]:
        cfg = lib.account_public_access_block(ctx)
        rid = ctx.account_id
        arn = f"arn:{ctx.partition}:s3:{ctx.home_region}:{ctx.account_id}:account"
        if lib.pab_blocks_all(cfg):
            return [CheckResult("PASS", "Block Public Access is fully enabled at the account level.", rid, arn, rid, ctx.home_region, dict(cfg))]
        missing = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not cfg.get(k)]
        return [CheckResult("FAIL", f"Account-level Block Public Access is not fully enabled (disabled: {', '.join(missing)}).", rid, arn, rid, ctx.home_region, {"disabled": missing})]
