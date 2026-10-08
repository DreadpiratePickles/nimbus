"""Ensure rotation for customer created KMS CMKs is enabled (CIS AWS 3.0 3.6)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class KmsCmkRotationEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            kms = ctx.client("kms", region)
            out = []
            for k in lib.describe_all(kms, "list_keys", "Keys"):
                meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                    continue
                if meta.get("KeySpec", meta.get("CustomerMasterKeySpec", "SYMMETRIC_DEFAULT")) != "SYMMETRIC_DEFAULT" or meta.get("Origin") == "EXTERNAL":
                    continue
                kid, arn = meta["KeyId"], meta["Arn"]
                enabled = kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False)
                if enabled:
                    out.append(CheckResult("PASS", f"KMS key {kid} has automatic rotation enabled.", kid, arn, kid, region))
                else:
                    out.append(CheckResult("FAIL", f"KMS key {kid} does not have automatic rotation enabled.", kid, arn, kid, region))
            return out

        return lib.regional_results(ctx, per_region)
