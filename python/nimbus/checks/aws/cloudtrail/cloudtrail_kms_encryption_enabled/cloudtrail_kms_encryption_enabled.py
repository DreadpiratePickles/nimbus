"""Ensure CloudTrail logs are encrypted at rest using KMS CMKs (CIS AWS 3.0 3.5)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudtrailKmsEncryptionEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        trails = lib.trails(ctx)
        if not trails:
            return [lib.account_result(ctx, "FAIL", "No CloudTrail trails are configured in the account.")]
        out = []
        for t in trails:
            name, arn, region = t["Name"], t["TrailARN"], t["HomeRegion"]

            if t.get("KmsKeyId"):
                out.append(CheckResult("PASS", f"Trail {name} has KMS encryption enabled.", name, arn, name, region, {"kms_key_id": t["KmsKeyId"]}, [t["KmsKeyId"]]))
            else:
                out.append(CheckResult("FAIL", f"Trail {name} does not have KMS encryption enabled.", name, arn, name, region))
        return out
