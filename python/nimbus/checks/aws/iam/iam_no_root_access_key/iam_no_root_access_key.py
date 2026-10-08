"""Ensure no root account access key exists (CIS AWS 3.0 1.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamNoRootAccessKey(Check):
    def execute(self, ctx) -> list[CheckResult]:
        row = lib.root_row(ctx)
        if row is None:
            present = int(lib.account_summary(ctx).get("AccountAccessKeysPresent", 0))
            if present:
                return [lib.account_result(ctx, "FAIL", "Root account has access keys (per IAM account summary).")]
            return [lib.account_result(ctx, "PASS", "Root account does not have access keys.")]
        k1, k2 = lib.is_true(row.get("access_key_1_active")), lib.is_true(row.get("access_key_2_active"))
        if k1 or k2:
            n = int(k1) + int(k2)
            return [lib.account_result(ctx, "FAIL", f"Root account has {n} active access key(s).",
                                       details={"access_key_1_active": k1, "access_key_2_active": k2})]
        return [lib.account_result(ctx, "PASS", "Root account does not have active access keys.")]
