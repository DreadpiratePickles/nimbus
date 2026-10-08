"""Ensure hardware MFA is enabled for the root account (CIS AWS 3.0 1.6)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamRootHardwareMfaEnabled(Check):
    def execute(self, ctx) -> list[CheckResult]:
        summary = lib.account_summary(ctx)
        if int(summary.get("AccountMFAEnabled", 0)) != 1:
            return [lib.account_result(ctx, "FAIL", "MFA is not enabled for the root account.")]
        devices = ctx.client("iam").list_virtual_mfa_devices(AssignmentStatus="Any").get("VirtualMFADevices", [])
        virtual_root = [d["SerialNumber"] for d in devices
                        if "root-account-mfa-device" in d.get("SerialNumber", "") or str(d.get("User", {}).get("Arn", "")).endswith(":root")]
        if virtual_root:
            return [lib.account_result(ctx, "FAIL", "Root account has a virtual MFA device instead of a hardware MFA device.",
                                       details={"virtual_mfa_devices": virtual_root})]
        return [lib.account_result(ctx, "PASS", "Root account has a hardware MFA device enabled.")]
