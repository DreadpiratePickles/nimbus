"""Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 3389 (CIS AWS 3.0 5.2, 5.3)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class Ec2SecuritygroupAllowIngressFromInternetToTcpPort3389(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.sg_open_result(ctx, self, 3389, 'TCP port 3389 (RDP)')
