"""Ensure a log metric filter and alarm exist for security group changes (CIS AWS 3.0 4.10)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudwatchLogMetricFilterSecurityGroupChanges(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.metric_filter_check(ctx, self, [['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup']], 'security group changes')
