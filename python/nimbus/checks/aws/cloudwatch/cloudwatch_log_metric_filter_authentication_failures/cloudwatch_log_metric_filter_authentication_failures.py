"""Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (CIS AWS 3.0 4.6)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudwatchLogMetricFilterAuthenticationFailures(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.metric_filter_check(ctx, self, [['$.eventName', 'ConsoleLogin', '$.errorMessage', 'Failed authentication']], 'AWS Management Console authentication failures')
