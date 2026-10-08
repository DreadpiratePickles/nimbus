"""Ensure a log metric filter and alarm exist for unauthorized API calls (CIS AWS 3.0 4.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudwatchLogMetricFilterUnauthorizedApiCalls(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.metric_filter_check(ctx, self, [['$.errorCode', 'UnauthorizedOperation', 'AccessDenied']], 'unauthorized API calls')
