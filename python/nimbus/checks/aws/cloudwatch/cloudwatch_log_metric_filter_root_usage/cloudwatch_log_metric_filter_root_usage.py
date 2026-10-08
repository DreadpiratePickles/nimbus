"""Ensure a log metric filter and alarm exist for usage of the root account (CIS AWS 3.0 4.3)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudwatchLogMetricFilterRootUsage(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.metric_filter_check(ctx, self, [['$.userIdentity.type', 'Root', '$.userIdentity.invokedBy', 'NOT EXISTS', '$.eventType', 'AwsServiceEvent']], 'usage of the root account')
