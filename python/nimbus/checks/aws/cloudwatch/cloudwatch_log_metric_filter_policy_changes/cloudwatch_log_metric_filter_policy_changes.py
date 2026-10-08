"""Ensure a log metric filter and alarm exist for IAM policy changes (CIS AWS 3.0 4.4)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class CloudwatchLogMetricFilterPolicyChanges(Check):
    def execute(self, ctx) -> list[CheckResult]:
        return lib.metric_filter_check(ctx, self, [['DeleteGroupPolicy', 'DeleteRolePolicy', 'DeleteUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion', 'AttachRolePolicy', 'DetachRolePolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'AttachGroupPolicy', 'DetachGroupPolicy']], 'IAM policy changes')
