"""Execute checks concurrently and convert results into Go-contract findings."""

from __future__ import annotations

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .base import Check, CheckResult

log = logging.getLogger("nimbus.checks")


def error_finding(check: Check, ctx, exc: BaseException) -> dict[str, Any]:
    try:
        account = ctx.account_id
    except Exception:  # noqa: BLE001
        account = ""
    region = getattr(ctx, "home_region", "") or ""
    result = CheckResult(
        status="FAIL",
        status_extended=f"Check {check.check_id} errored: {type(exc).__name__}: {exc}",
        resource_id=f"{check.check_id}:{account or 'unknown'}",
        resource_name=check.check_id,
        region=region,
        resource_details={"error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc(limit=5)},
    )
    return check.to_finding(result, account, status="ERROR")


def run_check(ctx, check: Check) -> list[dict[str, Any]]:
    try:
        results = check.execute(ctx) or []
        account = ctx.account_id
        return [check.to_finding(r, account) for r in results]
    except Exception as exc:  # noqa: BLE001 - per-check isolation
        log.warning("check %s failed: %s", check.check_id, exc)
        return [error_finding(check, ctx, exc)]


def run(ctx, checks: list[Check], workers: int = 8) -> list[dict[str, Any]]:
    """Run ``checks`` against ``ctx``; never raises for check failures."""
    findings: list[dict[str, Any]] = []
    order = {c.check_id: i for i, c in enumerate(checks)}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(run_check, ctx, c): c for c in checks}
        per_check: dict[str, list[dict[str, Any]]] = {}
        for fut in as_completed(futures):
            per_check[futures[fut].check_id] = fut.result()
    for cid in sorted(per_check, key=lambda k: order.get(k, 0)):
        findings.extend(per_check[cid])
    return findings
