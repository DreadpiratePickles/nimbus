"""CLI: python3 -m nimbus.checks --provider aws [...]"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import registry, runner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python3 -m nimbus.checks", description="Run nimbus native CSPM checks (Prowler-style).")
    p.add_argument("--provider", default="aws", choices=["aws"])
    p.add_argument("--profile")
    p.add_argument("--role-arn")
    p.add_argument("--external-id")
    p.add_argument("--regions", help="comma-separated regions (default: all enabled regions)")
    p.add_argument("--checks", help="comma-separated check IDs")
    p.add_argument("--services", help="comma-separated services (s3,iam,...)")
    p.add_argument("--compliance", action="append", help="framework[:control], e.g. cis_aws or cis_aws:1.4 (repeatable / comma-separated)")
    p.add_argument("--severity", help="comma-separated severities (critical,high,medium,low)")
    p.add_argument("--output", "-o", default="-", help="output file or - for stdout")
    p.add_argument("--jsonl", action="store_true", help="emit JSON lines instead of a JSON array")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--list", action="store_true", help="list matching checks and exit")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, stream=sys.stderr)
    checks = registry.filter_checks(
        provider=args.provider,
        ids=args.checks,
        services=args.services,
        severities=args.severity,
        compliance=args.compliance,
    )
    if args.list:
        for c in checks:
            cis = ",".join(c.compliance.get("cis_aws", []))
            print(f"{c.check_id}\t{c.severity}\t{c.service}\tcis_aws:{cis}\t{c.title}")
        print(f"{len(checks)} checks", file=sys.stderr)
        return 0

    from .context import AuditContext

    try:
        regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
        ctx = AuditContext(profile=args.profile, role_arn=args.role_arn, external_id=args.external_id,
                           regions=regions, max_workers=args.workers)
        _ = ctx.account_id
    except Exception as exc:  # noqa: BLE001 - hard error: no credentials / identity
        print(f"error: cannot establish AWS session: {exc}", file=sys.stderr)
        return 2

    findings = runner.run(ctx, checks, workers=args.workers)
    if args.jsonl:
        text = "".join(json.dumps(f, default=str) + "\n" for f in findings)
    else:
        text = json.dumps(findings, indent=2, default=str) + "\n"
    if args.output in ("-", ""):
        sys.stdout.write(text)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    fails = sum(1 for f in findings if f["status"] == "FAIL")
    errs = sum(1 for f in findings if f["status"] == "ERROR")
    print(f"{len(checks)} checks, {len(findings)} findings ({fails} FAIL, {errs} ERROR)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
