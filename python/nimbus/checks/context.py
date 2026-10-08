"""AuditContext: boto3 session, account identity, regions and cached clients."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, TypeVar

T = TypeVar("T")

DEFAULT_REGION = "us-east-1"


class AuditContext:
    """Everything a check needs to talk to AWS.

    * session from an explicit boto3 Session, a named profile, an assumed role
      (``sts:AssumeRole``) or the default credential chain;
    * ``account_id`` resolved once via STS;
    * ``regions`` either explicit or the enabled regions of the account;
    * ``client(service, region)`` cached and thread-safe;
    * ``map_regions(fn)`` runs ``fn(region)`` across regions with bounded workers;
    * ``cached(key, fn)`` memoises shared lookups (credential report, trails...).
    """

    def __init__(
        self,
        session: Any = None,
        profile: str | None = None,
        role_arn: str | None = None,
        regions: list[str] | None = None,
        external_id: str | None = None,
        max_workers: int = 8,
        account_id: str | None = None,
    ) -> None:
        self._profile = profile
        self._role_arn = role_arn
        self._external_id = external_id
        self._explicit_regions = [r for r in (regions or []) if r]
        self.max_workers = max(1, int(max_workers))
        self._lock = threading.RLock()
        self._clients: dict[tuple[str, str], Any] = {}
        self._cache: dict[str, Any] = {}
        self._account_id = account_id
        self._regions: list[str] | None = None
        self.audited_at = datetime.now(timezone.utc)
        self.session = session if session is not None else self._build_session()

    # -- session ------------------------------------------------------------------
    def _build_session(self):
        import boto3

        base = boto3.Session(profile_name=self._profile) if self._profile else boto3.Session()
        if not self._role_arn:
            return base
        sts = base.client("sts", region_name=base.region_name or DEFAULT_REGION)
        kwargs: dict[str, Any] = {"RoleArn": self._role_arn, "RoleSessionName": "nimbus-checks"}
        if self._external_id:
            kwargs["ExternalId"] = self._external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=base.region_name,
        )

    # -- identity -----------------------------------------------------------------
    @property
    def home_region(self) -> str:
        if self._explicit_regions:
            return self._explicit_regions[0]
        return getattr(self.session, "region_name", None) or DEFAULT_REGION

    @property
    def partition(self) -> str:
        r = self.home_region
        if r.startswith("cn-"):
            return "aws-cn"
        if r.startswith("us-gov-"):
            return "aws-us-gov"
        return "aws"

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            with self._lock:
                if self._account_id is None:
                    self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id

    @property
    def account_arn(self) -> str:
        return f"arn:{self.partition}:iam::{self.account_id}:root"

    # -- regions ------------------------------------------------------------------
    @property
    def regions(self) -> list[str]:
        if self._regions is None:
            with self._lock:
                if self._regions is None:
                    if self._explicit_regions:
                        self._regions = list(self._explicit_regions)
                    else:
                        self._regions = self._enabled_regions()
        return self._regions

    def _enabled_regions(self) -> list[str]:
        try:
            resp = self.client("ec2").describe_regions(
                AllRegions=True,
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
            )
            regions = sorted(r["RegionName"] for r in resp.get("Regions", []))
            return regions or [self.home_region]
        except Exception:  # noqa: BLE001 - fall back to home region
            return [self.home_region]

    # -- clients ------------------------------------------------------------------
    def client(self, service: str, region: str | None = None):
        region = region or self.home_region
        key = (service, region)
        with self._lock:
            c = self._clients.get(key)
            if c is None:
                from botocore.config import Config

                cfg = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="nimbus-checks")
                c = self.session.client(service, region_name=region, config=cfg)
                self._clients[key] = c
        return c

    def regional(self, service: str) -> Iterator[tuple[str, Any]]:
        for region in self.regions:
            yield region, self.client(service, region)

    def map_regions(self, fn: Callable[[str], T], regions: list[str] | None = None) -> list[T]:
        """Run ``fn(region)`` for every region concurrently; results keep region order."""
        regs = list(regions if regions is not None else self.regions)
        if len(regs) <= 1:
            return [fn(r) for r in regs]
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(regs))) as pool:
            return list(pool.map(fn, regs))

    # -- shared lookups -----------------------------------------------------------
    def cached(self, key: str, fn: Callable[[], T]) -> T:
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        value = fn()
        with self._lock:
            return self._cache.setdefault(key, value)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()
