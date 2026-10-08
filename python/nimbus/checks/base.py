"""Core check abstractions: CheckResult and Check (metadata + finding conversion)."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_STATUSES = ("PASS", "FAIL", "MANUAL")

# Prowler/ASFF resource types -> nimbus lower-snake resource types (Go inventory views).
RESOURCE_TYPE_MAP = {
    "AwsAccount": "aws_account",
    "AwsS3Bucket": "aws_s3_bucket",
    "AwsS3AccountPublicAccessBlock": "aws_s3_account_public_access_block",
    "AwsEc2Instance": "aws_instance",
    "AwsEc2SecurityGroup": "aws_security_group",
    "AwsEc2NetworkAcl": "aws_network_acl",
    "AwsEc2Volume": "aws_ebs_volume",
    "AwsEc2Eip": "aws_eip",
    "AwsEc2Vpc": "aws_vpc",
    "AwsIamUser": "aws_iam_user",
    "AwsIamRole": "aws_iam_role",
    "AwsIamPolicy": "aws_iam_policy",
    "AwsIamAccessAnalyzer": "aws_accessanalyzer_analyzer",
    "AwsRdsDbInstance": "aws_db_instance",
    "AwsEfsFileSystem": "aws_efs_file_system",
    "AwsCloudTrailTrail": "aws_cloudtrail",
    "AwsConfigConfigurationRecorder": "aws_config_configuration_recorder",
    "AwsKmsKey": "aws_kms_key",
    "AwsLogsMetricFilter": "aws_cloudwatch_log_metric_filter",
    "AwsGuardDutyDetector": "aws_guardduty_detector",
    "AwsSecurityHubHub": "aws_securityhub_account",
    "AwsLambdaFunction": "aws_lambda_function",
    "AwsEksCluster": "aws_eks_cluster",
}


def map_resource_type(resource_type: str) -> str:
    """Map a Prowler ResourceType (AwsS3Bucket) to nimbus style (aws_s3_bucket)."""
    if not resource_type:
        return "aws_resource"
    if resource_type in RESOURCE_TYPE_MAP:
        return RESOURCE_TYPE_MAP[resource_type]
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", resource_type).lower()
    return snake if snake.startswith("aws_") else "aws_" + snake


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint(source: str, check_id: str, provider: str, account: str, region: str, resource_id: str, file: str = "") -> str:
    """Mirror of Go model.Finding.Fingerprint (sha256 of joined key, first 16 bytes hex)."""
    key = "|".join([source, check_id, provider, account, region, resource_id, file])
    return hashlib.sha256(key.encode()).digest()[:16].hex()


@dataclass
class CheckResult:
    status: str  # PASS | FAIL | MANUAL
    status_extended: str = ""
    resource_id: str = ""
    resource_arn: str = ""
    resource_name: str = ""
    region: str = ""
    resource_details: dict[str, Any] = field(default_factory=dict)
    related: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.status = self.status.upper()
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid check status {self.status!r}")
        if not self.resource_name:
            self.resource_name = self.resource_id


class Check:
    """Base class for a native check.

    Subclasses live in ``<check_id>.py`` next to ``<check_id>.metadata.json`` and
    implement :meth:`execute`.  Metadata is loaded lazily from that file.
    """

    _metadata_cache: dict[str, Any] | None = None

    # -- metadata -----------------------------------------------------------------
    @classmethod
    def metadata_path(cls) -> Path:
        src = Path(inspect.getfile(cls))
        return src.with_name(src.stem + ".metadata.json")

    @classmethod
    def load_metadata(cls) -> dict[str, Any]:
        cached = cls.__dict__.get("_metadata_cache")
        if cached is None:
            with open(cls.metadata_path(), encoding="utf-8") as fh:
                cached = json.load(fh)
            cls._metadata_cache = cached
        return cached

    @property
    def metadata(self) -> dict[str, Any]:
        return self.load_metadata()

    @property
    def check_id(self) -> str:
        return self.metadata["CheckID"]

    @property
    def title(self) -> str:
        return self.metadata.get("CheckTitle", self.check_id)

    @property
    def severity(self) -> str:
        return str(self.metadata.get("Severity", "medium")).lower()

    @property
    def service(self) -> str:
        return self.metadata.get("ServiceName", "")

    @property
    def provider(self) -> str:
        return self.metadata.get("Provider", "aws")

    @property
    def resource_type(self) -> str:
        return self.metadata.get("ResourceType", "")

    @property
    def compliance(self) -> dict[str, list[str]]:
        return {k: list(v) for k, v in (self.metadata.get("Compliance") or {}).items() if v}

    @property
    def remediation_text(self) -> str:
        return ((self.metadata.get("Remediation") or {}).get("Recommendation") or {}).get("Text", "")

    # -- execution ----------------------------------------------------------------
    def execute(self, ctx) -> list[CheckResult]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- finding conversion ---------------------------------------------------------
    def to_finding(self, result: CheckResult, account_id: str, status: str | None = None) -> dict[str, Any]:
        """Convert a CheckResult into the Go ``model.Finding`` JSON contract."""
        now = utcnow_iso()
        st = (status or result.status).upper()
        if st == "MANUAL":
            st = "SKIP"
        resource_id = result.resource_arn or result.resource_id
        compliance = self.compliance
        cis = compliance.get("cis_aws", [])
        provider = self.provider
        source = "nimbus"
        return {
            "id": fingerprint(source, self.check_id, provider, account_id or "", result.region or "", resource_id),
            "source": source,
            "check_id": self.check_id,
            "canonical_id": "",
            "title": self.title,
            "description": self.metadata.get("Risk") or self.metadata.get("Description", ""),
            "severity": self.severity.upper(),
            "status": st,
            "provider": provider,
            "account": account_id or "",
            "region": result.region or "",
            "resource": {
                "id": resource_id,
                "type": map_resource_type(self.resource_type),
                "name": result.resource_name or result.resource_id or resource_id,
                "attributes": dict(result.resource_details or {}),
                "related": list(result.related or []),
            },
            "remediation": self.remediation_text,
            "weaknesses": [],
            "compliance": compliance,
            "tags": {
                "cis_control": ",".join(cis),
                "service": self.service,
                "status_extended": result.status_extended,
            },
            "first_seen": now,
            "last_seen": now,
        }

    def __repr__(self) -> str:
        return f"<Check {self.check_id}>"
