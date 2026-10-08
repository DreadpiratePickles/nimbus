"""Pydantic v2 mirror of internal/model/model.go.

Field names are identical to the Go JSON tags. ``to_doc()`` reproduces Go's ``omitempty``
behaviour so a Python-serialised finding is byte-compatible in shape with a Go one, and
``fingerprint()`` matches ``model.Finding.Fingerprint`` exactly.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

GO_ZERO_TIME = datetime(1, 1, 1, tzinfo=timezone.utc)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.value]


SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class Status(str, Enum):
    FAIL = "FAIL"
    PASS = "PASS"
    SKIP = "SKIP"
    ERROR = "ERROR"


PROVIDERS = ("aws", "azure", "gcp", "oci", "kubernetes", "github", "m365", "okta", "iac", "unknown")


def parse_severity(raw: Any) -> Severity:
    """Same spellings as Go's model.ParseSeverity."""
    if isinstance(raw, Severity):
        return raw
    s = str(raw if raw is not None else "").strip().lower()
    if s in ("critical", "crit", "danger", "5", "error"):
        return Severity.CRITICAL
    if s in ("high", "4", "warning", "warn"):
        return Severity.HIGH
    if s in ("medium", "med", "moderate", "3"):
        return Severity.MEDIUM
    if s in ("low", "2", "minor"):
        return Severity.LOW
    return Severity.INFO


def parse_status(raw: Any) -> Status:
    """Same spellings as Go's model.ParseStatus."""
    if isinstance(raw, Status):
        return raw
    s = str(raw if raw is not None else "").strip().lower()
    if s in ("fail", "failed", "alarm", "open", "new", "danger", "warning"):
        return Status.FAIL
    if s in ("pass", "passed", "ok", "success", "resolved"):
        return Status.PASS
    if s in ("skip", "skipped", "manual", "muted", "suppressed", "info"):
        return Status.SKIP
    return Status.ERROR


def normalize_provider(raw: str) -> str:
    s = (raw or "").strip().lower()
    table = {
        "aws": "aws", "amazon": "aws",
        "azure": "azure", "azurerm": "azure", "az": "azure", "microsoft": "azure",
        "gcp": "gcp", "google": "gcp", "googlecloud": "gcp", "google cloud": "gcp",
        "oci": "oci", "oracle": "oci",
        "kubernetes": "kubernetes", "k8s": "kubernetes", "helm": "kubernetes", "kustomize": "kubernetes",
        "github": "github", "gh": "github",
        "m365": "m365", "microsoft365": "m365", "office365": "m365", "o365": "m365",
        "okta": "okta",
        "terraform": "iac", "cloudformation": "iac", "iac": "iac", "dockerfile": "iac", "bicep": "iac", "arm": "iac",
    }
    return table.get(s, "unknown")


def go_time(dt: Optional[datetime]) -> str:
    """Format like Go's time.Time JSON (RFC3339Nano, UTC as 'Z')."""
    if dt is None:
        dt = GO_ZERO_TIME
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    s = f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    if dt.microsecond:
        s += ("." + f"{dt.microsecond:06d}").rstrip("0")
    return s + "Z"


def parse_time(raw: Any) -> Optional[datetime]:
    if raw in (None, ""):
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    s = str(raw).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Go may emit nanoseconds; Python handles at most microseconds.
    if "." in s:
        head, _, tail = s.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        rest = tail[len(digits):]
        s = f"{head}.{digits[:6]}{rest}" if digits else head + rest
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_zero(dt: Optional[datetime]) -> bool:
    return dt is None or dt.year <= 1


class _Base(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore", use_enum_values=False)


class Resource(_Base):
    id: str = ""
    type: str = ""
    name: str = ""
    attributes: Optional[dict[str, Any]] = None
    related: Optional[list[str]] = None

    def to_doc(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "type": self.type, "name": self.name}
        if self.attributes:
            d["attributes"] = self.attributes
        if self.related:
            d["related"] = self.related
        return d


class Finding(_Base):
    id: str = ""
    source: str = ""
    check_id: str = ""
    canonical_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    status: Status = Status.FAIL
    provider: str = ""
    account: str = ""
    region: str = ""
    resource: Resource = Field(default_factory=Resource)
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    remediation: str = ""
    weaknesses: list[str] = Field(default_factory=list)
    compliance: dict[str, list[str]] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)
    scan_id: str = ""
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw: Any = None

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: Any) -> Severity:
        return parse_severity(v)

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, v: Any) -> Status:
        if v in (None, ""):
            return Status.FAIL
        return parse_status(v)

    @field_validator("first_seen", "last_seen", mode="before")
    @classmethod
    def _time(cls, v: Any) -> Optional[datetime]:
        dt = parse_time(v)
        return None if _is_zero(dt) else dt

    @field_validator("weaknesses", mode="before")
    @classmethod
    def _weak(cls, v: Any) -> list[str]:
        return list(v or [])

    @field_validator("compliance", "tags", mode="before")
    @classmethod
    def _maps(cls, v: Any) -> dict:
        return dict(v or {})

    @field_validator("tags", mode="after")
    @classmethod
    def _tags_str(cls, v: dict) -> dict:
        return {str(k): str(val) for k, val in v.items()}

    @field_validator("resource", mode="before")
    @classmethod
    def _res(cls, v: Any) -> Any:
        return v or {}

    # -- Go parity ---------------------------------------------------------------
    def fingerprint(self) -> str:
        key = "|".join([self.source, self.check_id, self.provider, self.account, self.region, self.resource.id, self.file])
        return hashlib.sha256(key.encode("utf-8")).digest()[:16].hex()

    def finalize(self, now: Optional[datetime] = None) -> "Finding":
        now = now or datetime.now(timezone.utc)
        if not self.provider:
            self.provider = "unknown"
        if not self.resource.name:
            self.resource.name = self.resource.id
        if not self.canonical_id:
            self.canonical_id = self.source.upper() + ":" + self.check_id
        if not self.id:
            self.id = self.fingerprint()
        if _is_zero(self.first_seen):
            self.first_seen = now
        self.last_seen = now
        return self

    def has_weakness(self, w: str) -> bool:
        return w in self.weaknesses

    def add_compliance(self, framework: str, *controls: str) -> None:
        cur = self.compliance.setdefault(framework, [])
        for c in controls:
            if c and c not in cur:
                cur.append(c)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.severity.value]

    def to_doc(self) -> dict[str, Any]:
        """JSON-ready dict with Go's omitempty semantics."""
        d: dict[str, Any] = {
            "id": self.id, "source": self.source, "check_id": self.check_id, "canonical_id": self.canonical_id,
            "title": self.title,
        }
        if self.description:
            d["description"] = self.description
        d["severity"] = self.severity.value
        d["status"] = self.status.value
        d["provider"] = self.provider
        d["account"] = self.account
        if self.region:
            d["region"] = self.region
        d["resource"] = self.resource.to_doc()
        for k in ("file", "line_start", "line_end", "remediation"):
            v = getattr(self, k)
            if v:
                d[k] = v
        if self.weaknesses:
            d["weaknesses"] = self.weaknesses
        if self.compliance:
            d["compliance"] = self.compliance
        if self.tags:
            d["tags"] = self.tags
        if self.scan_id:
            d["scan_id"] = self.scan_id
        d["first_seen"] = go_time(self.first_seen)
        d["last_seen"] = go_time(self.last_seen)
        if self.raw not in (None, "", {}, []):
            d["raw"] = self.raw
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_doc(), separators=(",", ":"), default=str)


class Step(_Base):
    stage: int = 0
    finding_id: str = ""
    weakness: str = ""
    relation: str = ""
    resource: str = ""
    title: str = ""
    summary: str = ""


class AttackPath(_Base):
    id: str = ""
    rule_id: str = ""
    name: str = ""
    impact: str = ""
    mitre: list[str] = Field(default_factory=list)
    provider: str = ""
    account: str = ""
    score: float = 0.0
    severity: Severity = Severity.INFO
    steps: list[Step] = Field(default_factory=list)
    narrative: str = ""
    finding_ids: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: Any) -> Severity:
        return parse_severity(v)

    @field_validator("mitre", "steps", "finding_ids", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> list:
        return list(v or [])

    def to_doc(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        if not self.mitre:
            d.pop("mitre", None)
        return d


class ToolRun(_Base):
    tool: str = ""
    account: str = ""
    status: str = ""
    message: str = ""
    findings: int = 0
    output: str = ""


class ScanSummary(_Base):
    scan_id: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    accounts: list[str] = Field(default_factory=list)
    tools: list[ToolRun] = Field(default_factory=list)
    total: int = 0
    failed: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_provider: dict[str, int] = Field(default_factory=dict)
    attack_paths: int = 0

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def _time(cls, v: Any) -> Optional[datetime]:
        return parse_time(v)

    @field_validator("accounts", "tools", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> list:
        return list(v or [])

    @field_validator("by_severity", "by_provider", mode="before")
    @classmethod
    def _maps(cls, v: Any) -> dict:
        return dict(v or {})

    def to_doc(self) -> dict[str, Any]:
        d = self.model_dump(mode="json")
        d["started_at"] = go_time(self.started_at)
        d["finished_at"] = go_time(self.finished_at)
        return d


class GraphNode(_Base):
    """Mirror of internal/graph.Node (JSON stored in graph_nodes.doc)."""
    id: str
    type: str = ""
    class_: str = Field(default="", alias="class")
    name: str = ""
    provider: str = ""
    account: str = ""
    region: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    weaknesses: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    sensitive: bool = False
    criticality: str = ""
    owner: str = ""
    modified_at: str = ""
    cve_count: int = 0
    monthly_cost: float = 0.0

    @field_validator("attributes", mode="before")
    @classmethod
    def _attrs(cls, v: Any) -> dict:
        return dict(v or {})

    @field_validator("weaknesses", "finding_ids", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> list:
        return list(v or [])

    def to_doc(self) -> dict[str, Any]:
        d = self.model_dump(mode="json", by_alias=True)
        return {k: v for k, v in d.items() if v not in ("", 0, 0.0, False, [], {}, None) or k in ("id", "type", "class", "name", "provider", "account")}


class GraphEdge(_Base):
    from_: str = Field(alias="from")
    to: str
    kind: str
    attr: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attr", mode="before")
    @classmethod
    def _attr(cls, v: Any) -> dict:
        return dict(v or {})

    def to_doc(self) -> dict[str, Any]:
        d = {"from": self.from_, "to": self.to, "kind": self.kind}
        if self.attr:
            d["attr"] = self.attr
        return d


def load_findings(data: Any) -> list[Finding]:
    """Parse a JSON array, JSON-lines text or list of dicts into findings."""
    if isinstance(data, (bytes, str)):
        text = data.decode() if isinstance(data, bytes) else data
        text = text.strip()
        if not text:
            return []
        if text.startswith("["):
            data = json.loads(text)
        else:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [d if isinstance(d, Finding) else Finding.model_validate(d) for d in data]
