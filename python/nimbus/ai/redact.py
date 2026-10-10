"""Outbound minimisation for model calls (plan §5.2, ``--redact-llm`` default on).

Before any estate data goes to a model provider:

* only allowlisted columns leave (``OUTBOUND_COLUMNS``) plus columns whose values are all numbers
  (aggregates such as ``count``); everything else - raw provider JSON (``doc``, ``raw``), tags,
  attributes, policy documents, descriptions - is withheld and named as withheld;
* account ids (any value under an account column and any 12-digit number), ARN account segments,
  Azure subscription ids and IPv4 addresses become stable placeholders (``ACCT_xxxxxxxx``...),
  which the model can use in its SQL and which are re-hydrated locally before anything runs and
  in the answer shown to the user.

``NIMBUS_REDACT_LLM=0`` turns redaction (not the column allowlist) off.

Computed forms (verify-4 defect 3). The model chooses the SQL, so an allowlisted column name can
carry any expression (``hex(account) AS title``, ``tags AS title``, ``CAST(account AS INTEGER)``).
Values are therefore also checked by what they contain, not only by column name, mirroring the Go
MCP server's value-level pass: a 12-digit integer is an account; a hex string that decodes to an
identifier is withheld; a string whose digits contain an account id this session has seen (after
concatenation, spacing or ``group_concat``) is withheld; a digits-only string that is a piece of
a known account (``substr``) is withheld; a JSON object in a scalar column (``tags AS title``) is
withheld. ``guardrails.ToolGate`` additionally refuses identifier-transforming functions, aliasing
into allowlisted names and range/LIKE comparisons on account columns in model-chosen SQL. Residual
risk: an identifier in a shape not recognised here (an account id with dashes, a hostname), and a
low-bandwidth yes/no oracle through equality on non-account columns, are not caught; redaction
minimises what a provider sees, it is not an access-control boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from typing import Any, Sequence

OUTBOUND_COLUMNS = frozenset({
    "id", "finding_id", "issue_id", "path_id", "canonical_id", "check_id", "source", "severity", "status", "provider",
    "account", "region", "resource_id", "resource_name", "resource_type", "title", "weaknesses", "compliance",
    "score", "risk_score", "band", "name", "rule_id", "impact", "control_id", "failing_checks", "namespace", "pod",
    "kind", "state", "confidence", "first_seen", "last_seen", "type", "class", "hops", "sensitive", "path", "steps",
    "finding_ids", "attack_paths", "remediation", "label",
})

_ACCOUNT_COLS = frozenset({"account", "account_id", "subscription", "project"})

_ARN = re.compile(r"(arn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:)(\d{12})(:)")
_ACCT = re.compile(r"(?<!\d)\d{12}(?!\d)")  # also inside 'x111111111111' / '111111111111x'
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}){6,}")
WITHHELD = "[withheld: computed identifier]"
_SUB = re.compile(r"(?i)(/subscriptions/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PH = re.compile(r"\b(?:ACCT|IP|SUB|TAG)_[0-9a-f]{8}\b")
# 12 digits written in groups ("7319 4628 0517", "7319-4628-0517", "7319.4628.0517"): an account
# id even before the session has seen it (verify-5 PY-5); IPv4 addresses are replaced first.
_ACCT_GROUPED = re.compile(r"(?<![\d.])\d{2,6}(?:[ .\-]\d{2,6}){1,5}(?![\d.]?\d)")


def redaction_enabled() -> bool:
    return os.environ.get("NIMBUS_REDACT_LLM", "1").strip().lower() not in ("0", "false", "no", "off")


class Redactor:
    """Stable per-instance placeholders; the HMAC key is random, so placeholders cannot be
    reversed offline (a 12-digit account space is small enough to brute-force a plain hash)."""

    def __init__(self, enabled: bool | None = None):
        self.enabled = redaction_enabled() if enabled is None else enabled
        self._key = secrets.token_bytes(32)
        self._to: dict[str, str] = {}
        self._from: dict[str, str] = {}
        self.last_input_raw = False

    def placeholder(self, kind: str, value: str) -> str:
        if not value or value in self._from:
            return value
        k = f"{kind}|{value}"
        if k not in self._to:
            ph = f"{kind}_" + hmac.new(self._key, k.encode(), hashlib.sha256).hexdigest()[:8]
            self._to[k], self._from[ph] = ph, value
        return self._to[k]

    def known_accounts(self) -> list[str]:
        return [k.split("|", 1)[1] for k in self._to if k.startswith("ACCT|") and len(k) > 5]

    def learn(self, kind: str, values: Any) -> None:
        """Seed placeholders for values the session must hide even before a query shows them."""
        for v in values or ():
            if v not in (None, ""):
                self.placeholder(kind, str(v))

    def _computed(self, s: str) -> bool:
        """True when s is a transformed form of a known or recognisable identifier."""
        digits = re.sub(r"\D", "", s)
        known = self.known_accounts()
        if digits and any(a in digits for a in known):
            return True
        if s.strip().isdigit() and len(s.strip()) >= 4 and any(s.strip() in a for a in known):
            return True
        if _HEX.fullmatch(s.strip()):
            try:
                dec = bytes.fromhex(s.strip()).decode("utf-8", "ignore")
            except ValueError:
                dec = ""
            if dec and (self._plain(dec) != dec or self._computed(dec)):
                return True
        return False

    def _plain(self, s: str) -> str:
        s = _ARN.sub(lambda m: m.group(1) + self.placeholder("ACCT", m.group(2)) + m.group(3), s)
        s = _SUB.sub(lambda m: m.group(1) + self.placeholder("SUB", m.group(2).lower()), s)
        s = _ACCT.sub(lambda m: self.placeholder("ACCT", m.group(0)), s)
        s = _IPV4.sub(lambda m: m.group(0) if m.group(0) == "0.0.0.0" else self.placeholder("IP", m.group(0)), s)
        s = _ACCT_GROUPED.sub(lambda m: self.placeholder("ACCT", re.sub(r"\D", "", m.group(0)))
                              if len(re.sub(r"\D", "", m.group(0))) == 12 else m.group(0), s)
        return s

    def text(self, s: str) -> str:
        if not self.enabled or not s:
            return s
        out = self._plain(s)
        if self._computed(out):
            return WITHHELD
        return out

    def value(self, column: str, v: Any) -> Any:
        if not self.enabled or v is None or isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            if column.lower() in _ACCOUNT_COLS or (float(v).is_integer() and 1e11 <= abs(v) < 1e12):
                return self.placeholder("ACCT", str(int(v)))
            return v
        if column.lower() == "tags" and isinstance(v, dict):
            return {self.text(str(k)): self.placeholder("TAG", json.dumps(x) if not isinstance(x, str) else x) for k, x in v.items()}
        if column.lower() in _ACCOUNT_COLS:
            return self.placeholder("ACCT", str(v))
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, (list, tuple)):
            return [self.value("", x) for x in v]
        if isinstance(v, dict):
            return {self.text(str(k)): self.value(str(k), x) for k, x in v.items()}
        return self.text(str(v))

    def restore(self, s: str) -> str:
        if not s:
            return s
        return _PH.sub(lambda m: self._from.get(m.group(0), m.group(0)), s)

    def has_raw_identifier(self, v: Any) -> bool:
        """True when v (tool arguments from the model) holds an identifier redaction would replace.
        The model only ever saw placeholders, so a raw id is a guess compared with real data."""
        if isinstance(v, str):
            return bool(_ARN.search(v) or _SUB.search(v) or _ACCT.search(v)
                        or any(ip != "0.0.0.0" for ip in _IPV4.findall(v)))
        if isinstance(v, (list, tuple)):
            return any(self.has_raw_identifier(x) for x in v)
        if isinstance(v, dict):
            return any(self.has_raw_identifier(x) for x in v.values())
        return False

    def restore_obj(self, v: Any) -> Any:
        """Re-hydrate placeholders in model tool arguments. Records in ``last_input_raw`` whether the
        arguments held a raw identifier (``guardrails.ToolGate`` refuses such a call)."""
        self.last_input_raw = self.enabled and self.has_raw_identifier(v)
        return self._restore_obj(v)

    def _restore_obj(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.restore(v)
        if isinstance(v, list):
            return [self._restore_obj(x) for x in v]
        if isinstance(v, dict):
            return {k: self._restore_obj(x) for k, x in v.items()}
        return v


def _numeric_column(rows: Sequence[Sequence[Any]], i: int) -> bool:
    return all(r[i] is None or (isinstance(r[i], (int, float)) and not isinstance(r[i], bool)) for r in rows)


def minimise(columns: Sequence[str], rows: Sequence[Sequence[Any]], redactor: Redactor) -> tuple[list[str], list[list[Any]], list[str]]:
    """Apply the outbound column allowlist and redaction. Returns (columns, rows, withheld)."""
    keep, withheld = [], []
    for i, c in enumerate(columns):
        if c.lower() in OUTBOUND_COLUMNS or (rows and _numeric_column(rows, i)):
            keep.append(i)
        else:
            withheld.append(c)
    out_rows = [[_scalar(redactor, columns[i], r[i]) for i in keep] for r in rows]
    return [columns[i] for i in keep], out_rows, withheld


# Allowlisted columns that legitimately hold JSON text (lists of ids, compliance maps, steps).
_JSON_COLUMNS = frozenset({"weaknesses", "compliance", "finding_ids", "attack_paths", "steps", "hops", "path"})


def _scalar(redactor: Redactor, column: str, v: Any) -> Any:
    """One outbound cell. A JSON object/array in a column that is not a JSON column is a renamed
    structured value (``tags AS title``, ``doc AS remediation``) and is withheld."""
    if redactor.enabled and isinstance(v, str) and column.lower() not in _JSON_COLUMNS:
        t = v.strip()
        if t[:1] in ("{", "["):
            try:
                json.loads(t)
                return "[withheld: structured value]"
            except ValueError:
                pass
    return redactor.value(column, v)


# Fields of a finding / attack path that may reach a model (explain, fix). Everything else - raw
# provider JSON, resource attributes (policy documents, user data, env), tags, description,
# scan bookkeeping - stays local.
FINDING_FIELDS = ("id", "canonical_id", "check_id", "source", "title", "severity", "status", "provider", "account", "region",
                  "file", "line_start", "line_end", "remediation", "weaknesses", "compliance")
PATH_FIELDS = ("id", "rule_id", "name", "impact", "mitre", "provider", "account", "score", "severity", "finding_ids")
STEP_FIELDS = ("stage", "finding_id", "weakness", "relation", "resource", "title", "summary")


def outbound_finding(f: Any, redactor: Redactor) -> dict[str, Any]:
    d = f.to_doc()
    out = {k: redactor.value(k, d[k]) for k in FINDING_FIELDS if k in d and d[k] not in (None, "", [], {})}
    res = d.get("resource") or {}
    out["resource"] = {k: redactor.value(k, res.get(k, "")) for k in ("id", "type", "name")}
    return out


def outbound_path(p: Any, redactor: Redactor) -> dict[str, Any]:
    d = p.to_doc()
    out = {k: redactor.value(k, d[k]) for k in PATH_FIELDS if k in d}
    out["steps"] = [{k: redactor.value(k, s.get(k)) for k in STEP_FIELDS if k in s} for s in d.get("steps") or []]
    return out
