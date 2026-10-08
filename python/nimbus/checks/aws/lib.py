"""Shared AWS lookups and policy helpers used by the native checks.

All expensive lookups are memoised on the AuditContext via ``ctx.cached`` so
several checks share one API call (credential report, buckets, trails ...).
"""

from __future__ import annotations

import csv
import fnmatch
import io
import json
import time
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import unquote

from botocore.exceptions import ClientError  # noqa: F401  (re-exported for checks)

INTERNET_V4 = "0.0.0.0/0"
INTERNET_V6 = "::/0"
ROOT_USER = "<root_account>"


# ----------------------------------------------------------------------------- time
def parse_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    if not s or s.lower() in ("n/a", "no_information", "not_supported", "false", "true"):
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_since(value: Any, now: datetime | None = None) -> int | None:
    dt = parse_date(value)
    if dt is None:
        return None
    now = now or datetime.now(timezone.utc)
    return (now - dt).days


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


# ----------------------------------------------------------------------------- IAM
def credential_report(ctx) -> list[dict[str, str]]:
    def load() -> list[dict[str, str]]:
        iam = ctx.client("iam")
        for _ in range(20):
            state = iam.generate_credential_report().get("State")
            if state == "COMPLETE":
                break
            time.sleep(1)
        content = iam.get_credential_report()["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return list(csv.DictReader(io.StringIO(content)))

    return ctx.cached("iam:credential_report", load)


def root_row(ctx) -> dict[str, str] | None:
    for row in credential_report(ctx):
        if row.get("user") == ROOT_USER:
            return row
    return None


def user_rows(ctx) -> list[dict[str, str]]:
    return [r for r in credential_report(ctx) if r.get("user") != ROOT_USER]


def is_true(v: Any) -> bool:
    return str(v).strip().lower() == "true"


def account_summary(ctx) -> dict[str, int]:
    return ctx.cached("iam:account_summary", lambda: ctx.client("iam").get_account_summary()["SummaryMap"])


def password_policy(ctx) -> dict[str, Any] | None:
    def load():
        try:
            return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                return None
            raise

    return ctx.cached("iam:password_policy", load)


def _paginate(client, op: str, key: str, **kwargs) -> list[Any]:
    out: list[Any] = []
    for page in client.get_paginator(op).paginate(**kwargs):
        out.extend(page.get(key, []))
    return out


def iam_users(ctx) -> list[dict[str, Any]]:
    return ctx.cached("iam:users", lambda: _paginate(ctx.client("iam"), "list_users", "Users"))


def iam_roles(ctx) -> list[dict[str, Any]]:
    return ctx.cached("iam:roles", lambda: _paginate(ctx.client("iam"), "list_roles", "Roles"))


def iam_groups(ctx) -> list[dict[str, Any]]:
    return ctx.cached("iam:groups", lambda: _paginate(ctx.client("iam"), "list_groups", "Groups"))


def iam_policies(ctx, scope: str, only_attached: bool = True) -> list[dict[str, Any]]:
    return ctx.cached(
        f"iam:policies:{scope}:{only_attached}",
        lambda: _paginate(ctx.client("iam"), "list_policies", "Policies", Scope=scope, OnlyAttached=only_attached),
    )


def policy_default_document(ctx, policy: dict[str, Any]) -> dict[str, Any]:
    def load():
        resp = ctx.client("iam").get_policy_version(PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])
        return normalize_document(resp["PolicyVersion"]["Document"])

    return ctx.cached(f"iam:policydoc:{policy['Arn']}:{policy['DefaultVersionId']}", load)


def inline_policies(ctx) -> list[dict[str, Any]]:
    """Every inline policy: {entity_type, entity_name, entity_arn, policy_name, document}."""

    def load():
        iam = ctx.client("iam")
        out = []
        specs = (
            ("user", iam_users(ctx), "UserName", "list_user_policies", "get_user_policy"),
            ("group", iam_groups(ctx), "GroupName", "list_group_policies", "get_group_policy"),
            ("role", iam_roles(ctx), "RoleName", "list_role_policies", "get_role_policy"),
        )
        for etype, entities, name_key, list_op, get_op in specs:
            for ent in entities:
                name = ent[name_key]
                for pname in _paginate(iam, list_op, "PolicyNames", **{name_key: name}):
                    doc = getattr(iam, get_op)(**{name_key: name, "PolicyName": pname})["PolicyDocument"]
                    out.append({
                        "entity_type": etype,
                        "entity_name": name,
                        "entity_arn": ent["Arn"],
                        "policy_name": pname,
                        "document": normalize_document(doc),
                    })
        return out

    return ctx.cached("iam:inline_policies", load)


def normalize_document(doc: Any) -> dict[str, Any]:
    if isinstance(doc, str):
        doc = json.loads(unquote(doc))
    return doc or {}


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def statements(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in as_list((doc or {}).get("Statement")) if isinstance(s, dict)]


def is_admin_policy(doc: dict[str, Any]) -> bool:
    """True when a statement Allows Action "*" on Resource "*" (full "*:*" admin)."""
    for st in statements(doc):
        if st.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in as_list(st.get("Action"))]
        resources = [str(r) for r in as_list(st.get("Resource"))]
        if ("*" in actions or "*:*" in actions) and "*" in resources:
            return True
    return False


# Privilege-escalation action combinations (Rhino Security Labs research, as used by Prowler).
PRIVESC_COMBOS: list[set[str]] = [
    {"iam:CreatePolicyVersion"},
    {"iam:SetDefaultPolicyVersion"},
    {"iam:CreateAccessKey"},
    {"iam:CreateLoginProfile"},
    {"iam:UpdateLoginProfile"},
    {"iam:AttachUserPolicy"},
    {"iam:AttachGroupPolicy"},
    {"iam:AttachRolePolicy", "sts:AssumeRole"},
    {"iam:PutUserPolicy"},
    {"iam:PutGroupPolicy"},
    {"iam:PutRolePolicy", "sts:AssumeRole"},
    {"iam:AddUserToGroup"},
    {"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
    {"iam:PassRole", "ec2:RunInstances"},
    {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
    {"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"},
    {"iam:PassRole", "cloudformation:CreateStack"},
    {"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"},
    {"iam:PassRole", "glue:CreateDevEndpoint"},
    {"glue:UpdateDevEndpoint"},
    {"lambda:UpdateFunctionCode"},
]


def _action_allowed(action: str, patterns: Iterable[str]) -> bool:
    a = action.lower()
    return any(fnmatch.fnmatchcase(a, p.lower()) for p in patterns)


def privilege_escalation_actions(doc: dict[str, Any]) -> list[str]:
    """Return the escalation actions a policy grants (empty list if none)."""
    allowed: list[str] = []
    denied: list[str] = []
    for st in statements(doc):
        acts = [str(a) for a in as_list(st.get("Action"))]
        if st.get("Effect") == "Allow":
            allowed.extend(acts)
        elif st.get("Effect") == "Deny":
            denied.extend(acts)
    found: set[str] = set()
    for combo in PRIVESC_COMBOS:
        if all(_action_allowed(a, allowed) and not _action_allowed(a, denied) for a in combo):
            found.update(combo)
    return sorted(found)


def attached_policy_entities(ctx, policy_arn: str) -> list[str]:
    resp = ctx.client("iam").list_entities_for_policy(PolicyArn=policy_arn)
    out = [u["UserName"] for u in resp.get("PolicyUsers", [])]
    out += [g["GroupName"] for g in resp.get("PolicyGroups", [])]
    out += [r["RoleName"] for r in resp.get("PolicyRoles", [])]
    return out


# ----------------------------------------------------------------------------- S3
def s3_buckets(ctx) -> list[dict[str, Any]]:
    """Buckets with resolved region: [{Name, Region, Arn}]."""

    def load():
        s3 = ctx.client("s3")
        out = []
        for b in s3.list_buckets().get("Buckets", []):
            name = b["Name"]
            region = b.get("BucketRegion")
            if not region:
                try:
                    region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
                except ClientError:
                    region = ctx.home_region
            if region == "EU":
                region = "eu-west-1"
            out.append({"Name": name, "Region": region, "Arn": f"arn:{ctx.partition}:s3:::{name}"})
        return out

    return ctx.cached("s3:buckets", load)


def s3_client_for(ctx, bucket: dict[str, Any]):
    return ctx.client("s3", bucket["Region"])


def bucket_policy(ctx, bucket: dict[str, Any]) -> dict[str, Any] | None:
    def load():
        try:
            pol = s3_client_for(ctx, bucket).get_bucket_policy(Bucket=bucket["Name"])["Policy"]
            return json.loads(pol)
        except ClientError as exc:
            if error_code(exc) in ("NoSuchBucketPolicy", "NoSuchBucket"):
                return None
            raise

    return ctx.cached(f"s3:policy:{bucket['Name']}", load)


def bucket_acl_grants(ctx, bucket: dict[str, Any]) -> list[dict[str, Any]]:
    return ctx.cached(
        f"s3:acl:{bucket['Name']}",
        lambda: s3_client_for(ctx, bucket).get_bucket_acl(Bucket=bucket["Name"]).get("Grants", []),
    )


PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def public_acl_permissions(grants: list[dict[str, Any]]) -> list[str]:
    perms = []
    for g in grants:
        grantee = g.get("Grantee", {})
        if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_GROUPS:
            perms.append(g.get("Permission", ""))
    return perms


def bucket_public_access_block(ctx, bucket: dict[str, Any]) -> dict[str, bool]:
    def load():
        try:
            return s3_client_for(ctx, bucket).get_public_access_block(Bucket=bucket["Name"])["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if error_code(exc) in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                return {}
            raise

    return ctx.cached(f"s3:pab:{bucket['Name']}", load)


def account_public_access_block(ctx) -> dict[str, bool]:
    def load():
        try:
            return ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if error_code(exc) in ("NoSuchPublicAccessBlockConfiguration",):
                return {}
            raise

    return ctx.cached("s3:account_pab", load)


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            if "*" in [str(x) for x in as_list(v)]:
                return True
    return False


WRITE_ACTION_PATTERNS = ("s3:*", "*", "s3:put*", "s3:delete*", "s3:restoreobject", "s3:replicateobject", "s3:abortmultipartupload")


def public_policy_statements(doc: dict[str, Any] | None, write_only: bool = False) -> list[dict[str, Any]]:
    """Allow statements with a public principal and no Condition."""
    out = []
    for st in statements(doc or {}):
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        if not _principal_is_public(st.get("Principal")):
            continue
        if write_only:
            acts = [str(a).lower() for a in as_list(st.get("Action"))]
            if not any(a in WRITE_ACTION_PATTERNS or a.startswith(("s3:put", "s3:delete")) for a in acts):
                continue
        out.append(st)
    return out


def pab_blocks_all(cfg: dict[str, bool]) -> bool:
    return bool(cfg) and all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))


def bucket_is_public(ctx, bucket: dict[str, Any]) -> tuple[bool, str]:
    """(public?, reason) considering account PAB, bucket PAB, ACL and policy."""
    acct = account_public_access_block(ctx)
    if pab_blocks_all(acct):
        return False, "account-level Block Public Access is fully enabled"
    pab = bucket_public_access_block(ctx, bucket)
    if pab_blocks_all(pab):
        return False, "bucket-level Block Public Access is fully enabled"
    ignore_acls = acct.get("IgnorePublicAcls") or pab.get("IgnorePublicAcls")
    restrict_policy = acct.get("RestrictPublicBuckets") or pab.get("RestrictPublicBuckets")
    if not ignore_acls:
        perms = public_acl_permissions(bucket_acl_grants(ctx, bucket))
        if perms:
            return True, f"bucket ACL grants {','.join(sorted(set(perms)))} to a public group"
    if not restrict_policy and public_policy_statements(bucket_policy(ctx, bucket)):
        return True, "bucket policy allows access to a public principal (*)"
    return False, "no public ACL grants or public policy statements"


# ----------------------------------------------------------------------------- EC2
def describe_all(client, op: str, key: str, **kwargs) -> list[Any]:
    return _paginate(client, op, key, **kwargs)


def security_groups(ctx, region: str) -> list[dict[str, Any]]:
    return ctx.cached(f"ec2:sgs:{region}", lambda: describe_all(ctx.client("ec2", region), "describe_security_groups", "SecurityGroups"))


def instances(ctx, region: str) -> list[dict[str, Any]]:
    def load():
        out = []
        for res in describe_all(ctx.client("ec2", region), "describe_instances", "Reservations"):
            out.extend(i for i in res.get("Instances", []) if i.get("State", {}).get("Name") != "terminated")
        return out

    return ctx.cached(f"ec2:instances:{region}", load)


def _perm_open_to_internet(perm: dict[str, Any]) -> list[str]:
    srcs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp") == INTERNET_V4]
    srcs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == INTERNET_V6]
    return srcs


def perm_covers_port(perm: dict[str, Any], port: int | None, protocol: str = "tcp") -> bool:
    proto = str(perm.get("IpProtocol", "-1"))
    if proto == "-1":
        return True
    if port is None:  # "any port" means all traffic or full port range
        return perm.get("FromPort") in (0, -1, None) and perm.get("ToPort") in (65535, -1, None)
    if proto.lower() not in (protocol, "6" if protocol == "tcp" else protocol):
        return False
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if lo is None or hi is None:
        return True
    return lo <= port <= hi


def sg_open_ports(sg: dict[str, Any], port: int | None) -> list[str]:
    """Internet sources that may reach ``port`` (None = any port / all traffic)."""
    found = []
    for perm in sg.get("IpPermissions", []):
        srcs = _perm_open_to_internet(perm)
        if srcs and perm_covers_port(perm, port):
            found.extend(srcs)
    return sorted(set(found))


def sg_open_result(ctx, check, port: int | None, label: str):
    from nimbus.checks.base import CheckResult

    def per_region(region: str):
        out = []
        for sg in security_groups(ctx, region):
            srcs = sg_open_ports(sg, port)
            arn = f"arn:{ctx.partition}:ec2:{region}:{ctx.account_id}:security-group/{sg['GroupId']}"
            if srcs:
                status, msg = "FAIL", f"Security group {sg['GroupName']} ({sg['GroupId']}) allows ingress from {', '.join(srcs)} to {label}."
            else:
                status, msg = "PASS", f"Security group {sg['GroupName']} ({sg['GroupId']}) does not allow ingress from the internet to {label}."
            out.append(CheckResult(status, msg, sg["GroupId"], arn, sg["GroupName"], region,
                                   {"vpc_id": sg.get("VpcId"), "open_sources": srcs}, [sg.get("VpcId")] if sg.get("VpcId") else []))
        return out

    return regional_results(ctx, per_region)


# ----------------------------------------------------------------------------- CloudTrail
def trails(ctx) -> list[dict[str, Any]]:
    """Unique trails (deduped by ARN) with Status, EventSelectors and HomeRegion populated."""

    def load():
        seen: dict[str, dict[str, Any]] = {}

        def per_region(region):
            return region, ctx.client("cloudtrail", region).describe_trails(includeShadowTrails=True).get("trailList", [])

        for region, tl in ctx.map_regions(per_region):
            for t in tl:
                arn = t.get("TrailARN")
                if arn and arn not in seen:
                    t = dict(t)
                    t.setdefault("HomeRegion", region)
                    seen[arn] = t
        for t in seen.values():
            client = ctx.client("cloudtrail", t["HomeRegion"])
            try:
                t["Status"] = client.get_trail_status(Name=t["TrailARN"])
            except ClientError:
                t["Status"] = {}
            try:
                sel = client.get_event_selectors(TrailName=t["TrailARN"])
                t["EventSelectors"] = sel.get("EventSelectors") or []
                t["AdvancedEventSelectors"] = sel.get("AdvancedEventSelectors") or []
            except ClientError:
                t["EventSelectors"], t["AdvancedEventSelectors"] = [], []
        return list(seen.values())

    return ctx.cached("cloudtrail:trails", load)


def trail_is_logging(t: dict[str, Any]) -> bool:
    return bool(t.get("Status", {}).get("IsLogging"))


def trail_logs_management_events(t: dict[str, Any]) -> bool:
    sels = t.get("EventSelectors") or []
    adv = t.get("AdvancedEventSelectors") or []
    if not sels and not adv:
        return True  # default selectors log all management events
    for s in sels:
        if s.get("IncludeManagementEvents", True) and s.get("ReadWriteType", "All") == "All":
            return True
    for a in adv:
        for fs in a.get("FieldSelectors", []):
            if fs.get("Field") == "eventCategory" and "Management" in fs.get("Equals", []):
                return True
    return False


# ----------------------------------------------------------------------------- CloudWatch metric filters
def metric_filter_check(ctx, check, required: list[list[str]], description: str):
    """CIS section 4 helper.

    ``required`` is a list of alternatives; each alternative is a list of
    substrings that must all appear in a metric filter pattern on a log group
    fed by an active multi-region trail.  PASS requires a CloudWatch alarm on
    that filter's metric.
    """
    from nimbus.checks.base import CheckResult

    region = ctx.home_region
    candidates = [t for t in trails(ctx) if t.get("CloudWatchLogsLogGroupArn") and trail_is_logging(t)]
    multi = [t for t in candidates if t.get("IsMultiRegionTrail")] or candidates
    for t in multi:
        lg_arn = t["CloudWatchLogsLogGroupArn"]
        parts = lg_arn.split(":")
        lg_region, lg_name = parts[3], parts[6] if len(parts) > 6 else ""
        logs = ctx.client("logs", lg_region)
        filters = describe_all(logs, "describe_metric_filters", "metricFilters", logGroupName=lg_name)
        for mf in filters:
            pattern = mf.get("filterPattern", "") or ""
            norm = pattern.replace(" ", "")
            if not any(all(tok.replace(" ", "") in norm for tok in alt) for alt in required):
                continue
            cw = ctx.client("cloudwatch", lg_region)
            for mt in mf.get("metricTransformations", []):
                alarms = describe_all(cw, "describe_alarms", "MetricAlarms")
                if any(a.get("MetricName") == mt.get("metricName") and a.get("Namespace") == mt.get("metricNamespace") for a in alarms):
                    arn = f"arn:{ctx.partition}:logs:{lg_region}:{ctx.account_id}:metric-filter/{mf['filterName']}"
                    return [CheckResult("PASS", f"CloudWatch log group {lg_name} has metric filter {mf['filterName']} and an alarm for {description}.",
                                        mf["filterName"], arn, mf["filterName"], lg_region,
                                        {"log_group": lg_name, "filter_pattern": pattern, "trail": t.get("Name")}, [t["TrailARN"]])]
    return [CheckResult("FAIL", f"No CloudWatch log metric filter and alarm exist for {description}.",
                        ctx.account_id, ctx.account_arn, ctx.account_id, region,
                        {"trails_with_cloudwatch_logs": [t.get("Name") for t in candidates]})]


def account_result(ctx, status: str, msg: str, region: str | None = None, details: dict | None = None, resource_id: str | None = None, arn: str | None = None):
    from nimbus.checks.base import CheckResult

    rid = resource_id or ctx.account_id
    return CheckResult(status, msg, rid, arn or ctx.account_arn, rid, region or ctx.home_region, details or {})


# ----------------------------------------------------------------------------- regional helpers
def regional_results(ctx, fn, regions: list[str] | None = None):
    """Run ``fn(region) -> list[CheckResult]`` in every region; a region whose API
    is unreachable/denied yields a MANUAL result instead of failing the whole check."""
    from botocore.exceptions import BotoCoreError

    from nimbus.checks.base import CheckResult

    def guarded(region: str):
        try:
            return fn(region) or []
        except ClientError as exc:
            code = error_code(exc)
            if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClientException",
                        "InvalidClientTokenId", "OptInRequired", "AuthFailure", "SubscriptionRequiredException"):
                return [CheckResult("MANUAL", f"Could not evaluate region {region}: {code}", ctx.account_id, ctx.account_arn,
                                    ctx.account_id, region, {"error": str(exc)})]
            raise
        except BotoCoreError as exc:
            return [CheckResult("MANUAL", f"Could not evaluate region {region}: {exc}", ctx.account_id, ctx.account_arn,
                                ctx.account_id, region, {"error": str(exc)})]

    return [r for rs in ctx.map_regions(guarded, regions) for r in rs]
