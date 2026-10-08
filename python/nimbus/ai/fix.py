"""IaC fix generation (Terraform, CloudFormation, Bicep, Kubernetes).

Order of preference:
1. Anthropic API (when configured) - output is validated (mentions the resource, parses as YAML
   for cloudformation/kubernetes, balanced braces for terraform/bicep); invalid output is discarded.
2. ``cloud-posture fix --finding <CANONICAL_ID> --format <fmt> --print`` when the Go binary is on PATH.
3. Built-in offline templates for the most common canonical ids, else a documented stub that
   names the resource and points at the remediation text.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any, Optional

import yaml

from ..models import Finding
from .llm import complete, extract_code

FORMATS = ("terraform", "cloudformation", "bicep", "kubernetes")
_ALIASES = {"tf": "terraform", "hcl": "terraform", "cfn": "cloudformation", "k8s": "kubernetes", "yaml": "kubernetes"}


def normalize_format(fmt: str) -> str:
    f = (fmt or "terraform").lower().strip()
    f = _ALIASES.get(f, f)
    if f not in FORMATS:
        raise ValueError(f"unknown format {fmt!r} (terraform|cloudformation|bicep|kubernetes)")
    return f


def _slug(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_]+", "_", s.split("/")[-1].split(":")[-1]).strip("_").lower()
    if not s or s[0].isdigit():
        s = "r_" + s
    return s[:60]


def _balanced(code: str) -> bool:
    depth = 0
    in_str = False
    prev = ""
    for ch in code:
        if ch == '"' and prev != "\\":
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth < 0:
                    return False
        prev = ch
    return depth == 0 and not in_str


class _CfnLoader(yaml.SafeLoader):
    pass


def _cfn_tag(loader, suffix, node):  # accept !Ref, !Sub, !GetAtt ...
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _cfn_tag)


def validate_fix(code: str, fmt: str, resource_name: str = "") -> list[str]:
    """Return a list of problems (empty == valid)."""
    fmt = normalize_format(fmt)
    problems = []
    if not code or not code.strip():
        return ["empty output"]
    if resource_name:
        short = resource_name.split("/")[-1].split(":")[-1]
        if resource_name not in code and short not in code and _slug(resource_name) not in code:
            problems.append(f"output does not mention resource {resource_name!r}")
    if fmt in ("cloudformation", "kubernetes"):
        try:
            docs = [d for d in yaml.load_all(code, Loader=_CfnLoader) if d is not None]
            if not docs:
                problems.append("YAML has no documents")
            elif fmt == "kubernetes" and not all(isinstance(d, dict) and "kind" in d for d in docs):
                problems.append("Kubernetes manifest missing 'kind'")
            elif fmt == "cloudformation" and not any(isinstance(d, dict) and "Resources" in d for d in docs):
                problems.append("CloudFormation template missing 'Resources'")
        except yaml.YAMLError as exc:
            problems.append(f"invalid YAML: {exc}")
    else:
        if not _balanced(code):
            problems.append("unbalanced braces")
        if fmt == "terraform" and not re.search(r'^\s*(resource|module|data|locals|variable|provider)\b', code, re.M):
            problems.append("no Terraform block found")
        if fmt == "bicep" and not re.search(r"^\s*(resource|param|module|var|targetScope)\b", code, re.M):
            problems.append("no Bicep declaration found")
    return problems


# ---------------------------------------------------------------- offline templates

def _tpl(f: Finding, fmt: str) -> Optional[str]:
    rid = f.resource.id
    name = f.resource.name or rid
    short = name.split("/")[-1].split(":")[-1]
    s = _slug(name)
    cid = f.canonical_id.upper()
    head = {"terraform": "#", "bicep": "//", "cloudformation": "#", "kubernetes": "#"}[fmt]
    header = f"{head} cloud-posture fix for {cid} on {name}\n{head} {f.title}\n"
    if fmt == "terraform":
        if cid == "S3_PUBLIC_BUCKET":
            return header + f'''resource "aws_s3_bucket_public_access_block" "{s}" {{
  bucket                  = "{short}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
'''
        if cid == "S3_UNENCRYPTED":
            return header + f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{s}" {{
  bucket = "{short}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}
'''
        if cid == "EC2_IMDSV1":
            return header + f'''# Import the instance first: terraform import aws_instance.{s} {short}
resource "aws_instance" "{s}" {{
  # ... existing arguments ...
  metadata_options {{
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }}
}}
'''
        if cid in ("RDS_PUBLIC", "RDS_UNENCRYPTED"):
            body = "  publicly_accessible = false\n" if cid == "RDS_PUBLIC" else (
                "  storage_encrypted = true  # requires snapshot + restore for existing instances\n  kms_key_id        = var.kms_key_arn\n")
            return header + f'''resource "aws_db_instance" "{s}" {{
  identifier = "{short}"
{body}  # ... existing arguments ...
}}
'''
        if cid.startswith("EC2_SG_OPEN"):
            return header + f'''# Replace 0.0.0.0/0 ingress on {short} with a trusted CIDR or SSM Session Manager.
resource "aws_vpc_security_group_ingress_rule" "{s}_restricted" {{
  security_group_id = "{short}"
  cidr_ipv4         = var.trusted_admin_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}}
'''
    if fmt == "kubernetes" and cid in ("K8S_PRIVILEGED_CONTAINER", "K8S_PRIVILEGE_ESCALATION", "K8S_RUN_AS_ROOT", "K8S_HOST_NETWORK", "K8S_HOST_PATH"):
        ns = (f.resource.attributes or {}).get("namespace", "default")
        return header + f'''# Patch for {name}: apply with kubectl patch or merge into the workload manifest.
apiVersion: v1
kind: Pod
metadata:
  name: {short}
  namespace: {ns}
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
'''
    return None


def stub_fix(f: Finding, fmt: str) -> str:
    """Documented, syntactically valid placeholder naming the resource."""
    name = f.resource.name or f.resource.id or "resource"
    short = name.split("/")[-1].split(":")[-1]
    rem = (f.remediation or "See the provider documentation for the secure setting.").replace("\n", " ")
    s = _slug(name)
    if fmt == "terraform":
        return (f"# TODO(cloud-posture): no template for {f.canonical_id} yet.\n# Resource: {name}\n# Remediation: {rem}\n"
                f'locals {{\n  cloud_posture_fix_{s} = "{short}"\n}}\n')
    if fmt == "bicep":
        return (f"// TODO(cloud-posture): no template for {f.canonical_id} yet.\n// Resource: {name}\n// Remediation: {rem}\n"
                f"param targetResourceName string = '{short}'\n")
    if fmt == "cloudformation":
        return (f"# TODO(cloud-posture): no template for {f.canonical_id} yet.\n# Remediation: {rem}\n"
                f"AWSTemplateFormatVersion: '2010-09-09'\nDescription: cloud-posture fix stub for {short}\n"
                f"Resources:\n  CloudPostureFixPlaceholder:\n    Type: AWS::CloudFormation::WaitConditionHandle\n"
                f"    Metadata:\n      TargetResource: '{name}'\n      CanonicalId: {f.canonical_id}\n")
    return (f"# TODO(cloud-posture): no template for {f.canonical_id} yet.\n# Remediation: {rem}\n"
            f"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cloud-posture-fix-{_slug(short).replace('_', '-')}\n"
            f"  annotations:\n    cloud-posture/target: '{name}'\ndata:\n  canonical_id: {f.canonical_id}\n")


def _binary_fix(f: Finding, fmt: str) -> Optional[str]:
    exe = shutil.which("cloud-posture")
    if not exe:
        return None
    try:
        cp = subprocess.run([exe, "fix", "--finding", f.canonical_id, "--format", fmt, "--print"],
                            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cp.stdout if cp.returncode == 0 and cp.stdout.strip() else None


SYSTEM = ("You are an infrastructure-as-code security engineer. Produce a minimal, production-ready fix for the "
          "finding in the requested format. Return exactly one fenced code block followed by a short explanation "
          "(max 6 lines). Reference the affected resource by its real name/ID. Do not invent unrelated resources.")


def generate_fix(finding: Finding, fmt: str = "terraform", current_code: Optional[str] = None,
                 framework: Optional[str] = None, use_llm: bool = True) -> dict[str, Any]:
    fmt = normalize_format(fmt)
    name = finding.resource.name or finding.resource.id
    if use_llm:
        prompt = (f"Format: {fmt}\nFinding:\n{json.dumps({k: v for k, v in finding.to_doc().items() if k != 'raw'}, indent=2, default=str)}\n")
        if framework:
            prompt += f"\nThe fix must satisfy the {framework} controls mapped on the finding.\n"
        if current_code:
            prompt += f"\nCurrent code to patch (return the patched version):\n```\n{current_code}\n```\n"
        text = complete(SYSTEM, prompt, max_tokens=8000, effort="medium")
        if text:
            code = extract_code(text)
            problems = validate_fix(code, fmt, name)
            if not problems:
                expl = text.split("```")[-1].strip() or "Generated by Claude."
                return {"code": code, "explanation": expl, "format": fmt, "mode": "llm", "problems": []}
    code = _binary_fix(finding, fmt)
    mode = "cloud-posture"
    if code is None:
        code = _tpl(finding, fmt)
        mode = "template"
    if code is None:
        code = stub_fix(finding, fmt)
        mode = "stub"
    expl = {
        "cloud-posture": "Generated by the cloud-posture remediation templates.",
        "template": f"Built-in nimbus template for {finding.canonical_id}. Review, merge into your IaC and plan before applying.",
        "stub": ("No template exists for this check yet; this stub names the resource and the remediation guidance. "
                 "Set ANTHROPIC_API_KEY for an AI-generated fix, or install the cloud-posture binary."),
    }[mode]
    if finding.remediation:
        expl += f"\nRemediation: {finding.remediation}"
    return {"code": code, "explanation": expl, "format": fmt, "mode": mode, "problems": validate_fix(code, fmt, name)}
