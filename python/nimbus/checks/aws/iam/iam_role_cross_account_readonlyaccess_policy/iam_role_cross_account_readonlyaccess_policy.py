"""Ensure IAM roles do not have ReadOnlyAccess policy with cross-account trust (CIS AWS 3.0 1.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class IamRoleCrossAccountReadonlyaccessPolicy(Check):
    def execute(self, ctx) -> list[CheckResult]:
        iam = ctx.client("iam")
        ro_arn = f"arn:{ctx.partition}:iam::aws:policy/ReadOnlyAccess"
        out = []
        for role in lib.iam_roles(ctx):
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            name = role["RoleName"]
            attached = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])]
            if ro_arn not in attached:
                out.append(CheckResult("PASS", f"IAM role {name} does not have the ReadOnlyAccess policy attached.", name, role["Arn"], name, ctx.home_region))
                continue
            trust = lib.normalize_document(role.get("AssumeRolePolicyDocument") or {})
            external = []
            for st in lib.statements(trust):
                if st.get("Effect") != "Allow":
                    continue
                principal = st.get("Principal")
                aws = lib.as_list(principal.get("AWS")) if isinstance(principal, dict) else lib.as_list(principal)
                for p in aws:
                    p = str(p)
                    acct = p.split(":")[4] if p.startswith("arn:") and len(p.split(":")) > 4 else p
                    if p == "*" or acct != ctx.account_id:
                        external.append(p)
            if external:
                out.append(CheckResult("FAIL", f"IAM role {name} has ReadOnlyAccess and trusts external principal(s): {', '.join(external)}.",
                                       name, role["Arn"], name, ctx.home_region, {"external_principals": external}, external))
            else:
                out.append(CheckResult("PASS", f"IAM role {name} has ReadOnlyAccess but is not assumable cross-account.", name, role["Arn"], name, ctx.home_region))
        return out
