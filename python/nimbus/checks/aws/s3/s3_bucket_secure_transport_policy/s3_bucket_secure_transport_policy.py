"""Ensure S3 Bucket Policy is set to deny HTTP requests (CIS AWS 3.0 2.1.1)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class S3BucketSecureTransportPolicy(Check):
    def execute(self, ctx) -> list[CheckResult]:
        out = []
        for b in lib.s3_buckets(ctx):
            name, arn, region = b["Name"], b["Arn"], b["Region"]

            policy = lib.bucket_policy(ctx, b)
            ok = False
            for st in lib.statements(policy or {}):
                if st.get("Effect") != "Deny" or not lib._principal_is_public(st.get("Principal")):
                    continue
                acts = [str(a) for a in lib.as_list(st.get("Action"))]
                if not any(a in ("*", "s3:*", "s3:GetObject", "s3:PutObject") for a in acts):
                    continue
                cond = st.get("Condition", {}) or {}
                for op in ("Bool", "BoolIfExists"):
                    val = cond.get(op, {}).get("aws:SecureTransport")
                    if str(val).lower() in ("false", "['false']"):
                        ok = True
                num = cond.get("NumericLessThan", {}).get("s3:TlsVersion")
                if num is not None:
                    ok = True
            if ok:
                out.append(CheckResult("PASS", f"S3 bucket {name} has a bucket policy denying insecure (HTTP) transport.", name, arn, name, region))
            elif policy is None:
                out.append(CheckResult("FAIL", f"S3 bucket {name} does not have a bucket policy, so HTTP requests are not denied.", name, arn, name, region))
            else:
                out.append(CheckResult("FAIL", f"S3 bucket {name} bucket policy does not deny HTTP requests (aws:SecureTransport=false).", name, arn, name, region))
        return out
