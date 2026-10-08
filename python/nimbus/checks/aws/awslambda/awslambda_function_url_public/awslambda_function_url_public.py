"""Check Lambda Function URL is not publicly accessible (AuthType NONE) (CIS AWS 3.0 1.16)."""

from __future__ import annotations

from nimbus.checks.aws import lib
from nimbus.checks.base import Check, CheckResult


class AwslambdaFunctionUrlPublic(Check):
    def execute(self, ctx) -> list[CheckResult]:
        def per_region(region):
            lam = ctx.client("lambda", region)
            out = []
            for fn in lib.describe_all(lam, "list_functions", "Functions"):
                name, arn = fn["FunctionName"], fn["FunctionArn"]
                try:
                    urls = [lam.get_function_url_config(FunctionName=name)]
                except lib.ClientError as exc:
                    if lib.error_code(exc) not in ("ResourceNotFoundException",):
                        raise
                    urls = []
                if not urls:
                    out.append(CheckResult("PASS", f"Lambda function {name} does not have a function URL.", name, arn, name, region, {"runtime": fn.get("Runtime")}))
                    continue
                public = [u.get("FunctionUrl") for u in urls if u.get("AuthType") == "NONE"]
                if public:
                    out.append(CheckResult("FAIL", f"Lambda function {name} has a public function URL with AuthType NONE ({', '.join(public)}).", name, arn, name, region, {"function_urls": public, "role": fn.get("Role")}, [fn.get("Role")] if fn.get("Role") else []))
                else:
                    out.append(CheckResult("PASS", f"Lambda function {name} function URL requires AWS_IAM authentication.", name, arn, name, region))
            return out

        return lib.regional_results(ctx, per_region)
