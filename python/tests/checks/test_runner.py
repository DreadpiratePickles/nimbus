from nimbus.checks import runner
from nimbus.checks.base import CheckResult
from nimbus.checks.registry import get_check


class FakeCtx:
    account_id = "123456789012"
    home_region = "us-east-1"


def test_exception_in_check_yields_error_finding(monkeypatch):
    boom = get_check("iam_root_mfa_enabled")
    ok = get_check("s3_account_level_public_access_blocks")

    def explode(ctx):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(boom, "execute", explode)
    monkeypatch.setattr(ok, "execute", lambda ctx: [CheckResult("PASS", "fine", "acct", region="us-east-1")])
    findings = runner.run(FakeCtx(), [boom, ok], workers=2)
    assert [f["check_id"] for f in findings] == ["iam_root_mfa_enabled", "s3_account_level_public_access_blocks"]
    err = findings[0]
    assert err["status"] == "ERROR"
    assert "kaboom" in err["resource"]["attributes"]["error"]
    assert err["account"] == "123456789012"
    assert findings[1]["status"] == "PASS"


def test_run_against_moto_end_to_end(ctx):
    from nimbus.checks.registry import filter_checks

    ctx.client("s3").create_bucket(Bucket="e2e-bucket")
    checks = filter_checks(services="s3,ec2,cloudtrail")
    findings = runner.run(ctx, checks, workers=4)
    assert findings
    errors = [f for f in findings if f["status"] == "ERROR"]
    assert not errors, errors[:1]
    assert {f["account"] for f in findings} == {"123456789012"}
    assert any(f["resource"]["id"] == "arn:aws:s3:::e2e-bucket" and f["status"] == "FAIL" for f in findings)
