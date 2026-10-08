import re

from nimbus.checks.base import CheckResult, fingerprint, map_resource_type
from nimbus.checks.registry import all_checks, get_check

REQUIRED = {"id": str, "source": str, "check_id": str, "canonical_id": str, "title": str, "description": str, "severity": str,
            "status": str, "provider": str, "account": str, "region": str, "resource": dict, "remediation": str,
            "weaknesses": list, "compliance": dict, "tags": dict, "first_seen": str, "last_seen": str}
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _finding(check_id="s3_bucket_public_access", status="FAIL"):
    check = get_check(check_id)
    res = CheckResult(status, "bucket is public", "my-bucket", "arn:aws:s3:::my-bucket", "my-bucket", "us-east-1", {"k": "v"}, ["arn:x"])
    return check.to_finding(res, "123456789012")


def test_to_finding_has_contract_keys_and_types():
    f = _finding()
    for key, typ in REQUIRED.items():
        assert key in f, key
        assert isinstance(f[key], typ), (key, type(f[key]))
    assert f["source"] == "nimbus" and f["provider"] == "aws" and f["canonical_id"] == ""
    assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert f["status"] == "FAIL"
    assert f["resource"] == {"id": "arn:aws:s3:::my-bucket", "type": "aws_s3_bucket", "name": "my-bucket", "attributes": {"k": "v"}, "related": ["arn:x"]}
    assert f["compliance"]["cis_aws"] == ["2.1.4"]
    assert f["tags"]["cis_control"] == "2.1.4" and f["tags"]["service"] == "s3"
    assert all(isinstance(v, str) for v in f["tags"].values())
    assert ISO.match(f["first_seen"]) and ISO.match(f["last_seen"])
    assert f["id"] == fingerprint("nimbus", "s3_bucket_public_access", "aws", "123456789012", "us-east-1", "arn:aws:s3:::my-bucket")
    assert re.fullmatch(r"[0-9a-f]{32}", f["id"])
    assert f["remediation"] and f["description"]


def test_manual_maps_to_skip():
    assert _finding(status="MANUAL")["status"] == "SKIP"
    assert _finding(status="PASS")["status"] == "PASS"


def test_all_checks_produce_valid_findings_and_resource_types():
    for check in all_checks():
        f = check.to_finding(CheckResult("PASS", "ok", "rid", region="us-east-1"), "111111111111")
        assert f["check_id"] == check.check_id
        assert f["resource"]["id"] == "rid" and f["resource"]["name"] == "rid"
        assert re.fullmatch(r"aws_[a-z0-9_]+", f["resource"]["type"]), f["resource"]["type"]
        assert f["severity"] == check.severity.upper()


def test_resource_type_mapping():
    assert map_resource_type("AwsEc2Instance") == "aws_instance"
    assert map_resource_type("AwsRdsDbInstance") == "aws_db_instance"
    assert map_resource_type("AwsEc2Volume") == "aws_ebs_volume"
    assert map_resource_type("AwsSomethingNew") == "aws_something_new"


def test_invalid_status_rejected():
    import pytest

    with pytest.raises(ValueError):
        CheckResult("BROKEN")
