import hashlib
import json

from nimbus.models import AttackPath, Finding, load_findings, parse_severity, parse_status


def test_fingerprint_matches_go_algorithm():
    f = Finding(source="prowler", check_id="s3_bucket_public_access", provider="aws", account="123456789012",
                region="us-east-1", resource={"id": "arn:aws:s3:::my-bucket"}, file="")
    key = "prowler|s3_bucket_public_access|aws|123456789012|us-east-1|arn:aws:s3:::my-bucket|"
    expected = hashlib.sha256(key.encode()).digest()[:16].hex()
    assert f.fingerprint() == expected
    # hard-coded value (sha256 of the key above, first 16 bytes) - same as Go's model.Finding.Fingerprint
    assert expected == "6fcb411f62a54ae57d2995b1cf975393"
    assert f.fingerprint() == "6fcb411f62a54ae57d2995b1cf975393"
    assert len(f.fingerprint()) == 32


def test_fingerprint_hardcoded_vector():
    f = Finding(source="checkov", check_id="CKV_AWS_20", provider="iac", account="", region="",
                resource={"id": "aws_s3_bucket.data"}, file="main.tf")
    assert f.fingerprint() == hashlib.sha256(b"checkov|CKV_AWS_20|iac|||aws_s3_bucket.data|main.tf").hexdigest()[:32]


def test_finalize_defaults_like_go():
    f = Finding(source="okta-plugin", check_id="x_check", resource={"id": "u1"}).finalize()
    assert f.canonical_id == "OKTA-PLUGIN:x_check"
    assert f.provider == "unknown"
    assert f.severity.value == "INFO" and f.status.value == "FAIL"
    assert f.resource.name == "u1"
    assert f.id == f.fingerprint()
    assert f.first_seen is not None and f.last_seen is not None


def test_round_trip_go_json_with_omitempty_and_nanos():
    go_json = json.dumps({
        "id": "abc", "source": "prowler", "check_id": "c", "canonical_id": "S3_PUBLIC_BUCKET", "title": "t", "severity": "HIGH",
        "status": "FAIL", "provider": "aws", "account": "1", "resource": {"id": "r", "type": "aws_s3_bucket", "name": "r"},
        "first_seen": "2024-05-01T10:00:00.123456789Z", "last_seen": "0001-01-01T00:00:00Z", "raw": {"a": 1},
    })
    f = Finding.model_validate_json(go_json)
    assert f.first_seen.microsecond == 123456
    assert f.last_seen is None
    doc = f.to_doc()
    assert "description" not in doc and "region" not in doc and "weaknesses" not in doc
    assert doc["last_seen"] == "0001-01-01T00:00:00Z"
    assert doc["first_seen"] == "2024-05-01T10:00:00.123456Z"
    assert doc["raw"] == {"a": 1}


def test_parsers_and_loaders():
    assert parse_severity("danger").value == "CRITICAL"
    assert parse_severity("warning").value == "HIGH"
    assert parse_status("ok").value == "PASS"
    assert parse_status("muted").value == "SKIP"
    assert parse_status("weird").value == "ERROR"
    lines = '{"source":"a","check_id":"b","severity":"low"}\n{"source":"a","check_id":"c"}\n'
    fs = load_findings(lines)
    assert [f.check_id for f in fs] == ["b", "c"] and fs[0].severity.value == "LOW"
    p = AttackPath.model_validate({"id": "p", "severity": "critical", "steps": [{"stage": 1, "finding_id": "x"}]})
    assert p.severity.value == "CRITICAL" and p.steps[0].finding_id == "x"
