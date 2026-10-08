from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from nimbus.models import Finding
from nimbus.store import Store

NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Never call the Anthropic API from tests."""
    monkeypatch.setenv("NIMBUS_OFFLINE", "1")
    monkeypatch.delenv("CLOUD_POSTURE_DASHBOARD_HTML", raising=False)


def F(**kw) -> Finding:
    base = dict(source="prowler", severity="HIGH", status="FAIL", provider="aws", account="111111111111", region="us-east-1")
    base.update(kw)
    return Finding.model_validate(base).finalize(NOW)


def sample_findings() -> list[Finding]:
    return [
        F(check_id="s3_bucket_public_access", canonical_id="S3_PUBLIC_BUCKET", title="S3 bucket allows public access",
          resource={"id": "arn:aws:s3:::customer-pii", "type": "aws_s3_bucket", "name": "customer-pii"},
          weaknesses=["PUBLIC_DATA_STORE"], compliance={"cis_aws": ["2.1.4"], "pci_dss": ["1.3.1"], "gdpr": ["Art.32"]},
          remediation="Enable S3 Block Public Access.", raw={"StatusExtended": "Bucket customer-pii has a public ACL", "x": "y" * 900}),
        F(check_id="s3_bucket_default_encryption", canonical_id="S3_UNENCRYPTED", title="S3 bucket has no default encryption", severity="MEDIUM",
          resource={"id": "arn:aws:s3:::customer-pii", "type": "aws_s3_bucket", "name": "customer-pii"},
          weaknesses=["UNENCRYPTED_AT_REST"], compliance={"cis_aws": ["2.1.1"], "hipaa": ["164.312(a)(2)(iv)"]}),
        F(check_id="rds_instance_no_public_access", canonical_id="RDS_PUBLIC", title="RDS instance is publicly accessible", severity="CRITICAL",
          resource={"id": "arn:aws:rds:us-east-1:111111111111:db:orders", "type": "aws_db_instance", "name": "orders"},
          weaknesses=["PUBLIC_NETWORK_EXPOSURE", "DATABASE"], compliance={"cis_aws": ["2.3.3"], "pci_dss": ["1.3.6"]}),
        F(check_id="rds_instance_storage_encrypted", canonical_id="RDS_UNENCRYPTED", title="RDS storage not encrypted",
          resource={"id": "arn:aws:rds:us-east-1:111111111111:db:orders", "type": "aws_db_instance", "name": "orders"},
          weaknesses=["UNENCRYPTED_AT_REST", "DATABASE"], compliance={"cis_aws": ["2.3.1"]}),
        F(check_id="iam_user_mfa_enabled_console_access", canonical_id="IAM_USER_NO_MFA", title="IAM user with console access has no MFA",
          resource={"id": "arn:aws:iam::111111111111:user/alice", "type": "aws_iam_user", "name": "alice"},
          weaknesses=["NO_MFA"], compliance={"cis_aws": ["1.10"]}),
        F(check_id="iam_user_mfa_enabled_console_access", canonical_id="IAM_USER_NO_MFA", title="IAM user with console access has no MFA",
          status="PASS", resource={"id": "arn:aws:iam::111111111111:user/bob", "type": "aws_iam_user", "name": "bob"},
          weaknesses=["NO_MFA"], compliance={"cis_aws": ["1.10"]}),
        F(check_id="iam_rotate_access_key_90_days", canonical_id="IAM_STALE_KEYS", title="IAM access key unused or older than 90 days",
          severity="MEDIUM", resource={"id": "arn:aws:iam::111111111111:user/deploy/AKIAOLD", "type": "aws_iam_access_key", "name": "deploy"},
          weaknesses=["STALE_CREDENTIALS"], compliance={"cis_aws": ["1.14"]}),
        F(check_id="iam_policy_no_administrative_privileges", canonical_id="IAM_ADMIN_POLICY", title="IAM policy grants full administrative privileges (*:*)",
          resource={"id": "arn:aws:iam::111111111111:user/deploy", "type": "aws_iam_user", "name": "deploy"},
          weaknesses=["OVERPRIVILEGED_IDENTITY"], compliance={"cis_aws": ["1.16"]}),
        F(check_id="ec2_instance_imdsv2_enabled", canonical_id="EC2_IMDSV1", title="EC2 instance allows IMDSv1",
          resource={"id": "i-0abc", "type": "aws_instance", "name": "web-1"}, weaknesses=["IMDSV1_ENABLED"], compliance={"cis_aws": ["5.6"]}),
        F(check_id="ec2_instance_public_ip", canonical_id="EC2_PUBLIC_IP", title="EC2 instance has a public IP address", severity="MEDIUM",
          resource={"id": "i-0abc", "type": "aws_instance", "name": "web-1"}, weaknesses=["PUBLIC_NETWORK_EXPOSURE"]),
        F(source="checkov", check_id="CKV_K8S_16", canonical_id="K8S_PRIVILEGED_CONTAINER", title="Privileged container", provider="kubernetes",
          account="prod-cluster", region="", resource={"id": "k8s:payments/api-0", "type": "k8s_pod", "name": "api-0", "attributes": {"namespace": "payments"}},
          weaknesses=["PRIVILEGED_CONTAINER"], compliance={"cis_k8s": ["5.2.2"]}),
        F(source="trivy", check_id="AVD-AWS-0001", canonical_id="TRIVY:LOW_THING", title="Low thing", severity="LOW", provider="gcp",
          account="proj-dev", resource={"id": "gcp:bucket/logs", "type": "gcp_storage_bucket", "name": "logs-dev"}, weaknesses=["NO_LOGGING"]),
    ]


def sample_paths(findings: list[Finding]) -> list[dict]:
    by = {f.canonical_id: f for f in findings}
    pub, enc = by["RDS_PUBLIC"], by["RDS_UNENCRYPTED"]
    web, imds, admin = by["EC2_PUBLIC_IP"], by["EC2_IMDSV1"], by["IAM_ADMIN_POLICY"]
    return [
        {"id": "ap-db", "rule_id": "PUBLIC_DATABASE_BREACH", "name": "Internet-reachable database holding unencrypted data",
         "impact": "Direct database compromise and data theft", "mitre": ["T1190", "T1213"], "provider": "aws", "account": "111111111111",
         "score": 9.5, "severity": "CRITICAL", "narrative": "orders is public and unencrypted",
         "steps": [{"stage": 1, "finding_id": pub.id, "weakness": "PUBLIC_NETWORK_EXPOSURE", "relation": "", "resource": pub.resource.id, "title": pub.title, "summary": "reach db"},
                   {"stage": 2, "finding_id": enc.id, "weakness": "UNENCRYPTED_AT_REST", "relation": "same_resource", "resource": enc.resource.id, "title": enc.title, "summary": "read data"}],
         "finding_ids": [pub.id, enc.id]},
        {"id": "ap-admin", "rule_id": "INTERNET_TO_ACCOUNT_ADMIN", "name": "Internet-exposed compute to account admin via metadata credentials",
         "impact": "Full cloud account compromise", "mitre": ["T1190", "T1552.005"], "provider": "aws", "account": "111111111111",
         "score": 8.0, "severity": "CRITICAL", "narrative": "web-1 -> IMDSv1 -> admin",
         "steps": [{"stage": 1, "finding_id": web.id, "weakness": "PUBLIC_NETWORK_EXPOSURE", "relation": "", "resource": "i-0abc", "title": web.title, "summary": ""},
                   {"stage": 2, "finding_id": imds.id, "weakness": "IMDSV1_ENABLED", "relation": "related", "resource": "i-0abc", "title": imds.title, "summary": ""},
                   {"stage": 3, "finding_id": admin.id, "weakness": "OVERPRIVILEGED_IDENTITY", "relation": "same_account", "resource": admin.resource.id, "title": admin.title, "summary": ""}],
         "finding_ids": [web.id, imds.id, admin.id]},
    ]


def sample_graph() -> tuple[list[dict], list[dict]]:
    recent = (NOW - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    nodes = [
        {"id": "internet", "type": "internet", "class": "internet", "name": "Internet", "provider": "any"},
        {"id": "arn:aws:s3:::customer-pii", "type": "aws_s3_bucket", "class": "datastore", "name": "customer-pii", "provider": "aws",
         "account": "111111111111", "sensitive": True, "criticality": "production", "owner": "data-team"},
        {"id": "arn:aws:rds:us-east-1:111111111111:db:orders", "type": "aws_db_instance", "class": "datastore", "name": "orders",
         "provider": "aws", "account": "111111111111", "sensitive": True, "criticality": "production", "modified_at": recent},
        {"id": "i-0abc", "type": "aws_instance", "class": "compute", "name": "web-1", "provider": "aws", "account": "111111111111",
         "criticality": "production", "cve_count": 12},
        {"id": "arn:aws:iam::111111111111:role/web", "type": "aws_iam_role", "class": "identity", "name": "web-role", "provider": "aws",
         "account": "111111111111"},
        {"id": "gcp:bucket/logs", "type": "gcp_storage_bucket", "class": "datastore", "name": "logs-dev", "provider": "gcp",
         "account": "proj-dev", "criticality": "dev", "owner": "ops"},
    ]
    edges = [
        {"from": "internet", "to": "i-0abc", "kind": "allows_traffic_to"},
        {"from": "internet", "to": "arn:aws:rds:us-east-1:111111111111:db:orders", "kind": "allows_traffic_to"},
        {"from": "internet", "to": "arn:aws:s3:::customer-pii", "kind": "exposes"},
        {"from": "i-0abc", "to": "arn:aws:iam::111111111111:role/web", "kind": "runs_as"},
        {"from": "arn:aws:iam::111111111111:role/web", "to": "arn:aws:s3:::customer-pii", "kind": "grants_access_to"},
        {"from": "arn:aws:iam::111111111111:role/web", "to": "arn:aws:rds:us-east-1:111111111111:db:orders", "kind": "grants_access_to"},
    ]
    return nodes, edges


@pytest.fixture
def findings() -> list[Finding]:
    return sample_findings()


@pytest.fixture
def seeded(tmp_path) -> Store:
    s = Store(tmp_path / "posture.db")
    fs = sample_findings()
    for f in fs:
        f.scan_id = "scan-1"
    s.upsert_findings(fs)
    s.replace_attack_paths(sample_paths(fs), scan_id="scan-1")
    nodes, edges = sample_graph()
    s.replace_graph(nodes, edges)
    s.save_scan({"scan_id": "scan-1", "started_at": NOW - timedelta(minutes=5), "finished_at": NOW, "accounts": ["111111111111"],
                 "total": len(fs), "failed": sum(f.status.value == "FAIL" for f in fs), "attack_paths": 2})
    return s
