import sqlite3

import pytest

from nimbus.store import Store, view_name


def test_round_trip_and_views(seeded: Store):
    fs = seeded.findings()
    assert len(fs) == 12
    assert fs[0].severity.value == "CRITICAL"  # severity ordering like Go
    one = seeded.finding(fs[0].id)
    assert one is not None and one.to_doc() == fs[0].to_doc()
    assert len(seeded.findings(status="PASS")) == 1
    assert {f.provider for f in seeded.findings(provider="kubernetes")} == {"kubernetes"}
    assert len(seeded.findings(min_severity="HIGH")) == len([f for f in fs if f.severity.rank >= 4])
    assert seeded.findings(canonical_id="s3_public_bucket")[0].canonical_id == "S3_PUBLIC_BUCKET"

    views = seeded.views()
    for v in ("aws_s3_buckets", "aws_db_instances", "aws_iam_users", "k8s_pods", "findings_summary", "attack_path_summary",
              "compliance_controls", "cis_aws_benchmark", "soc2", "iso_27001"):
        assert v in views, v
    cols, rows = seeded.query("SELECT name, public_access, encrypted, open_findings FROM aws_s3_buckets")
    assert cols == ["name", "public_access", "encrypted", "open_findings"]
    assert rows == [["customer-pii", 1, 0, 2]]
    cols, rows = seeded.query("SELECT entry_point, target, path_length FROM attack_path_summary WHERE id = 'ap-admin'")
    assert rows[0] == ["i-0abc", "arn:aws:iam::111111111111:user/deploy", 3]
    cols, rows = seeded.query("SELECT control_id, status, failed, passed FROM cis_aws_benchmark WHERE control_id = '1.10'")
    assert rows == [["1.10", "FAIL", 1, 1]]

    # raw columns written like Go
    cols, rows = seeded.query("SELECT weaknesses, compliance, resource_type, first_seen FROM findings WHERE canonical_id='K8S_PRIVILEGED_CONTAINER'")
    assert rows[0][0] == '["PRIVILEGED_CONTAINER"]' and rows[0][2] == "k8s_pod" and rows[0][3].endswith("Z")


def test_read_only_query(seeded: Store):
    with pytest.raises(sqlite3.OperationalError):
        seeded.query("DELETE FROM findings")
    assert len(seeded.findings()) == 12


def test_upsert_keeps_first_seen(seeded: Store):
    f = seeded.findings(canonical_id="EC2_IMDSV1")[0]
    first = f.first_seen
    f2 = f.model_copy(deep=True)
    from datetime import datetime, timedelta, timezone
    f2.first_seen = datetime.now(timezone.utc) + timedelta(days=1)
    f2.title = "changed"
    seeded.upsert_findings([f2])
    got = seeded.finding(f.id)
    assert got.title == "changed" and got.first_seen == first


def test_graph_scans_schema(seeded: Store):
    nodes, edges = seeded.graph()
    assert any(n["id"] == "internet" for n in nodes)
    assert {"from": "internet", "to": "i-0abc", "kind": "allows_traffic_to", "attr": {}} in edges
    assert seeded.last_scan().scan_id == "scan-1"
    txt = seeded.schema_text()
    assert "TABLE findings(" in txt and "VIEW aws_s3_buckets(" in txt


def test_view_name():
    assert view_name("aws_s3_bucket") == "aws_s3_buckets"
    assert view_name("Microsoft.Compute/virtualMachines") == "microsoft_compute_virtualmachines"
    assert view_name("k8s_pods") == "k8s_pods"
