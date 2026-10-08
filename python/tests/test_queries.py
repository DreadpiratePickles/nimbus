import pytest

from nimbus import queries as q
from nimbus.ai.sqlsafety import UnsafeSQL


def test_index_complete():
    names = {x["name"] for x in q.index()}
    assert names == {"public_buckets_with_pii", "attack_paths_to_databases", "cis_control_status", "cross_cloud_internet_exposed_compute",
                     "stale_keys_with_admin", "k8s_privileged_pods_by_namespace", "unencrypted_datastores_by_provider",
                     "top_risky_accounts", "findings_trend_by_scan", "compliance_score_per_framework"}
    for x in q.index():
        assert x["description"] and isinstance(x["frameworks"], list) and x["sql_text"].strip()


def test_every_named_query_runs(seeded):
    for x in q.index():
        cols, rows = q.run_named(seeded, x["name"])
        assert cols, x["name"]


def test_named_query_results(seeded):
    _, rows = q.run_named(seeded, "public_buckets_with_pii")
    assert rows[0][1] == "customer-pii"
    _, rows = q.run_named(seeded, "attack_paths_to_databases")
    assert [r[0] for r in rows] == ["ap-db"]
    _, rows = q.run_named(seeded, "cross_cloud_internet_exposed_compute")
    assert [(r[0], r[2]) for r in rows] == [("aws", "web-1")]
    _, rows = q.run_named(seeded, "stale_keys_with_admin")
    assert rows and rows[0][5] == "arn:aws:iam::111111111111:user/deploy"
    cols, rows = q.run_named(seeded, "k8s_privileged_pods_by_namespace")
    assert rows[0][:3] == ["payments", "prod-cluster", 1]
    cols, rows = q.run_named(seeded, "top_risky_accounts")
    assert rows[0][1] == "111111111111"
    cols, rows = q.run_named(seeded, "findings_trend_by_scan")
    assert rows[0][0] == "scan-1" and rows[0][-1] == 12
    cols, rows = q.run_named(seeded, "cis_control_status")
    assert any(r[1] == "1.10" for r in rows)


def test_adhoc_and_unknown(seeded):
    cols, rows = q.run_sql(seeded, "SELECT COUNT(*) AS n FROM findings")
    assert rows == [[12]]
    with pytest.raises(UnsafeSQL):
        q.run_sql(seeded, "DROP TABLE findings")
    with pytest.raises(KeyError):
        q.run_named(seeded, "nope")
