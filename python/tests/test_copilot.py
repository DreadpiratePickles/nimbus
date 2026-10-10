import pytest

from nimbus.ai.copilot import SecurityCopilot, generate_policy, rule_based_sql
from nimbus.ai.sqlsafety import UnsafeSQL, sanitize


@pytest.fixture
def cp(seeded):
    return SecurityCopilot(seeded, use_llm=False)


def names(res, col="resource_name"):
    i = res["columns"].index(col)
    return {r[i] for r in res["rows"]}


def test_public_buckets(cp):
    res = cp.ask("Which S3 buckets are public?")
    assert res["intent"] == "public_buckets" and res["mode"] == "offline"
    assert names(res) == {"customer-pii"}
    assert "LIMIT 200" in res["sql"] and "customer-pii" in res["answer"]


def test_public_databases_and_instances(cp):
    assert names(cp.ask("show me public databases")) == {"orders"}
    assert names(cp.ask("internet exposed instances in aws")) == {"web-1"}


def test_unencrypted(cp):
    res = cp.ask("list unencrypted databases")
    assert res["intent"] == "unencrypted" and names(res) == {"orders"}
    assert names(cp.ask("unencrypted buckets")) == {"customer-pii"}


def test_users_without_mfa(cp):
    res = cp.ask("users without MFA")
    assert res["intent"] == "no_mfa" and names(res) == {"alice"}


def test_attack_paths_to_rds(cp):
    res = cp.ask("attack paths to RDS")
    assert res["intent"] == "attack_paths"
    assert names(res, "id") == {"ap-db"}


def test_top_risks_and_grouping(cp):
    res = cp.ask("what are my top risks?")
    assert res["intent"] == "top_risks" and res["rows"][0][2] == "CRITICAL"
    res = cp.ask("findings by account")
    assert res["intent"] == "findings_by_account"
    counts = {r[0]: r[1] for r in res["rows"]}
    assert counts["111111111111"] == 9 and counts["prod-cluster"] == 1
    assert cp.ask("count findings by provider")["intent"] == "findings_by_provider"
    assert cp.ask("show critical findings")["intent"] == "findings_by_severity"


def test_stale_keys_privileged_pods(cp):
    assert names(cp.ask("stale access keys")) == {"deploy"}
    res = cp.ask("privileged pods")
    assert res["intent"] == "privileged_pods" and res["rows"][0][0] == "payments"


def test_compliance_status_for_control(cp):
    res = cp.ask("compliance status for CIS 1.10")
    assert res["intent"] == "compliance_control_status"
    row = dict(zip(res["columns"], res["rows"][0]))
    assert row["control_id"] == "1.10" and row["status"] == "FAIL" and row["failed"] == 1 and row["passed"] == 1
    res = cp.ask("what is the status of soc2 control CC6.2?")
    row = dict(zip(res["columns"], res["rows"][0]))
    assert row["control_id"] == "CC6.2" and row["status"] == "FAIL"  # derived from NO_MFA / STALE_CREDENTIALS


def test_unknown_question(cp):
    res = cp.ask("tell me a joke")
    assert res["intent"] == "unknown" and not res["rows"]
    assert rule_based_sql("bananas") is None


@pytest.mark.parametrize("bad", [
    "DELETE FROM findings",
    "SELECT 1; DROP TABLE findings",
    "select * from findings; select 2",
    "WITH x AS (SELECT 1) INSERT INTO findings SELECT * FROM x",
    "PRAGMA table_info(findings)",
    "ATTACH DATABASE '/tmp/x.db' AS x",
    "UPDATE findings SET status='PASS'",
    "",
    "-- just a comment",
    "REPLACE INTO findings VALUES (1)",
])
def test_sql_safety_rejections(bad):
    with pytest.raises(UnsafeSQL):
        sanitize(bad)


def test_sql_sanitize_accepts_and_limits():
    assert sanitize("SELECT * FROM findings -- trailing\n;") == "SELECT * FROM findings\nLIMIT 200"
    assert sanitize("select 'a;b' as x /* c */").endswith("LIMIT 200")
    assert sanitize("SELECT * FROM findings LIMIT 10") == "SELECT * FROM findings LIMIT 10"
    assert sanitize("SELECT * FROM findings LIMIT 5000").startswith("SELECT * FROM (")
    assert "DELETE" not in sanitize("SELECT 'delete me' AS note")  .upper().replace("'DELETE ME'", "")


def test_copilot_rejects_unsafe_sql(cp):
    with pytest.raises(UnsafeSQL):
        cp.run_sql("DROP TABLE findings", origin="llm")


def test_investigate_blast_radius(cp, seeded):
    imds = seeded.findings(canonical_id="EC2_IMDSV1")[0]
    res = cp.investigate(imds.id)
    assert [p["id"] for p in res["attack_paths"]] == ["ap-admin"]
    sens = {r["name"] for r in res["blast_radius"]["sensitive"]}
    assert sens == {"customer-pii", "orders"}
    hops = {r["name"]: r["hops"] for r in res["blast_radius"]["reachable"]}
    assert hops["web-role"] == 1 and hops["orders"] == 2
    assert res["explanation"].startswith("An attacker could")
    assert any(r["canonical_id"] == "EC2_PUBLIC_IP" for r in res["related_findings"])
    with pytest.raises(KeyError):
        cp.investigate("nope")


def test_remediation_guidance(cp):
    g = cp.remediation_guidance("s3_public_bucket")
    assert g["title"] == "S3 bucket allows public access" and g["open_findings"] == 1
    assert "cloud-posture fix --finding S3_PUBLIC_BUCKET" in g["guidance"]


@pytest.mark.parametrize("req,tpl,needle", [
    ("deny public S3 buckets", "public_s3", "aws_s3_bucket_public_access_block"),
    ("block security groups open to 0.0.0.0/0 on ssh", "open_security_group", "admin_ports"),
    ("require IMDSv2 on instances", "imdsv1", "http_tokens"),
    ("no privileged pods", "privileged_pod", "privileged"),
    ("RDS storage must be encrypted - unencrypted RDS not allowed", "unencrypted_rds", "storage_encrypted"),
    ("users must have MFA", "no_mfa", "mfa_active"),
    ("deny public RDS instances", "public_rds", "publicly_accessible"),
    ("forbid cluster-admin bindings", "cluster_admin_binding", "cluster-admin"),
])
def test_policy_generation_offline(req, tpl, needle):
    res = generate_policy(req, use_llm=False)
    assert res["template"] == tpl and res["mode"] == "offline"
    assert res["policy"].lstrip().startswith("#") and "package nimbus." in res["policy"] and needle in res["policy"]
    assert "import rego.v1" in res["policy"]


def test_policy_no_match():
    res = generate_policy("make coffee", use_llm=False)
    assert res["policy"] == "" and "Available" in res["notes"]
