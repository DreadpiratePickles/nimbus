import json
import re
from pathlib import Path

import nimbus.checks
from nimbus.checks.registry import all_checks, filter_checks

CHECKS_ROOT = Path(nimbus.checks.__file__).parent / "aws"
REQUIRED = ["Provider", "CheckID", "CheckTitle", "CheckType", "ServiceName", "SubServiceName", "ResourceIdTemplate", "Severity",
            "ResourceType", "Description", "Risk", "RelatedUrl", "Remediation", "Categories", "DependsOn", "RelatedTo", "Notes", "Compliance"]
FRAMEWORKS = ["cis_aws", "nist_800_53", "pci_dss", "hipaa", "gdpr", "soc2"]
CIS_30 = re.compile(r"^(1\.([1-9]|1[0-9]|2[0-2])|2\.1\.[1-4]|2\.2\.1|2\.3\.[1-3]|2\.4\.1|3\.[1-9]|4\.([1-9]|1[0-6])|5\.[1-6])$")
MANDATORY = """iam_root_mfa_enabled iam_root_hardware_mfa_enabled iam_no_root_access_key iam_avoid_root_usage iam_user_mfa_enabled_console_access
iam_rotate_access_key_90_days iam_user_accesskey_unused iam_user_console_access_unused iam_password_policy_minimum_length_14 iam_password_policy_reuse_24
iam_aws_attached_policy_no_administrative_privileges iam_customer_attached_policy_no_administrative_privileges iam_inline_policy_no_administrative_privileges
iam_support_role_created iam_user_no_setup_initial_access_key iam_policy_allows_privilege_escalation iam_role_cross_account_readonlyaccess_policy
accessanalyzer_enabled s3_bucket_public_access s3_account_level_public_access_blocks s3_bucket_default_encryption s3_bucket_secure_transport_policy
s3_bucket_object_versioning s3_bucket_server_access_logging_enabled s3_bucket_policy_public_write_access ec2_ebs_volume_encryption ec2_ebs_default_encryption
ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389
ec2_securitygroup_allow_ingress_from_internet_to_any_port ec2_securitygroup_default_restrict_traffic ec2_instance_imdsv2_enabled ec2_instance_public_ip
ec2_networkacl_allow_ingress_tcp_port_22 ec2_elastic_ip_unassigned vpc_flow_logs_enabled rds_instance_storage_encrypted rds_instance_no_public_access
rds_instance_minor_version_upgrade_enabled rds_instance_multi_az efs_encryption_at_rest_enabled cloudtrail_multi_region_enabled
cloudtrail_log_file_validation_enabled cloudtrail_logs_s3_bucket_is_not_publicly_accessible cloudtrail_cloudwatch_logging_enabled""".split()


def metadata_files():
    return sorted(CHECKS_ROOT.rglob("*.metadata.json"))


def test_every_check_dir_has_valid_metadata():
    files = metadata_files()
    assert len(files) >= 50
    ids = []
    for f in files:
        meta = json.loads(f.read_text())
        for key in REQUIRED:
            assert key in meta, f"{f.name} missing {key}"
        cid = meta["CheckID"]
        ids.append(cid)
        assert f.name == f"{cid}.metadata.json" and f.parent.name == cid
        assert (f.parent / f"{cid}.py").exists()
        assert meta["Provider"] == "aws"
        assert meta["Severity"] in ("critical", "high", "medium", "low")
        assert set(meta["Remediation"]["Code"]) == {"CLI", "NativeIaC", "Other", "Terraform"}
        assert meta["Remediation"]["Recommendation"]["Text"]
        for fw in FRAMEWORKS:
            assert meta["Compliance"].get(fw), f"{cid} missing {fw}"
        for control in meta["Compliance"]["cis_aws"]:
            assert CIS_30.match(control), f"{cid}: {control} is not a CIS AWS 3.0 control id"
    assert len(ids) == len(set(ids)), "duplicate CheckIDs"


def test_registry_loads_all_checks():
    checks = all_checks()
    assert len(checks) >= 50
    ids = {c.check_id for c in checks}
    missing = set(MANDATORY) - ids
    assert not missing, missing
    assert len(ids) == len(checks)
    for c in checks:
        assert type(c).__name__ == "".join(p.capitalize() for p in c.check_id.split("_"))


def test_registry_filters():
    assert {c.check_id for c in filter_checks(ids="iam_root_mfa_enabled,s3_bucket_public_access")} == {"iam_root_mfa_enabled", "s3_bucket_public_access"}
    s3 = filter_checks(services=["s3"])
    assert s3 and all(c.service == "s3" for c in s3)
    assert {c.check_id for c in filter_checks(compliance="cis_aws:1.4")} == {"iam_no_root_access_key"}
    sec2 = filter_checks(compliance="cis_aws:2.1")
    assert "s3_bucket_public_access" in {c.check_id for c in sec2} and all(any(x.startswith("2.1.") for x in c.compliance["cis_aws"]) for c in sec2)
    crit = filter_checks(severities="critical")
    assert crit and all(c.severity == "critical" for c in crit)
    assert len(filter_checks(compliance="cis_aws")) == len(all_checks())
    assert filter_checks(services="awslambda")[0].check_id == "awslambda_function_url_public"
