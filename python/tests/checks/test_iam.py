import json

from .conftest import ACCOUNT, by_id, cred_row, iso, policy_json, run, set_credential_report, status_of

ROOT = "<root_account>"
ADMIN = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
SCOPED = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]
TRUST_SAME = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]}
TRUST_OTHER = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"}]}


def test_root_mfa(ctx, monkeypatch):
    assert run("iam_root_mfa_enabled", ctx)[0].status == "FAIL"  # moto: AccountMFAEnabled=0
    ctx.clear_cache()
    monkeypatch.setattr(ctx.client("iam"), "get_account_summary", lambda: {"SummaryMap": {"AccountMFAEnabled": 1}})
    assert run("iam_root_mfa_enabled", ctx)[0].status == "PASS"


def test_root_hardware_mfa(ctx, monkeypatch):
    iam = ctx.client("iam")
    monkeypatch.setattr(iam, "get_account_summary", lambda: {"SummaryMap": {"AccountMFAEnabled": 1}})
    monkeypatch.setattr(iam, "list_virtual_mfa_devices", lambda **kw: {"VirtualMFADevices": [
        {"SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/root-account-mfa-device", "User": {"Arn": f"arn:aws:iam::{ACCOUNT}:root"}}]})
    assert run("iam_root_hardware_mfa_enabled", ctx)[0].status == "FAIL"
    monkeypatch.setattr(iam, "list_virtual_mfa_devices", lambda **kw: {"VirtualMFADevices": []})
    assert run("iam_root_hardware_mfa_enabled", ctx)[0].status == "PASS"


def test_root_hardware_mfa_no_mfa(ctx):
    assert run("iam_root_hardware_mfa_enabled", ctx)[0].status == "FAIL"


def test_no_root_access_key(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [cred_row(ROOT, access_key_1_active=True, access_key_1_last_rotated=iso(10))])
    r = run("iam_no_root_access_key", ctx)[0]
    assert r.status == "FAIL" and "1 active" in r.status_extended
    ctx.clear_cache()
    set_credential_report(monkeypatch, ctx, [cred_row(ROOT)])
    assert run("iam_no_root_access_key", ctx)[0].status == "PASS"


def test_avoid_root_usage(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [cred_row(ROOT, password_enabled=True, password_last_used=iso(0.1))])
    assert run("iam_avoid_root_usage", ctx)[0].status == "FAIL"
    ctx.clear_cache()
    set_credential_report(monkeypatch, ctx, [cred_row(ROOT, password_enabled=True, password_last_used=iso(30))])
    assert run("iam_avoid_root_usage", ctx)[0].status == "PASS"


def test_user_mfa_console_real_moto_report(ctx):
    iam = ctx.client("iam")
    iam.create_user(UserName="console-user")
    iam.create_login_profile(UserName="console-user", Password="Sup3r$ecretPassw0rd!")
    iam.create_user(UserName="api-user")
    res = run("iam_user_mfa_enabled_console_access", ctx)
    assert status_of(res, "console-user") == "FAIL"
    assert status_of(res, "api-user") == "PASS"
    assert by_id(res, "console-user").resource_arn == f"arn:aws:iam::{ACCOUNT}:user/console-user"


def test_user_mfa_console_with_mfa(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [cred_row("alice", password_enabled=True, mfa_active=True)])
    assert status_of(run("iam_user_mfa_enabled_console_access", ctx), "alice") == "PASS"


def test_rotate_access_key_90_days(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [
        cred_row(ROOT),
        cred_row("old", access_key_1_active=True, access_key_1_last_rotated=iso(200)),
        cred_row("fresh", access_key_1_active=True, access_key_1_last_rotated=iso(10)),
        cred_row("nokeys"),
    ])
    res = run("iam_rotate_access_key_90_days", ctx)
    assert status_of(res, "old") == "FAIL"
    assert status_of(res, "fresh") == "PASS"
    assert status_of(res, "nokeys") == "PASS"
    assert all(r.resource_id != ROOT for r in res)


def test_accesskey_unused(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [
        cred_row("stale", access_key_1_active=True, access_key_1_last_rotated=iso(300), access_key_1_last_used_date=iso(60)),
        cred_row("never", access_key_2_active=True, access_key_2_last_rotated=iso(100)),
        cred_row("active", access_key_1_active=True, access_key_1_last_rotated=iso(300), access_key_1_last_used_date=iso(2)),
    ])
    res = run("iam_user_accesskey_unused", ctx)
    assert status_of(res, "stale") == "FAIL"
    assert status_of(res, "never") == "FAIL"
    assert status_of(res, "active") == "PASS"


def test_console_access_unused(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [
        cred_row("dormant", password_enabled=True, password_last_used=iso(90)),
        cred_row("recent", password_enabled=True, password_last_used=iso(3)),
        cred_row("nopass"),
    ])
    res = run("iam_user_console_access_unused", ctx)
    assert status_of(res, "dormant") == "FAIL"
    assert status_of(res, "recent") == "PASS"
    assert status_of(res, "nopass") == "PASS"


def test_password_policy_missing(ctx):
    assert run("iam_password_policy_minimum_length_14", ctx)[0].status == "FAIL"
    assert run("iam_password_policy_reuse_24", ctx)[0].status == "FAIL"


def test_password_policy_weak_then_strong(ctx):
    iam = ctx.client("iam")
    iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=5)
    assert run("iam_password_policy_minimum_length_14", ctx)[0].status == "FAIL"
    assert run("iam_password_policy_reuse_24", ctx)[0].status == "FAIL"
    ctx.clear_cache()
    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)
    assert run("iam_password_policy_minimum_length_14", ctx)[0].status == "PASS"
    assert run("iam_password_policy_reuse_24", ctx)[0].status == "PASS"


def test_aws_attached_admin_policy(managed_policies, ctx):
    iam = ctx.client("iam")
    iam.create_user(UserName="admin")
    iam.attach_user_policy(UserName="admin", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_user(UserName="reader")
    iam.attach_user_policy(UserName="reader", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    res = run("iam_aws_attached_policy_no_administrative_privileges", ctx)
    admin = by_id(res, "AdministratorAccess")
    assert admin.status == "FAIL" and "admin" in admin.related
    assert status_of(res, "ReadOnlyAccess") == "PASS"


def test_customer_attached_admin_policy(ctx):
    iam = ctx.client("iam")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(TRUST_SAME))
    admin = iam.create_policy(PolicyName="star-admin", PolicyDocument=policy_json(ADMIN))["Policy"]["Arn"]
    scoped = iam.create_policy(PolicyName="scoped", PolicyDocument=policy_json(SCOPED))["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="r1", PolicyArn=admin)
    iam.attach_role_policy(RoleName="r1", PolicyArn=scoped)
    res = run("iam_customer_attached_policy_no_administrative_privileges", ctx)
    assert status_of(res, "star-admin") == "FAIL"
    assert status_of(res, "scoped") == "PASS"


def test_inline_admin_policy(ctx):
    iam = ctx.client("iam")
    iam.create_user(UserName="u1")
    iam.put_user_policy(UserName="u1", PolicyName="inline-admin", PolicyDocument=policy_json(ADMIN))
    iam.create_group(GroupName="g1")
    iam.put_group_policy(GroupName="g1", PolicyName="inline-scoped", PolicyDocument=policy_json(SCOPED))
    res = run("iam_inline_policy_no_administrative_privileges", ctx)
    assert status_of(res, "inline-admin") == "FAIL"
    assert status_of(res, "inline-scoped") == "PASS"


def test_support_role(managed_policies, ctx):
    assert run("iam_support_role_created", ctx)[0].status == "FAIL"
    iam = ctx.client("iam")
    iam.create_role(RoleName="support", AssumeRolePolicyDocument=json.dumps(TRUST_SAME))
    iam.attach_role_policy(RoleName="support", PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
    r = run("iam_support_role_created", ctx)[0]
    assert r.status == "PASS" and "support" in r.related


def test_no_setup_initial_access_key(ctx, monkeypatch):
    set_credential_report(monkeypatch, ctx, [
        cred_row("setup", password_enabled=True, access_key_1_active=True, access_key_1_last_rotated=iso(5)),
        cred_row("used", password_enabled=True, access_key_1_active=True, access_key_1_last_rotated=iso(5), access_key_1_last_used_date=iso(1)),
        cred_row("apionly", access_key_1_active=True, access_key_1_last_rotated=iso(5)),
    ])
    res = run("iam_user_no_setup_initial_access_key", ctx)
    assert status_of(res, "setup") == "FAIL"
    assert status_of(res, "used") == "PASS"
    assert status_of(res, "apionly") == "PASS"


def test_privilege_escalation(ctx):
    iam = ctx.client("iam")
    iam.create_policy(PolicyName="escalate", PolicyDocument=policy_json([{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]))
    iam.create_policy(PolicyName="wildcard-iam", PolicyDocument=policy_json([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]))
    iam.create_policy(PolicyName="denied", PolicyDocument=policy_json([
        {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]))
    iam.create_policy(PolicyName="safe", PolicyDocument=policy_json(SCOPED))
    res = run("iam_policy_allows_privilege_escalation", ctx)
    assert status_of(res, "escalate") == "FAIL"
    assert "ec2:RunInstances" in by_id(res, "escalate").resource_details["escalation_actions"]
    assert status_of(res, "wildcard-iam") == "FAIL"
    assert status_of(res, "denied") == "PASS"
    assert status_of(res, "safe") == "PASS"


def test_cross_account_readonly(managed_policies, ctx):
    iam = ctx.client("iam")
    ro = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam.create_role(RoleName="external-ro", AssumeRolePolicyDocument=json.dumps(TRUST_OTHER))
    iam.attach_role_policy(RoleName="external-ro", PolicyArn=ro)
    iam.create_role(RoleName="internal-ro", AssumeRolePolicyDocument=json.dumps(TRUST_SAME))
    iam.attach_role_policy(RoleName="internal-ro", PolicyArn=ro)
    iam.create_role(RoleName="external-other", AssumeRolePolicyDocument=json.dumps(TRUST_OTHER))
    res = run("iam_role_cross_account_readonlyaccess_policy", ctx)
    assert status_of(res, "external-ro") == "FAIL"
    assert status_of(res, "internal-ro") == "PASS"
    assert status_of(res, "external-other") == "PASS"


def test_accessanalyzer(ctx, monkeypatch):
    aa = ctx.client("accessanalyzer")
    monkeypatch.setattr(aa, "list_analyzers", lambda **kw: {"analyzers": []})
    assert run("accessanalyzer_enabled", ctx)[0].status == "FAIL"
    monkeypatch.setattr(aa, "list_analyzers", lambda **kw: {"analyzers": [
        {"name": "default", "arn": f"arn:aws:access-analyzer:us-east-1:{ACCOUNT}:analyzer/default", "status": "ACTIVE", "type": "ACCOUNT"}]})
    r = run("accessanalyzer_enabled", ctx)[0]
    assert r.status == "PASS" and r.resource_id == "default"
