import json

from .conftest import ACCOUNT, run, status_of

PAB_ALL = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def mk(ctx, name):
    ctx.client("s3").create_bucket(Bucket=name)
    return name


def test_bucket_public_access_acl_and_policy(ctx):
    s3 = ctx.client("s3")
    mk(ctx, "public-acl-bucket")
    s3.put_bucket_acl(Bucket="public-acl-bucket", ACL="public-read")
    mk(ctx, "public-policy-bucket")
    s3.put_bucket_policy(Bucket="public-policy-bucket", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-policy-bucket/*"}]}))
    mk(ctx, "private-bucket")
    mk(ctx, "blocked-bucket")
    s3.put_bucket_acl(Bucket="blocked-bucket", ACL="public-read")
    s3.put_public_access_block(Bucket="blocked-bucket", PublicAccessBlockConfiguration=PAB_ALL)
    res = run("s3_bucket_public_access", ctx)
    assert status_of(res, "public-acl-bucket") == "FAIL"
    assert status_of(res, "public-policy-bucket") == "FAIL"
    assert status_of(res, "private-bucket") == "PASS"
    assert status_of(res, "blocked-bucket") == "PASS"


def test_bucket_public_access_account_block(ctx):
    mk(ctx, "acl-bucket")
    ctx.client("s3").put_bucket_acl(Bucket="acl-bucket", ACL="public-read-write")
    ctx.client("s3control").put_public_access_block(AccountId=ACCOUNT, PublicAccessBlockConfiguration=PAB_ALL)
    assert status_of(run("s3_bucket_public_access", ctx), "acl-bucket") == "PASS"


def test_account_level_public_access_blocks(ctx):
    r = run("s3_account_level_public_access_blocks", ctx)[0]
    assert r.status == "FAIL"
    ctx.clear_cache()
    ctx.client("s3control").put_public_access_block(AccountId=ACCOUNT, PublicAccessBlockConfiguration=PAB_ALL)
    assert run("s3_account_level_public_access_blocks", ctx)[0].status == "PASS"


def test_default_encryption(ctx):
    mk(ctx, "plain-bucket")
    mk(ctx, "kms-bucket")
    ctx.client("s3").put_bucket_encryption(Bucket="kms-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    res = run("s3_bucket_default_encryption", ctx)
    assert status_of(res, "plain-bucket") == "FAIL"
    assert status_of(res, "kms-bucket") == "PASS"


def test_secure_transport_policy(ctx):
    mk(ctx, "no-policy")
    mk(ctx, "tls-only")
    mk(ctx, "allow-only")
    s3 = ctx.client("s3")
    s3.put_bucket_policy(Bucket="tls-only", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "DenyHTTP", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::tls-only", "arn:aws:s3:::tls-only/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}))
    s3.put_bucket_policy(Bucket="allow-only", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::allow-only/*"}]}))
    res = run("s3_bucket_secure_transport_policy", ctx)
    assert status_of(res, "no-policy") == "FAIL"
    assert status_of(res, "allow-only") == "FAIL"
    assert status_of(res, "tls-only") == "PASS"


def test_object_versioning(ctx):
    mk(ctx, "unversioned")
    mk(ctx, "versioned")
    ctx.client("s3").put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    res = run("s3_bucket_object_versioning", ctx)
    assert status_of(res, "unversioned") == "FAIL"
    assert status_of(res, "versioned") == "PASS"


def test_server_access_logging(ctx):
    s3 = ctx.client("s3")
    mk(ctx, "log-target")
    s3.put_bucket_acl(Bucket="log-target", GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
                      GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery")
    mk(ctx, "logged")
    s3.put_bucket_logging(Bucket="logged", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "log-target", "TargetPrefix": "logged/"}})
    res = run("s3_bucket_server_access_logging_enabled", ctx)
    assert status_of(res, "logged") == "PASS"
    assert status_of(res, "log-target") == "FAIL"


def test_policy_public_write(ctx):
    s3 = ctx.client("s3")
    mk(ctx, "writable")
    s3.put_bucket_policy(Bucket="writable", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "PublicPut", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::writable/*"}]}))
    mk(ctx, "readable")
    s3.put_bucket_policy(Bucket="readable", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::readable/*"}]}))
    mk(ctx, "nopolicy")
    res = run("s3_bucket_policy_public_write_access", ctx)
    assert status_of(res, "writable") == "FAIL"
    assert status_of(res, "readable") == "PASS"
    assert status_of(res, "nopolicy") == "PASS"
