import io
import json
import zipfile

from .conftest import REGION, run, status_of


def mkdb(ctx, name, **kw):
    params = dict(DBInstanceIdentifier=name, DBInstanceClass="db.t3.micro", Engine="postgres", AllocatedStorage=20,
                  MasterUsername="admin1", MasterUserPassword="Passw0rdPassw0rd")
    params.update(kw)
    ctx.client("rds").create_db_instance(**params)
    return name


def test_rds_storage_encrypted(ctx):
    mkdb(ctx, "plain-db", StorageEncrypted=False)
    mkdb(ctx, "enc-db", StorageEncrypted=True)
    res = run("rds_instance_storage_encrypted", ctx)
    assert status_of(res, "plain-db") == "FAIL"
    assert status_of(res, "enc-db") == "PASS"


def test_rds_no_public_access(ctx):
    mkdb(ctx, "public-db", PubliclyAccessible=True)
    mkdb(ctx, "private-db", PubliclyAccessible=False)
    res = run("rds_instance_no_public_access", ctx)
    assert status_of(res, "public-db") == "FAIL"
    assert status_of(res, "private-db") == "PASS"


def test_rds_minor_version_upgrade(ctx):
    mkdb(ctx, "noauto-db", AutoMinorVersionUpgrade=False)
    mkdb(ctx, "auto-db", AutoMinorVersionUpgrade=True)
    res = run("rds_instance_minor_version_upgrade_enabled", ctx)
    assert status_of(res, "noauto-db") == "FAIL"
    assert status_of(res, "auto-db") == "PASS"


def test_rds_multi_az(ctx):
    mkdb(ctx, "single-db", MultiAZ=False)
    mkdb(ctx, "multi-db", MultiAZ=True)
    res = run("rds_instance_multi_az", ctx)
    assert status_of(res, "single-db") == "FAIL"
    assert status_of(res, "multi-db") == "PASS"


def test_efs_encryption(ctx):
    efs = ctx.client("efs")
    plain = efs.create_file_system(CreationToken="plain", Encrypted=False)["FileSystemId"]
    enc = efs.create_file_system(CreationToken="enc", Encrypted=True)["FileSystemId"]
    res = run("efs_encryption_at_rest_enabled", ctx)
    assert status_of(res, plain) == "FAIL"
    assert status_of(res, enc) == "PASS"


def test_kms_rotation(ctx):
    kms = ctx.client("kms")
    norot = kms.create_key(Description="no rotation")["KeyMetadata"]["KeyId"]
    rot = kms.create_key(Description="rotated")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=rot)
    asym = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    res = run("kms_cmk_rotation_enabled", ctx)
    assert status_of(res, norot) == "FAIL"
    assert status_of(res, rot) == "PASS"
    assert all(r.resource_id != asym for r in res)


def _function(ctx, name):
    role = ctx.client("iam").create_role(RoleName=f"{name}-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "def handler(event, context):\n    return 1\n")
    ctx.client("lambda").create_function(FunctionName=name, Runtime="python3.12", Role=role, Handler="app.handler", Code={"ZipFile": buf.getvalue()})
    return name


def test_lambda_function_url_public(ctx):
    lam = ctx.client("lambda")
    lam.create_function_url_config(FunctionName=_function(ctx, "open-fn"), AuthType="NONE")
    lam.create_function_url_config(FunctionName=_function(ctx, "iam-fn"), AuthType="AWS_IAM")
    _function(ctx, "nourl-fn")
    res = run("awslambda_function_url_public", ctx)
    assert status_of(res, "open-fn") == "FAIL"
    assert status_of(res, "iam-fn") == "PASS"
    assert status_of(res, "nourl-fn") == "PASS"


def test_eks_public_endpoint(ctx):
    eks = ctx.client("eks")
    role = "arn:aws:iam::123456789012:role/eks"
    eks.create_cluster(name="public-cluster", roleArn=role, resourcesVpcConfig={"subnetIds": [], "endpointPublicAccess": True})
    eks.create_cluster(name="private-cluster", roleArn=role, resourcesVpcConfig={"subnetIds": [], "endpointPublicAccess": False, "endpointPrivateAccess": True})
    eks.create_cluster(name="restricted-cluster", roleArn=role, resourcesVpcConfig={"subnetIds": [], "endpointPublicAccess": True, "publicAccessCidrs": ["203.0.113.0/24"]})
    res = run("eks_control_plane_endpoint_access_publicly_accessible", ctx)
    assert status_of(res, "public-cluster") == "FAIL"
    assert status_of(res, "private-cluster") == "PASS"
    assert status_of(res, "restricted-cluster") == "PASS"
    assert all(r.region == REGION for r in res)
