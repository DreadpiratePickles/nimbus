import json

from .conftest import ACCOUNT, REGION, run, status_of

ROLE = f"arn:aws:iam::{ACCOUNT}:role/cloudtrail-cw"


def bucket(ctx, name="trail-logs-bucket"):
    ctx.client("s3").create_bucket(Bucket=name)
    return name


def trail(ctx, name, **kw):
    ct = ctx.client("cloudtrail")
    kw.setdefault("S3BucketName", bucket(ctx, f"{name}-logs"))
    ct.create_trail(Name=name, **kw)
    ct.start_logging(Name=name)
    return name


def log_group(ctx, name="cloudtrail-lg"):
    logs = ctx.client("logs")
    logs.create_log_group(logGroupName=name)
    return f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}:*"


def test_no_trails(ctx):
    for cid in ("cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled", "cloudtrail_kms_encryption_enabled",
                "cloudtrail_cloudwatch_logging_enabled", "cloudtrail_s3_dataevents_read_enabled",
                "cloudtrail_logs_s3_bucket_is_not_publicly_accessible"):
        res = run(cid, ctx)
        assert res and all(r.status == "FAIL" for r in res), cid


def test_multi_region(ctx):
    trail(ctx, "single-trail")
    ctx.client("cloudtrail").stop_logging(Name="single-trail")
    assert run("cloudtrail_multi_region_enabled", ctx)[0].status == "FAIL"
    ctx.clear_cache()
    trail(ctx, "multi-trail", IsMultiRegionTrail=True)
    r = run("cloudtrail_multi_region_enabled", ctx)[0]
    assert r.status == "PASS" and r.resource_id == "multi-trail"


def test_log_file_validation(ctx):
    trail(ctx, "novalidation")
    trail(ctx, "validated", EnableLogFileValidation=True)
    res = run("cloudtrail_log_file_validation_enabled", ctx)
    assert status_of(res, "novalidation") == "FAIL"
    assert status_of(res, "validated") == "PASS"


def test_kms_encryption(ctx):
    key = ctx.client("kms").create_key()["KeyMetadata"]["Arn"]
    trail(ctx, "nokms")
    trail(ctx, "withkms", KmsKeyId=key)
    res = run("cloudtrail_kms_encryption_enabled", ctx)
    assert status_of(res, "nokms") == "FAIL"
    assert status_of(res, "withkms") == "PASS"


def test_cloudwatch_logging(ctx):
    trail(ctx, "nocw")
    trail(ctx, "withcw", CloudWatchLogsLogGroupArn=log_group(ctx), CloudWatchLogsRoleArn=ROLE)
    res = run("cloudtrail_cloudwatch_logging_enabled", ctx)
    assert status_of(res, "nocw") == "FAIL"
    assert status_of(res, "withcw") == "PASS"


def test_trail_bucket_public(ctx):
    s3 = ctx.client("s3")
    trail(ctx, "public-trail", S3BucketName=bucket(ctx, "public-trail-bucket"))
    s3.put_bucket_acl(Bucket="public-trail-bucket", ACL="public-read")
    trail(ctx, "private-trail", S3BucketName=bucket(ctx, "private-trail-bucket"))
    res = run("cloudtrail_logs_s3_bucket_is_not_publicly_accessible", ctx)
    assert status_of(res, "public-trail") == "FAIL"
    assert status_of(res, "private-trail") == "PASS"


def test_s3_dataevents_read(ctx):
    trail(ctx, "mgmt-only")
    assert run("cloudtrail_s3_dataevents_read_enabled", ctx)[0].status == "FAIL"
    ctx.clear_cache()
    trail(ctx, "data-trail", IsMultiRegionTrail=True)
    ctx.client("cloudtrail").put_event_selectors(TrailName="data-trail", EventSelectors=[{
        "ReadWriteType": "All", "IncludeManagementEvents": True,
        "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}])
    r = run("cloudtrail_s3_dataevents_read_enabled", ctx)[0]
    assert r.status == "PASS" and r.resource_id == "data-trail"


def test_config_recorder(ctx):
    assert run("config_recorder_all_regions_enabled", ctx)[0].status == "FAIL"
    cfg = ctx.client("config")
    cfg.put_configuration_recorder(ConfigurationRecorder={"name": "default", "roleARN": f"arn:aws:iam::{ACCOUNT}:role/config",
                                                          "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}})
    assert run("config_recorder_all_regions_enabled", ctx)[0].status == "FAIL"  # exists but not recording
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": bucket(ctx, "config-bucket")})
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    r = run("config_recorder_all_regions_enabled", ctx)[0]
    assert r.status == "PASS" and r.resource_id == "default"


METRIC_CASES = {
    "cloudwatch_log_metric_filter_unauthorized_api_calls":
        '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
    "cloudwatch_log_metric_filter_root_usage":
        '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    "cloudwatch_log_metric_filter_policy_changes":
        "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||"
        "($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||"
        "($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||"
        "($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
    "cloudwatch_log_metric_filter_authentication_failures":
        '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }',
    "cloudwatch_log_metric_filter_security_group_changes":
        "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || "
        "($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || "
        "($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }",
}


def test_metric_filters(ctx):
    for cid in METRIC_CASES:
        assert run(cid, ctx)[0].status == "FAIL", cid  # no trail at all
    trail(ctx, "cw-trail", IsMultiRegionTrail=True, CloudWatchLogsLogGroupArn=log_group(ctx), CloudWatchLogsRoleArn=ROLE)
    logs, cw = ctx.client("logs"), ctx.client("cloudwatch")
    for i, (cid, pattern) in enumerate(METRIC_CASES.items()):
        ctx.clear_cache()
        metric = f"cis-metric-{i}"
        logs.put_metric_filter(logGroupName="cloudtrail-lg", filterName=f"cis-filter-{i}", filterPattern=pattern,
                               metricTransformations=[{"metricName": metric, "metricNamespace": "CISBenchmark", "metricValue": "1"}])
        assert run(cid, ctx)[0].status == "FAIL", f"{cid}: filter without alarm must fail"
        cw.put_metric_alarm(AlarmName=metric, MetricName=metric, Namespace="CISBenchmark", Statistic="Sum", Period=300,
                            EvaluationPeriods=1, Threshold=1, ComparisonOperator="GreaterThanOrEqualToThreshold",
                            AlarmActions=[f"arn:aws:sns:{REGION}:{ACCOUNT}:alerts"])
        r = run(cid, ctx)[0]
        assert r.status == "PASS", cid
        assert r.resource_id == f"cis-filter-{i}"


def test_metric_filter_wrong_pattern(ctx):
    trail(ctx, "cw-trail", IsMultiRegionTrail=True, CloudWatchLogsLogGroupArn=log_group(ctx), CloudWatchLogsRoleArn=ROLE)
    ctx.client("logs").put_metric_filter(logGroupName="cloudtrail-lg", filterName="other", filterPattern='{ $.eventName = "RunInstances" }',
                                         metricTransformations=[{"metricName": "m", "metricNamespace": "ns", "metricValue": "1"}])
    ctx.client("cloudwatch").put_metric_alarm(AlarmName="m", MetricName="m", Namespace="ns", Statistic="Sum", Period=300, EvaluationPeriods=1,
                                              Threshold=1, ComparisonOperator="GreaterThanOrEqualToThreshold")
    assert run("cloudwatch_log_metric_filter_root_usage", ctx)[0].status == "FAIL"


def test_metric_filter_monkeypatched_clients(ctx, monkeypatch):
    """Exercise the path where logs/cloudwatch APIs are stubbed (e.g. unsupported in an emulator)."""
    trail(ctx, "cw-trail", IsMultiRegionTrail=True, CloudWatchLogsLogGroupArn=log_group(ctx), CloudWatchLogsRoleArn=ROLE)

    class Pager:
        def __init__(self, page):
            self.page = page

        def paginate(self, **kw):
            return [self.page]

    logs, cw = ctx.client("logs"), ctx.client("cloudwatch")
    monkeypatch.setattr(logs, "get_paginator", lambda op: Pager({"metricFilters": [{"filterName": "f", "filterPattern": METRIC_CASES["cloudwatch_log_metric_filter_authentication_failures"],
                                                                                    "metricTransformations": [{"metricName": "auth", "metricNamespace": "CIS"}]}]}))
    monkeypatch.setattr(cw, "get_paginator", lambda op: Pager({"MetricAlarms": [{"MetricName": "auth", "Namespace": "CIS"}]}))
    assert run("cloudwatch_log_metric_filter_authentication_failures", ctx)[0].status == "PASS"


def test_guardduty(ctx):
    assert run("guardduty_is_enabled", ctx)[0].status == "FAIL"
    did = ctx.client("guardduty").create_detector(Enable=True)["DetectorId"]
    r = run("guardduty_is_enabled", ctx)[0]
    assert r.status == "PASS" and r.resource_id == did


def test_guardduty_suspended_monkeypatched(ctx, monkeypatch):
    gd = ctx.client("guardduty")
    monkeypatch.setattr(gd, "list_detectors", lambda **kw: {"DetectorIds": ["abc"]})
    monkeypatch.setattr(gd, "get_detector", lambda **kw: {"Status": "DISABLED"})
    assert run("guardduty_is_enabled", ctx)[0].status == "FAIL"


def test_securityhub(ctx):
    assert run("securityhub_enabled", ctx)[0].status == "FAIL"
    ctx.client("securityhub").enable_security_hub()
    assert run("securityhub_enabled", ctx)[0].status == "PASS"


def test_regional_access_denied_is_manual(ctx, monkeypatch):
    from botocore.exceptions import ClientError

    def deny(**kw):
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "nope"}}, "ListDetectors")

    monkeypatch.setattr(ctx.client("guardduty"), "list_detectors", deny)
    r = run("guardduty_is_enabled", ctx)[0]
    assert r.status == "MANUAL"
    assert json.dumps(r.resource_details)
