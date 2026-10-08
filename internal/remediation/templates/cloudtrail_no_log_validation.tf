import {
  to = aws_cloudtrail.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_cloudtrail" "{{ .Slug }}" {
  name                       = "{{ .Name }}"
  s3_bucket_name             = {{ with .Attr.S3BucketName }}"{{ . }}"{{ else }}null{{ end }}
  enable_log_file_validation = true
  lifecycle {
    ignore_changes = [s3_bucket_name, is_multi_region_trail, include_global_service_events, tags, event_selector, advanced_event_selector, cloud_watch_logs_group_arn, cloud_watch_logs_role_arn, kms_key_id, sns_topic_name]
  }
}
