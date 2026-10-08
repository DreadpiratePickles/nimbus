resource "aws_s3_bucket" "{{ .Slug }}_trail" {
  bucket        = "cloudtrail-{{ .Account }}-{{ .Slug }}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "{{ .Slug }}_trail" {
  bucket                  = aws_s3_bucket.{{ .Slug }}_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "{{ .Slug }}_trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.{{ .Slug }}_trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.{{ .Slug }}_trail.arn}/AWSLogs/{{ .Account }}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "{{ .Slug }}_trail" {
  bucket = aws_s3_bucket.{{ .Slug }}_trail.id
  policy = data.aws_iam_policy_document.{{ .Slug }}_trail.json
}

resource "aws_cloudtrail" "{{ .Slug }}" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.{{ .Slug }}_trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.{{ .Slug }}_trail]
}
