resource "aws_s3_bucket_server_side_encryption_configuration" "{{ .Slug }}" {
  bucket = "{{ .Name }}"
  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3 (least change). aws:kms with the AWS-managed key would break cross-account readers;
      # switch to a customer-managed KMS key deliberately if policy requires it.
      sse_algorithm = "AES256"
    }
  }
}
