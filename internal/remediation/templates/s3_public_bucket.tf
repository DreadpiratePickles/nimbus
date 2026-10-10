resource "aws_s3_bucket_public_access_block" "{{ .Slug }}" {
  bucket                  = "{{ .Name }}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "{{ .Slug }}" {
  bucket = "{{ .Name }}"
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs entirely
  }
}
