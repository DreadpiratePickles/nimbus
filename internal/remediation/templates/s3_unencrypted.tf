import {
  to = aws_s3_bucket_server_side_encryption_configuration.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "{{ .Slug }}" {
  bucket = "{{ .Name }}"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}
