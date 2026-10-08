import {
  to = aws_s3_bucket_versioning.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_s3_bucket_versioning" "{{ .Slug }}" {
  bucket = "{{ .Name }}"
  versioning_configuration {
    status = "Enabled"
  }
}
