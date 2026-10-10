resource "aws_s3_bucket_versioning" "{{ .Slug }}" {
  bucket = "{{ .Name }}"
  versioning_configuration {
    status = "Enabled"
  }
}
