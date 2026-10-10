variable "{{ .Slug }}_log_bucket" {
  description = "Destination bucket for server access logs"
  type        = string
}

resource "aws_s3_bucket_logging" "{{ .Slug }}" {
  bucket        = "{{ .Name }}"
  target_bucket = var.{{ .Slug }}_log_bucket
  target_prefix = "s3-access/{{ .Name }}/"
}
