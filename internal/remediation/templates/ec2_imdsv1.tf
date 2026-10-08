import {
  to = aws_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_instance" "{{ .Slug }}" {
  # Existing attributes are preserved via ignore_changes; only metadata options are enforced.
  ami           = {{ with .Attr.ImageId }}"{{ . }}"{{ else }}null{{ end }}
  instance_type = {{ with .Attr.InstanceType }}"{{ . }}"{{ else }}null{{ end }}

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  lifecycle {
    ignore_changes = all
  }
}
# Immediate CLI equivalent:
#   aws ec2 modify-instance-metadata-options --instance-id {{ .Name }} --http-tokens required --http-endpoint enabled{{ with .Region }} --region {{ . }}{{ end }}
