import {
  to = aws_kms_key.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_kms_key" "{{ .Slug }}" {
  enable_key_rotation = true
  lifecycle {
    ignore_changes = [description, policy, tags, deletion_window_in_days, key_usage, customer_master_key_spec]
  }
}
