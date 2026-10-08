import {
  to = aws_db_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_db_instance" "{{ .Slug }}" {
  identifier          = "{{ .Name }}"
  publicly_accessible = false
  apply_immediately   = true
  lifecycle {
    ignore_changes = all
  }
}
# CLI: aws rds modify-db-instance --db-instance-identifier {{ .Name }} --no-publicly-accessible --apply-immediately
