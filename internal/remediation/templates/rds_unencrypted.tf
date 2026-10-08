# Encryption cannot be toggled in place. Snapshot, copy encrypted, restore, then cut over.
#   aws rds create-db-snapshot --db-instance-identifier {{ .Name }} --db-snapshot-identifier {{ .Slug }}-pre-enc
#   aws rds copy-db-snapshot --source-db-snapshot-identifier {{ .Slug }}-pre-enc --target-db-snapshot-identifier {{ .Slug }}-enc --kms-key-id alias/aws/rds
#   aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {{ .Name }}-enc --db-snapshot-identifier {{ .Slug }}-enc
resource "aws_db_instance" "{{ .Slug }}_encrypted" {
  identifier          = "{{ .Name }}-enc"
  snapshot_identifier = "{{ .Slug }}-enc"
  storage_encrypted   = true
  kms_key_id          = null # default aws/rds key
  instance_class      = {{ with .Attr.DBInstanceClass }}"{{ . }}"{{ else }}"db.t3.medium"{{ end }}
  skip_final_snapshot = false
}
