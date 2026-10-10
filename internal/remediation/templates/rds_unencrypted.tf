# Encryption cannot be toggled in place. Snapshot, copy encrypted, restore, then cut over.
# CLI: aws rds create-db-snapshot --db-instance-identifier={{ sh .Raw.Name }} --db-snapshot-identifier={{ .Slug }}-pre-enc
# CLI: aws rds copy-db-snapshot --source-db-snapshot-identifier={{ .Slug }}-pre-enc --target-db-snapshot-identifier={{ .Slug }}-enc --kms-key-id alias/aws/rds
# CLI: aws rds restore-db-instance-from-db-snapshot --db-instance-identifier={{ sh (printf "%s-enc" .Raw.Name) }} --db-snapshot-identifier={{ .Slug }}-enc
resource "aws_db_instance" "{{ .Slug }}_encrypted" {
  identifier          = "{{ .Name }}-enc"
  snapshot_identifier = "{{ .Slug }}-enc"
  storage_encrypted   = true
  kms_key_id          = null # default aws/rds key
  instance_class      = {{ with .Attr.DBInstanceClass }}"{{ . }}"{{ else }}"db.t3.medium"{{ end }}
  skip_final_snapshot = false
}
