import {
  to = aws_db_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_db_instance" "{{ .Slug }}" {
  # Only publicly_accessible is managed; everything else is ignored so the imported instance is
  # not modified or replaced. Review the plan: it must show an in-place update only.
  identifier          = "{{ .Name }}"
  instance_class      = {{ with .Attr.DBInstanceClass }}"{{ . }}"{{ else }}null # TODO: set to the current instance class{{ end }}
  publicly_accessible = false
  apply_immediately   = true
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [instance_class, engine, engine_version, allocated_storage, max_allocated_storage, storage_type, iops, storage_throughput, storage_encrypted, kms_key_id, username, password, db_name, parameter_group_name, option_group_name, db_subnet_group_name, vpc_security_group_ids, multi_az, availability_zone, backup_retention_period, backup_window, maintenance_window, auto_minor_version_upgrade, deletion_protection, skip_final_snapshot, final_snapshot_identifier, copy_tags_to_snapshot, monitoring_interval, monitoring_role_arn, performance_insights_enabled, performance_insights_kms_key_id, performance_insights_retention_period, enabled_cloudwatch_logs_exports, iam_database_authentication_enabled, ca_cert_identifier, license_model, port, network_type, tags, tags_all]
  }
}
# CLI: aws rds modify-db-instance --db-instance-identifier={{ sh .Raw.Name }} --no-publicly-accessible --apply-immediately
