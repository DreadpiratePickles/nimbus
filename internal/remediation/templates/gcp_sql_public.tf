import {
  to = google_sql_database_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "google_sql_database_instance" "{{ .Slug }}" {
  name             = "{{ .Name }}"
  database_version = {{ with .Attr.database_version }}"{{ . }}"{{ else }}"POSTGRES_15"{{ end }}
  region           = "{{ default "us-central1" .Region }}"
  settings {
    tier = {{ with .Attr.tier }}"{{ . }}"{{ else }}"db-custom-1-3840"{{ end }}
    ip_configuration {
      ipv4_enabled    = false
      private_network = {{ with .Attr.private_network }}"{{ . }}"{{ else }}"projects/{{ .Account }}/global/networks/default"{{ end }}
      ssl_mode        = "ENCRYPTED_ONLY"
    }
  }
  deletion_protection = true
  lifecycle {
    ignore_changes = [settings[0].tier, settings[0].backup_configuration, settings[0].database_flags, database_version]
  }
}
