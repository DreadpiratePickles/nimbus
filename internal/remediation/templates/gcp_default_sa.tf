resource "google_service_account" "{{ .Slug }}" {
  account_id   = "{{ .Slug }}-sa"
  display_name = "Least-privilege SA for {{ .Name }}"
}

import {
  to = google_compute_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "google_compute_instance" "{{ .Slug }}" {
  name         = "{{ .Name }}"
  machine_type = {{ with .Attr.machine_type }}"{{ . }}"{{ else }}"e2-medium"{{ end }}
  zone         = "{{ default "us-central1-a" .Region }}"
  boot_disk { initialize_params { image = "debian-cloud/debian-12" } }
  network_interface { network = "default" }
  service_account {
    email  = google_service_account.{{ .Slug }}.email
    scopes = ["https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write"]
  }
  lifecycle {
    ignore_changes = [boot_disk, network_interface, machine_type, metadata, labels, tags]
  }
}
