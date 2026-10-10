# Moves {{ .Name }} off the default compute service account onto a dedicated one.
# The new account starts with NO roles: grant the roles the workload needs before applying, or
# its API calls will fail. Changing the service account stops and restarts the instance
# (allow_stopping_for_update); schedule it.
resource "google_service_account" "{{ .Slug }}" {
  account_id   = "{{ dnslabel .Slug 26 }}-sa"
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
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    network = "default"
  }
  service_account {
    email  = google_service_account.{{ .Slug }}.email
    scopes = ["cloud-platform"] # access is governed by the account's IAM roles, not scopes
  }
  allow_stopping_for_update = true
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [boot_disk, network_interface, machine_type, metadata, metadata_startup_script, labels, tags, zone, scheduling, shielded_instance_config, attached_disk, desired_status]
  }
}
