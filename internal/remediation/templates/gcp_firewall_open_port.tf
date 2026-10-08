variable "{{ .Slug }}_allowed_ranges" {
  type    = list(string)
  default = ["10.0.0.0/8"]
}

import {
  to = google_compute_firewall.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "google_compute_firewall" "{{ .Slug }}" {
  name          = "{{ .Name }}"
  network       = {{ with .Attr.network }}"{{ . }}"{{ else }}"default"{{ end }}
  direction     = "INGRESS"
  source_ranges = var.{{ .Slug }}_allowed_ranges
  allow {
    protocol = "tcp"
    ports    = [{{ range $i, $p := .Ports }}{{ if $i }}, {{ end }}"{{ $p }}"{{ end }}]
  }
  lifecycle {
    ignore_changes = [description, priority, target_tags, target_service_accounts]
  }
}
