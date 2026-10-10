# Least-change fix for firewall rule {{ .Name }}: only source_ranges changes. The allow block is
# ignored so ports are not rewritten; every port this rule allows is narrowed to the new ranges.
variable "{{ .Slug }}_allowed_ranges" {
  description = "REQUIRED: source ranges allowed by {{ .Name }}. For SSH/RDP through Identity-Aware Proxy use [\"35.235.240.0/20\"]."
  type        = list(string)
  validation {
    condition     = length(var.{{ .Slug }}_allowed_ranges) > 0 && alltrue([for c in var.{{ .Slug }}_allowed_ranges : can(cidrhost(c, 0)) && !endswith(c, "/0")])
    error_message = "Provide at least one valid range; /0 ranges are not allowed."
  }
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
    ignore_changes = [allow, deny, network, description, priority, target_tags, target_service_accounts, source_tags, source_service_accounts, log_config, disabled]
  }
}
