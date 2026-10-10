# Least-change fix for GCE instance {{ .Name }}: remove its external IPv4 (the access config on
# nic0) so it is no longer addressable from the internet. Removing an access config is in place (no
# restart); Terraform would recreate the instance to change network_interface, so the change is a
# CLI step and Terraform only adds the replacement path in (Cloud NAT for egress, IAP for SSH).
# CLI: gcloud compute instances describe --zone={{ sh (default "us-central1-a" .Raw.Region) }} --format="value(networkInterfaces[0].accessConfigs[0].name)" -- {{ sh .Raw.Name }}
# CLI: gcloud compute instances delete-access-config --zone={{ sh (default "us-central1-a" .Raw.Region) }} --access-config-name="$ACCESS_CONFIG_NAME" -- {{ sh .Raw.Name }}

variable "{{ .Slug }}_network" {
  description = "VPC network of {{ .Name }}."
  type        = string
  default     = "default"
}

variable "{{ .Slug }}_iap_ssh" {
  description = "Allow SSH to the instance through Identity-Aware Proxy (35.235.240.0/20) after the external IP is gone."
  type        = bool
  default     = true
}

resource "google_compute_firewall" "{{ .Slug }}_iap_ssh" {
  count         = var.{{ .Slug }}_iap_ssh ? 1 : 0
  name          = "{{ dnslabel .Slug 40 }}-iap-ssh"
  network       = var.{{ .Slug }}_network
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
