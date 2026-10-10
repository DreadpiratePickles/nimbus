# nimbus cloud lab: GCP stub (S09 public GCE instance running as the default compute SA with
# roles/editor). UNVERIFIED: never planned or applied; no GCP lab project exists yet.
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

variable "nimbus_e2e" {
  type = string
  validation {
    condition     = var.nimbus_e2e == "1"
    error_message = "Refusing to build a deliberately vulnerable lab without nimbus_e2e=1."
  }
}
variable "project_id" { type = string }
variable "project_number" { type = string }
variable "cost_ceiling_usd" {
  type    = number
  default = 25
}
variable "expires_at" { type = string }

locals {
  default_sa = "${var.project_number}-compute@developer.gserviceaccount.com"
  labels     = { nimbus_lab = "true", cost_ceiling_usd = tostring(var.cost_ceiling_usd), expires_at = replace(lower(var.expires_at), ":", "-") }
}

# New projects no longer grant Editor to the default compute SA; the lab grants it explicitly.
resource "google_project_iam_member" "default_sa_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${local.default_sa}"
}

resource "google_compute_firewall" "ssh_any" {
  name          = "nimbus-lab-allow-ssh-any"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  target_tags = ["nimbus-lab"]
}

resource "google_compute_instance" "web" {
  name         = "nimbus-lab-gce-web"
  zone         = "us-central1-a"
  machine_type = "e2-micro"
  tags         = ["nimbus-lab"]
  labels       = local.labels
  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }
  network_interface {
    network = "default"
    access_config {} # external IP
  }
  service_account {
    email  = local.default_sa
    scopes = ["cloud-platform"]
  }
}
