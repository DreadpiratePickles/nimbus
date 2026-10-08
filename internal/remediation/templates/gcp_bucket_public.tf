import {
  to = google_storage_bucket.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "google_storage_bucket" "{{ .Slug }}" {
  name                        = "{{ .Name }}"
  location                    = "{{ default "US" .Region }}"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  lifecycle {
    ignore_changes = [location, storage_class, labels, versioning, lifecycle_rule, cors, website, logging, encryption]
  }
}
# CLI: gcloud storage buckets update gs://{{ .Name }} --public-access-prevention --uniform-bucket-level-access
