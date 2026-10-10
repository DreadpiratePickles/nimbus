# nimbus cloud ground-truth lab (AWS). UNVERIFIED: never applied; no lab credentials exist yet.
# Seeds the same scenarios and names as lab/local/estate.yaml. Real ARNs carry the real
# account id and AWS-assigned instance ids, so every resource is tagged nimbus_lab_id with the
# estate resource id it stands for; the e2e harness maps real ids to lab ids through that tag.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.60" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      nimbus_lab       = "true"
      cost_ceiling_usd = tostring(var.cost_ceiling_usd)
      expires_at       = var.expires_at
      owner            = var.owner
      managed_by       = "terraform/nimbus-lab"
    }
  }
}
