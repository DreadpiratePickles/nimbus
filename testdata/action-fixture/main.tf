# Action e2e fixture (P1-PLANDIFF D4): one module, an EC2 instance whose instance profile holds
# AdministratorAccess, behind a security group whose SSH rule source is var.ssh_cidr.
#
#   base state (fixture.tfstate)         ssh_cidr = 203.0.113.0/24   (trusted corporate range)
#   "bad" PR                             -var ssh_cidr=0.0.0.0/0     → opens 1 attack path
#   revert PR (state = bad, default var)                             → closes 1 attack path
#
# The provider is configured with mock credentials and every API check skipped: `plan -refresh=false`
# against the committed state makes no AWS call. Never apply this module.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "5.100.0" }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock-access-key"
  secret_key                  = "mock-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

variable "ssh_cidr" {
  type    = string
  default = "203.0.113.0/24"
}

module "web" {
  source   = "./modules/web"
  ssh_cidr = var.ssh_cidr
}
