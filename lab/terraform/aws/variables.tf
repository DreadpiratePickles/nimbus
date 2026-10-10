variable "nimbus_e2e" {
  description = "Must be \"1\". Guards against an accidental apply: the lab is deliberately vulnerable."
  type        = string
  validation {
    condition     = var.nimbus_e2e == "1"
    error_message = "Refusing to build a deliberately vulnerable lab without nimbus_e2e=1 (NIMBUS_E2E=1 make lab-up)."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "cost_ceiling_usd" {
  description = "Monthly cost ceiling tag; the nightly destroy job and AWS Budgets alarm key off it."
  type        = number
  default     = 25
}

variable "expires_at" {
  description = "RFC3339 time after which the nightly job destroys the lab."
  type        = string
}

variable "owner" {
  type    = string
  default = "nimbus-lab"
}

variable "external_account_id" {
  description = "Account trusted by the vendor role (S04). Must be a real account you control; AWS rejects unknown principals."
  type        = string
}

variable "corp_cidr" {
  description = "Trusted corporate egress range for the seeded false positive (S13)."
  type        = string
  default     = "203.0.113.0/24"
}

variable "github_repo" {
  description = "owner/name of the unprotected repository trusted by the OIDC deploy role (S12)."
  type        = string
  default     = "nimbus-lab/infra-live"
}

variable "enable_eks" {
  description = "S07/S08 cost the most (~$75/month control plane + node); off by default."
  type        = bool
  default     = false
}

variable "enable_rds" {
  type    = bool
  default = true
}
