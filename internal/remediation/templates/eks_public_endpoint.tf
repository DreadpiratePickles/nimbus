# Least-change fix for EKS cluster {{ .Name }}: the API endpoint becomes private (reachable from
# the VPC, peered networks and VPN). To keep a public endpoint for known networks instead, set
# keep_public_endpoint = true and list them in public_access_cidrs (0.0.0.0/0 is refused).
# Only the endpoint settings are managed; subnets, security groups, version, logging and
# encryption are ignored so the imported cluster is not replaced.
# Current endpoint settings:
# CLI: aws eks describe-cluster --name={{ sh .Raw.Name }} --query cluster.resourcesVpcConfig

variable "{{ .Slug }}_keep_public_endpoint" {
  description = "Keep the public endpoint of {{ .Name }}, restricted to public_access_cidrs. false makes the endpoint private only."
  type        = bool
  default     = false
}

variable "{{ .Slug }}_public_access_cidrs" {
  description = "Networks (office egress, CI runners, VPN) allowed to reach the public endpoint when keep_public_endpoint is true."
  type        = list(string)
  default     = []
  validation {
    condition     = !contains(var.{{ .Slug }}_public_access_cidrs, "0.0.0.0/0") && alltrue([for c in var.{{ .Slug }}_public_access_cidrs : can(cidrhost(c, 0))])
    error_message = "List specific CIDR ranges; the world-open range is what this fix removes."
  }
}

import {
  to = aws_eks_cluster.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_eks_cluster" "{{ .Slug }}" {
  name     = "{{ .Name }}"
  role_arn = {{ with .Attr.roleArn }}"{{ . }}"{{ else }}null{{ end }}
  vpc_config {
    subnet_ids              = [] # ignored below: the live subnets stay
    endpoint_private_access = true
    endpoint_public_access  = var.{{ .Slug }}_keep_public_endpoint
    public_access_cidrs     = var.{{ .Slug }}_keep_public_endpoint ? var.{{ .Slug }}_public_access_cidrs : null
  }
  lifecycle {
    ignore_changes = [role_arn, version, vpc_config[0].subnet_ids, vpc_config[0].security_group_ids, tags, kubernetes_network_config, encryption_config, enabled_cluster_log_types]
    precondition {
      condition     = !var.{{ .Slug }}_keep_public_endpoint || length(var.{{ .Slug }}_public_access_cidrs) > 0
      error_message = "keep_public_endpoint needs at least one CIDR in public_access_cidrs."
    }
  }
}
# CLI: aws eks update-cluster-config --name={{ sh .Raw.Name }} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true
