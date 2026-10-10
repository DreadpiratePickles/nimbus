# Least-change fix for world-open ingress on security group {{ .ShortID }} ({{ .Name }}), port(s){{ range .Ports }} {{ . }}{{ end }}.
# Requires Terraform >= 1.6 (import ids from variables). Nothing else on the group changes:
# the existing world-open rule for each port is imported and re-pointed at the first allowed
# CIDR (Terraform replaces that one rule, which removes the 0.0.0.0/0 entry); the remaining
# CIDRs get their own rules. Review the plan: only aws_vpc_security_group_ingress_rule changes.
# Find the rule ids:
# CLI: aws ec2 describe-security-group-rules --filters=Name=group-id,Values={{ sh .Raw.ShortID }} --query "SecurityGroupRules[?CidrIpv4=='0.0.0.0/0' && !IsEgress].[SecurityGroupRuleId,FromPort,ToPort]"

variable "{{ .Slug }}_allowed_cidrs" {
  description = "REQUIRED: CIDR ranges allowed on the previously world-open port(s), e.g. VPN or bastion ranges."
  type        = list(string)
  validation {
    condition     = length(var.{{ .Slug }}_allowed_cidrs) > 0 && alltrue([for c in var.{{ .Slug }}_allowed_cidrs : can(cidrhost(c, 0)) && !endswith(c, "/0")])
    error_message = "Provide at least one valid IPv4 CIDR; /0 ranges are not allowed."
  }
}
{{ range .Ports }}
variable "{{ $.Slug }}_open_rule_id_{{ . }}" {
  description = "REQUIRED: id (sgr-...) of the existing world-open ingress rule that covers port {{ . }}."
  type        = string
  validation {
    condition     = startswith(var.{{ $.Slug }}_open_rule_id_{{ . }}, "sgr-")
    error_message = "Expected a security group rule id (sgr-...)."
  }
}

import {
  to = aws_vpc_security_group_ingress_rule.{{ $.Slug }}_tcp_{{ . }}
  id = var.{{ $.Slug }}_open_rule_id_{{ . }}
}

resource "aws_vpc_security_group_ingress_rule" "{{ $.Slug }}_tcp_{{ . }}" {
  security_group_id = "{{ $.ShortID }}"
  description       = "Restricted by nimbus (was open to the world)"
  ip_protocol       = "tcp"
  from_port         = {{ . }}
  to_port           = {{ . }}
  cidr_ipv4         = var.{{ $.Slug }}_allowed_cidrs[0]
}

resource "aws_vpc_security_group_ingress_rule" "{{ $.Slug }}_tcp_{{ . }}_extra" {
  for_each          = toset(slice(var.{{ $.Slug }}_allowed_cidrs, 1, length(var.{{ $.Slug }}_allowed_cidrs)))
  security_group_id = "{{ $.ShortID }}"
  description       = "Restricted by nimbus"
  ip_protocol       = "tcp"
  from_port         = {{ . }}
  to_port           = {{ . }}
  cidr_ipv4         = each.value
}
{{ end }}
