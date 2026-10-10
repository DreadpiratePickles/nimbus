# Least-change fix for instance {{ .Name }}: it stops being reachable from the internet on port(s){{ range .Ports }} {{ . }}{{ end }}.
# The world-open rule lives on a security group the instance uses (often shared), so this file adds
# a replacement group that admits the port(s) only from allowed_cidrs; nothing is removed here.
#   1. List the instance's groups and the world-open ingress rules on them:
# CLI: aws ec2 describe-instances --instance-ids={{ sh .Raw.ShortID }} --query "Reservations[].Instances[].SecurityGroups[].GroupId"
#   2. terraform apply this file, then put the instance on the new group plus any group that is not world-open:
# CLI: aws ec2 modify-instance-attribute --instance-id={{ sh .Raw.ShortID }} --groups "$RESTRICTED_SG_ID" $OTHER_PRIVATE_SG_IDS
#   3. Only when no other instance needs it, revoke the world-open rule on the old group (see sg_open_port.tf).

variable "{{ .Slug }}_allowed_cidrs" {
  description = "Source CIDRs that keep reaching {{ .Name }} (office / VPN egress, load balancer subnets). REQUIRED: a world-open range is what this fix removes."
  type        = list(string)
  validation {
    condition     = length(var.{{ .Slug }}_allowed_cidrs) > 0 && alltrue([for c in var.{{ .Slug }}_allowed_cidrs : can(cidrhost(c, 0)) && !contains(["0.0.0.0/0", "::/0"], c)])
    error_message = "List specific CIDRs; 0.0.0.0/0 and ::/0 re-open the instance."
  }
}

variable "{{ .Slug }}_vpc_id" {
  description = "VPC id of {{ .Name }} (VpcId in describe-instances)."
  type        = string
  {{- with .Attr.vpc_id }}
  default     = "{{ . }}"
  {{- end }}
}

resource "aws_security_group" "{{ .Slug }}_restricted" {
  name        = "{{ dnslabel .Slug 40 }}-restricted"
  description = "nimbus: {{ .Name }} reachable only from allowed CIDRs"
  vpc_id      = var.{{ .Slug }}_vpc_id
}
{{ range .Ports }}
resource "aws_vpc_security_group_ingress_rule" "{{ $.Slug }}_p{{ . }}" {
  for_each          = toset(var.{{ $.Slug }}_allowed_cidrs)
  security_group_id = aws_security_group.{{ $.Slug }}_restricted.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port   = {{ . }}
  to_port     = {{ . }}
}
{{ end }}
output "{{ .Slug }}_restricted_sg_id" {
  value = aws_security_group.{{ .Slug }}_restricted.id
}
