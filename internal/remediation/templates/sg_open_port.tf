# Replaces world-open ingress on security group {{ .Name }} with an allow-list.
variable "{{ .Slug }}_allowed_cidrs" {
  description = "CIDR ranges allowed to reach the previously world-open ports"
  type        = list(string)
  default     = []   # e.g. ["10.0.0.0/8", "203.0.113.4/32"]
}

import {
  to = aws_security_group.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "aws_security_group" "{{ .Slug }}" {
  name        = "{{ .Name }}"
  description = "Managed by cloud-posture; ingress restricted"
  vpc_id      = {{ with .Attr.vpc_id }}"{{ . }}"{{ else }}null # TODO: set vpc_id{{ end }}
  lifecycle {
    ignore_changes = [description, tags]
  }
}
{{ range .Ports }}
resource "aws_vpc_security_group_ingress_rule" "{{ $.Slug }}_tcp_{{ . }}" {
  for_each          = toset(var.{{ $.Slug }}_allowed_cidrs)
  security_group_id = aws_security_group.{{ $.Slug }}.id
  ip_protocol       = "tcp"
  from_port         = {{ . }}
  to_port           = {{ . }}
  cidr_ipv4         = each.value
}
{{ end }}
