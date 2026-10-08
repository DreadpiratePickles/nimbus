# Public IPs are assigned at launch; move the workload behind a load balancer or NAT.
import {
  to = aws_instance.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_instance" "{{ .Slug }}" {
  ami                         = null
  instance_type               = null
  associate_public_ip_address = false
  lifecycle {
    ignore_changes = [ami, instance_type, tags, user_data, security_groups, vpc_security_group_ids, subnet_id]
  }
}
