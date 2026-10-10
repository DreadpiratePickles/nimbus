# Public IPs are assigned at launch: associate_public_ip_address forces REPLACEMENT of an
# existing instance. prevent_destroy makes `terraform plan` stop instead of replacing it.
# Preferred path without replacement: move the workload behind a load balancer / NAT, or
# remove the public IPv4 from the primary ENI:
#   aws ec2 modify-network-interface-attribute --network-interface-id <eni-id> --no-associate-public-ip-address
import {
  to = aws_instance.{{ .Slug }}
  id = "{{ .ShortID }}"
}

resource "aws_instance" "{{ .Slug }}" {
  ami                         = null
  instance_type               = null
  associate_public_ip_address = false
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [ami, instance_type, tags, tags_all, user_data, user_data_base64, security_groups, vpc_security_group_ids, subnet_id, key_name, iam_instance_profile, root_block_device, ebs_block_device, network_interface, metadata_options]
  }
}
