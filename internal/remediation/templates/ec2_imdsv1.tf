import {
  to = aws_instance.{{ .Slug }}
  id = "{{ .ShortID }}"
}

resource "aws_instance" "{{ .Slug }}" {
  # Only metadata_options is managed; every other argument is ignored so the imported instance
  # is not modified or replaced. Review the plan: it must show an in-place update only.
  ami           = {{ with .Attr.ImageId }}"{{ . }}"{{ else }}null{{ end }}
  instance_type = {{ with .Attr.InstanceType }}"{{ . }}"{{ else }}null{{ end }}

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # raise to 2 if containers on the host need IMDS
  }

  lifecycle {
    ignore_changes = [ami, instance_type, tags, tags_all, user_data, user_data_base64, user_data_replace_on_change, subnet_id, vpc_security_group_ids, security_groups, key_name, iam_instance_profile, associate_public_ip_address, private_ip, secondary_private_ips, ebs_optimized, monitoring, root_block_device, ebs_block_device, ephemeral_block_device, network_interface, credit_specification, disable_api_termination, disable_api_stop, instance_initiated_shutdown_behavior, placement_group, tenancy, availability_zone, source_dest_check, launch_template, hibernation, maintenance_options, private_dns_name_options, capacity_reservation_specification, enclave_options, volume_tags]
  }
}
# Immediate CLI equivalent:
# CLI: aws ec2 modify-instance-metadata-options --instance-id={{ sh .Raw.ShortID }} --http-tokens required --http-endpoint enabled{{ with .Raw.Region }} --region={{ sh . }}{{ end }}
