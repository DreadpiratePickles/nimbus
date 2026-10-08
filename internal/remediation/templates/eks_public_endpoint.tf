import {
  to = aws_eks_cluster.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_eks_cluster" "{{ .Slug }}" {
  name     = "{{ .Name }}"
  role_arn = {{ with .Attr.roleArn }}"{{ . }}"{{ else }}null{{ end }}
  vpc_config {
    subnet_ids              = []
    endpoint_private_access = true
    endpoint_public_access  = false
  }
  lifecycle {
    ignore_changes = [role_arn, version, vpc_config[0].subnet_ids, vpc_config[0].security_group_ids, tags, kubernetes_network_config, encryption_config, enabled_cluster_log_types]
  }
}
# CLI: aws eks update-cluster-config --name {{ .Name }} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true
