# Canonical check catalog

Every scanner's native check IDs map onto these canonical IDs; weaknesses feed the attack-path engine; compliance keys drive the reports.

The section below is generated from `internal/catalog/catalog.yaml` by `go generate ./internal/catalog/...`; `TestChecksDocInSync` fails when it drifts. Edit the catalog, not this list.

<!-- BEGIN GENERATED CATALOG: go generate ./internal/catalog/... (do not edit by hand) -->

## ACCESS_ANALYZER_DISABLED

**IAM Access Analyzer not enabled in region** — provider `aws`, default severity `LOW`, resource `aws_accessanalyzer_analyzer`

- Weaknesses: NO_LOGGING
- prowler: `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings`
- steampipe: `iam_access_analyzer_enabled`
- cis_aws: 1.20
- nist_800_53: AC-6(9), CA-7

## AZ_AKS_RBAC_DISABLED

**AKS cluster RBAC disabled** — provider `azure`, default severity `HIGH`, resource `azure_kubernetes_cluster`

- Weaknesses: OVERPRIVILEGED_IDENTITY, K8S_API
- prowler: `aks_cluster_rbac_enabled`, `aks_clusters_public_access_disabled`
- checkov: `CKV_AZURE_5`, `CKV_AZURE_115`
- trivy: `AVD-AZU-0042`
- steampipe: `kubernetes_cluster_rbac_enabled`
- cis_azure: 8.1
- nist_800_53: AC-3, AC-6

## AZ_KEYVAULT_NO_SOFTDELETE

**Key Vault without soft-delete / purge protection** — provider `azure`, default severity `MEDIUM`, resource `azure_key_vault`

- Weaknesses: NO_BACKUP
- prowler: `keyvault_recoverable`
- checkov: `CKV_AZURE_42`, `CKV_AZURE_110`
- trivy: `AVD-AZU-0016`
- scoutsuite: `keyvault-no-soft-delete`
- steampipe: `keyvault_purge_protection_enabled`, `keyvault_soft_delete_enabled`
- cis_azure: 8.5
- nist_800_53: CP-9
- Fix templates: az_keyvault_softdelete.tf, az_keyvault_softdelete.bicep

## AZ_MFA_DISABLED

**Entra ID user or admin without MFA** — provider `azure`, default severity `CRITICAL`, resource `azure_user`

- Weaknesses: NO_MFA, WEAK_AUTH
- prowler: `entra_users_mfa_capable`, `entra_privileged_user_has_mfa`, `entra_non_privileged_user_has_mfa`, `entra_security_defaults_enabled`
- scoutsuite: `aad-users-no-mfa`
- steampipe: `iam_user_not_allowed_to_create_security_group`, `ad_user_mfa_enabled`
- cis_azure: 1.1.1, 1.1.2
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)

## AZ_NSG_OPEN_RDP

**Network security group allows RDP from the internet** — provider `azure`, default severity `HIGH`, resource `azure_network_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `network_rdp_internet_access_restricted`
- checkov: `CKV_AZURE_9`
- trivy: `AVD-AZU-0048`
- scoutsuite: `network-security-groups-rule-inbound-rdp`
- steampipe: `network_security_group_rdp_access_restricted`
- cis_azure: 6.1
- nist_800_53: SC-7
- pci_dss: 1.2.1
- Fix templates: az_nsg_open_port.tf, az_nsg_open_port.bicep

## AZ_NSG_OPEN_SSH

**Network security group allows SSH from the internet** — provider `azure`, default severity `HIGH`, resource `azure_network_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `network_ssh_internet_access_restricted`
- checkov: `CKV_AZURE_10`
- trivy: `AVD-AZU-0050`
- scoutsuite: `network-security-groups-rule-inbound-ssh`
- steampipe: `network_security_group_ssh_access_restricted`
- cis_azure: 6.2
- nist_800_53: SC-7
- pci_dss: 1.2.1
- Fix templates: az_nsg_open_port.tf, az_nsg_open_port.bicep

## AZ_NSG_UNRESTRICTED_SOURCE

**Network security group rule allows inbound traffic from any source address** — provider `azure`, default severity `HIGH`, resource `azure_network_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- trivy: `AVD-AZU-0047`
- nist_800_53: SC-7, AC-4
- pci_dss: 1.3.1
- Fix templates: az_nsg_open_port.tf, az_nsg_open_port.bicep

## AZ_SQL_NO_TDE

**Azure SQL transparent data encryption disabled** — provider `azure`, default severity `HIGH`, resource `azure_sql_database`

- Weaknesses: UNENCRYPTED_AT_REST, DATABASE
- prowler: `sqlserver_tde_encryption_enabled`
- checkov: `CKV_AZURE_144`
- scoutsuite: `sqldatabase-no-tde`
- steampipe: `sql_database_transparent_data_encryption_enabled`
- cis_azure: 4.1.5
- nist_800_53: SC-28
- pci_dss: 3.4
- hipaa: 164.312(a)(2)(iv)

## AZ_SQL_PUBLIC

**Azure SQL server allows public network access** — provider `azure`, default severity `CRITICAL`, resource `azure_sql_server`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE, DATABASE
- prowler: `sqlserver_firewall_rules_no_ingress_from_internet`
- checkov: `CKV_AZURE_35`, `CKV_AZURE_112`
- trivy: `AVD-AZU-0022`, `AVD-AZU-0029`
- scoutsuite: `sqldatabase-firewall-allows-all`
- steampipe: `sql_server_public_network_access_disabled`
- cis_azure: 4.1.2
- nist_800_53: SC-7
- pci_dss: 1.3.6
- hipaa: 164.312(e)(1)

## AZ_STORAGE_HTTP_ALLOWED

**Storage account does not require HTTPS** — provider `azure`, default severity `MEDIUM`, resource `azure_storage_account`

- Weaknesses: UNENCRYPTED_IN_TRANSIT
- prowler: `storage_secure_transfer_required_is_enabled`
- checkov: `CKV_AZURE_3`
- trivy: `AVD-AZU-0008`
- scoutsuite: `storageaccounts-https-traffic-disabled`
- steampipe: `storage_account_secure_transfer_required_enabled`
- cis_azure: 3.1
- nist_800_53: SC-8
- pci_dss: 4.1
- Fix templates: az_storage_https.tf, az_storage_https.bicep

## AZ_STORAGE_LOGGING_DISABLED

**Storage account service logging (blob / queue) disabled** — provider `azure`, default severity `LOW`, resource `azure_storage_account`

- Weaknesses: NO_LOGGING
- checkov: `CKV2_AZURE_21`, `CKV_AZURE_33`
- trivy: `AVD-AZU-0057`
- nist_800_53: AU-2, AU-12

## AZ_STORAGE_NETWORK_UNRESTRICTED

**Storage account network rules allow access from all networks** — provider `azure`, default severity `MEDIUM`, resource `azure_storage_account`

- checkov: `CKV_AZURE_59`
- trivy: `AVD-AZU-0012`
- scoutsuite: `storageaccounts-public-traffic-allowed`
- steampipe: `storage_account_default_network_access_rule_denied`
- cis_azure: 3.8
- nist_800_53: SC-7

## AZ_STORAGE_NO_CMK

**Storage account is not encrypted with a customer-managed key** — provider `azure`, default severity `LOW`, resource `azure_storage_account`

- checkov: `CKV2_AZURE_1`
- trivy: `AVD-AZU-0060`
- nist_800_53: SC-12, SC-28

## AZ_STORAGE_NO_PRIVATE_ENDPOINT

**Storage account is not reached through a private endpoint** — provider `azure`, default severity `LOW`, resource `azure_storage_account`

- checkov: `CKV2_AZURE_33`
- nist_800_53: SC-7

## AZ_STORAGE_PUBLIC_BLOB

**Storage account allows anonymous blob access** — provider `azure`, default severity `HIGH`, resource `azure_storage_account`

- Weaknesses: PUBLIC_DATA_STORE
- prowler: `storage_blob_public_access_level_is_disabled`
- checkov: `CKV_AZURE_190`, `CKV_AZURE_34`, `CKV2_AZURE_47`
- trivy: `AVD-AZU-0007`
- scoutsuite: `storageaccounts-public-blob-access`
- steampipe: `storage_account_blob_public_access_disabled`
- cis_azure: 3.7
- nist_800_53: AC-3, SC-7
- pci_dss: 1.3.1
- hipaa: 164.312(a)(1)
- gdpr: Art.32
- Fix templates: az_storage_public_blob.tf, az_storage_public_blob.bicep

## AZ_STORAGE_SAS_NO_EXPIRATION

**Storage account has no SAS expiration policy** — provider `azure`, default severity `LOW`, resource `azure_storage_account`

- checkov: `CKV2_AZURE_41`
- nist_800_53: AC-2, IA-5

## AZ_STORAGE_SHARED_KEY_ENABLED

**Storage account allows Shared Key (account key) authorization** — provider `azure`, default severity `MEDIUM`, resource `azure_storage_account`

- checkov: `CKV2_AZURE_40`
- nist_800_53: IA-2, IA-5

## AZ_STORAGE_TLS_MIN_VERSION

**Storage account allows TLS versions below 1.2** — provider `azure`, default severity `MEDIUM`, resource `azure_storage_account`

- Weaknesses: WEAK_TLS
- prowler: `storage_ensure_minimum_tls_version_12`
- checkov: `CKV_AZURE_44`
- trivy: `AVD-AZU-0011`
- cis_azure: 3.15
- nist_800_53: SC-8, SC-13
- pci_dss: 4.1

## AZ_VM_DISK_UNENCRYPTED

**Virtual machine disk not encrypted with CMK** — provider `azure`, default severity `MEDIUM`, resource `azure_managed_disk`

- Weaknesses: UNENCRYPTED_AT_REST
- prowler: `vm_ensure_attached_disks_encrypted_with_cmk`, `vm_ensure_unattached_disks_encrypted_with_cmk`
- checkov: `CKV_AZURE_2`, `CKV_AZURE_93`
- trivy: `AVD-AZU-0038`
- scoutsuite: `virtualmachines-disk-encryption-disabled`
- steampipe: `compute_disk_unattached_encrypted_with_cmk`, `compute_vm_attached_disks_encrypted_with_cmk`
- cis_azure: 7.3
- nist_800_53: SC-28
- pci_dss: 3.4

## BEDROCK_AGENT_PUBLIC

**Bedrock agent is invoked by an unauthenticated public endpoint** — provider `aws`, default severity `HIGH`, resource `aws_bedrockagent_agent`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- nimbus-lab: `bedrock_agent_publicly_invocable`
- nist_800_53: AC-3, SC-7
- Fix templates: bedrock_agent_private.tf

## CLOUDTRAIL_DISABLED

**CloudTrail not enabled in all regions** — provider `aws`, default severity `HIGH`, resource `aws_cloudtrail`

- Weaknesses: NO_LOGGING
- prowler: `cloudtrail_multi_region_enabled`, `cloudtrail_multi_region_enabled_logging_management_events`, `cloudtrail_cloudwatch_logging_enabled`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled`, `config_recorder_all_regions_enabled`, `vpc_flow_logs_enabled`
- checkov: `CKV_AWS_67`
- trivy: `AVD-AWS-0014`
- scoutsuite: `cloudtrail-not-configured`, `cloudtrail-no-global-services-logging`
- steampipe: `cloudtrail_multi_region_trail_enabled`, `cloudtrail_trail_enabled`
- cis_aws: 3.1
- nist_800_53: AU-2, AU-12
- pci_dss: 10.1, 10.2
- hipaa: 164.312(b)
- gdpr: Art.30
- Fix templates: cloudtrail_disabled.tf, cloudtrail_disabled.cfn.yaml

## CLOUDTRAIL_NO_LOG_VALIDATION

**CloudTrail log file validation disabled** — provider `aws`, default severity `LOW`, resource `aws_cloudtrail`

- Weaknesses: NO_LOGGING
- prowler: `cloudtrail_log_file_validation_enabled`
- checkov: `CKV_AWS_36`
- trivy: `AVD-AWS-0016`
- scoutsuite: `cloudtrail-no-log-file-validation`
- steampipe: `cloudtrail_trail_validation_enabled`
- cis_aws: 3.2
- nist_800_53: AU-9
- pci_dss: 10.5.5
- Fix templates: cloudtrail_no_log_validation.tf

## CLOUDWATCH_NO_ALARMS

**No CloudWatch metric filter / alarm for security-relevant events** — provider `aws`, default severity `MEDIUM`, resource `aws_cloudwatch_log_metric_filter`

- Weaknesses: NO_LOGGING
- prowler: `cloudwatch_log_metric_filter_unauthorized_api_calls`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_aws_organizations_changes`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`
- steampipe: `log_metric_filter_unauthorized_api`, `log_metric_filter_root_login`, `log_metric_filter_iam_policy`, `log_metric_filter_security_group`, `log_metric_filter_console_authentication_failure`
- cis_aws: 4.1, 4.3, 4.4, 4.6, 4.10, 4.15, 4.5
- nist_800_53: AU-6, SI-4
- pci_dss: 10.4
- hipaa: 164.312(b)

## CVE_VULNERABILITY

**Known vulnerability in image or package** — provider `kubernetes`, default severity `HIGH`, resource `container_image`

- Weaknesses: UNPATCHED
- trivy: `CVE`
- nist_800_53: SI-2, RA-5
- pci_dss: 6.2, 11.3
- hipaa: 164.308(a)(1)(ii)(B)

## EBS_UNENCRYPTED

**EBS volume not encrypted** — provider `aws`, default severity `MEDIUM`, resource `aws_ebs_volume`

- Weaknesses: UNENCRYPTED_AT_REST
- prowler: `ec2_ebs_volume_encryption`, `ec2_ebs_default_encryption`, `efs_encryption_at_rest_enabled`
- checkov: `CKV_AWS_3`, `CKV_AWS_189`, `CKV_AWS_8`
- trivy: `AVD-AWS-0026`, `AVD-AWS-0131`
- scoutsuite: `ec2-ebs-volume-not-encrypted`
- steampipe: `ebs_attached_volume_encryption_enabled`, `ebs_volume_encryption_at_rest_enabled`
- cis_aws: 2.2.1
- nist_800_53: SC-28
- pci_dss: 3.4
- hipaa: 164.312(a)(2)(iv)
- Fix templates: ebs_unencrypted.tf

## EC2_IMDSV1

**EC2 instance allows IMDSv1 (metadata credential theft)** — provider `aws`, default severity `HIGH`, resource `aws_instance`

- Weaknesses: IMDSV1_ENABLED
- prowler: `ec2_instance_imdsv2_enabled`
- checkov: `CKV_AWS_79`
- trivy: `AVD-AWS-0028`
- scoutsuite: `ec2-instance-imdsv1-enabled`
- steampipe: `ec2_instance_uses_imdsv2`
- cis_aws: 5.6
- nist_800_53: IA-5, AC-6
- pci_dss: 2.2
- Fix templates: ec2_imdsv1.tf, ec2_imdsv1.cfn.yaml

## EC2_INSTANCE_PORT_EXPOSED

**EC2 instance reachable on an administrative or service port from the internet** — provider `aws`, default severity `HIGH`, resource `aws_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `ec2_instance_port_ssh_exposed_to_internet`, `ec2_instance_port_rdp_exposed_to_internet`, `ec2_instance_port_https_exposed_to_internet`, `ec2_instance_port_http_exposed_to_internet`, `ec2_instance_port_telnet_exposed_to_internet`, `ec2_instance_port_ftp_exposed_to_internet`
- nist_800_53: SC-7, AC-4
- pci_dss: 1.2.1, 1.3.1
- Fix templates: ec2_instance_port_exposed.tf

## EC2_NO_DETAILED_MONITORING

**EC2 instance detailed (1-minute) CloudWatch monitoring disabled** — provider `aws`, default severity `LOW`, resource `aws_instance`

- prowler: `ec2_instance_detailed_monitoring_enabled`
- checkov: `CKV_AWS_126`
- nist_800_53: SI-4

## EC2_PUBLIC_IP

**EC2 instance has a public IP address** — provider `aws`, default severity `MEDIUM`, resource `aws_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `ec2_instance_public_ip`
- checkov: `CKV_AWS_88`
- trivy: `AVD-AWS-0009`
- scoutsuite: `ec2-instance-with-public-ip`
- steampipe: `ec2_instance_not_publicly_accessible`
- nist_800_53: SC-7
- pci_dss: 1.3.2
- Fix templates: ec2_public_ip.tf

## EC2_SG_NO_DESCRIPTION

**Security group or rule has no description** — provider `aws`, default severity `LOW`, resource `aws_security_group`

- checkov: `CKV_AWS_23`
- trivy: `AVD-AWS-0099`, `AVD-AWS-0124`
- nist_800_53: CM-6, CM-8

## EC2_SG_OPEN_ALL

**Security group allows all traffic from the internet** — provider `aws`, default severity `CRITICAL`, resource `aws_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `ec2_securitygroup_allow_ingress_from_internet_to_any_port`, `ec2_securitygroup_allow_wide_open_public_ipv4`, `ec2_securitygroup_default_restrict_traffic`
- checkov: `CKV_AWS_277`
- scoutsuite: `ec2-security-group-opens-all-ports-to-all`
- steampipe: `vpc_security_group_restrict_ingress_common_ports_all`, `vpc_security_group_restrict_ingress_tcp_udp_all`
- cis_aws: 5.2, 5.3
- nist_800_53: SC-7
- pci_dss: 1.2.1, 1.3.1
- Fix templates: sg_open_port.tf, sg_open_port.cfn.yaml

## EC2_SG_OPEN_EGRESS

**Security group allows unrestricted egress to the internet** — provider `aws`, default severity `LOW`, resource `aws_security_group`

- checkov: `CKV_AWS_382`
- trivy: `AVD-AWS-0104`
- nist_800_53: SC-7, SC-7(5)
- pci_dss: 1.3.2

## EC2_SG_OPEN_HTTP

**Security group allows HTTP (80) from the internet** — provider `aws`, default severity `MEDIUM`, resource `aws_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- checkov: `CKV_AWS_260`
- nist_800_53: SC-7, SC-8
- pci_dss: 1.2.1, 1.3.1
- Fix templates: sg_open_port.tf, sg_open_port.cfn.yaml

## EC2_SG_OPEN_RDP

**Security group allows RDP (3389) from the internet** — provider `aws`, default severity `HIGH`, resource `aws_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389`
- checkov: `CKV_AWS_25`
- scoutsuite: `ec2-security-group-opens-RDP-port-to-all`
- steampipe: `vpc_security_group_restrict_ingress_rdp_all`
- cis_aws: 5.3
- nist_800_53: SC-7
- pci_dss: 1.2.1
- Fix templates: sg_open_port.tf, sg_open_port.cfn.yaml

## EC2_SG_OPEN_SSH

**Security group allows SSH (22) from the internet** — provider `aws`, default severity `HIGH`, resource `aws_security_group`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_22`
- checkov: `CKV_AWS_24`
- trivy: `AVD-AWS-0107`
- scoutsuite: `ec2-security-group-opens-SSH-port-to-all`
- steampipe: `vpc_security_group_restrict_ingress_ssh_all`
- cis_aws: 5.2
- nist_800_53: SC-7, AC-4
- pci_dss: 1.2.1, 1.3.1
- hipaa: 164.312(e)(1)
- Fix templates: sg_open_port.tf, sg_open_port.cfn.yaml

## EIP_UNASSIGNED

**Elastic IP allocated but not associated (cost + hygiene)** — provider `aws`, default severity `INFO`, resource `aws_eip`

- prowler: `ec2_elastic_ip_unassigned`
- steampipe: `vpc_eip_associated`
- nist_800_53: CM-8

## EKS_PUBLIC_ENDPOINT

**EKS cluster API endpoint publicly accessible** — provider `aws`, default severity `HIGH`, resource `aws_eks_cluster`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE, K8S_API
- prowler: `eks_control_plane_endpoint_access_publicly_accessible`, `eks_cluster_network_policy_enabled`
- checkov: `CKV_AWS_39`, `CKV_AWS_38`
- trivy: `AVD-AWS-0040`, `AVD-AWS-0041`
- steampipe: `eks_cluster_endpoint_restrict_public_access`, `eks_cluster_endpoint_public_access_restricted`
- cis_aws: 5.2
- nist_800_53: SC-7
- Fix templates: eks_public_endpoint.tf

## GCP_BUCKET_PUBLIC

**Cloud Storage bucket publicly accessible** — provider `gcp`, default severity `HIGH`, resource `gcp_storage_bucket`

- Weaknesses: PUBLIC_DATA_STORE
- prowler: `cloudstorage_bucket_public_access`
- checkov: `CKV_GCP_28`
- trivy: `AVD-GCP-0001`
- scoutsuite: `cloudstorage-bucket-allUsers`, `cloudstorage-bucket-allAuthenticatedUsers`
- steampipe: `storage_bucket_not_publicly_accessible`
- cis_gcp: 5.1
- nist_800_53: AC-3, SC-7
- pci_dss: 1.3.1
- hipaa: 164.312(a)(1)
- gdpr: Art.32
- Fix templates: gcp_bucket_public.tf

## GCP_BUCKET_UNIFORM_ACCESS_DISABLED

**Cloud Storage bucket does not use uniform bucket-level access** — provider `gcp`, default severity `MEDIUM`, resource `gcp_storage_bucket`

- checkov: `CKV_GCP_29`
- trivy: `AVD-GCP-0002`
- steampipe: `storage_bucket_uniform_access_enabled`
- cis_gcp: 5.2
- nist_800_53: AC-3

## GCP_DEFAULT_SA_FULL_ACCESS

**Compute instance uses default service account with full API access** — provider `gcp`, default severity `HIGH`, resource `gcp_compute_instance`

- Weaknesses: OVERPRIVILEGED_IDENTITY, DEFAULT_SERVICE_ACCOUNT
- prowler: `compute_instance_default_service_account_in_use`, `compute_instance_default_service_account_in_use_with_full_api_access`
- checkov: `CKV_GCP_30`
- trivy: `AVD-GCP-0044`
- scoutsuite: `computeengine-instance-default-service-account`, `computeengine-instance-full-api-access`
- steampipe: `compute_instance_with_no_default_service_account`, `compute_instance_with_no_default_service_account_with_full_access`
- cis_gcp: 4.1, 4.2
- nist_800_53: AC-6
- pci_dss: 7.1.2
- Fix templates: gcp_default_sa.tf

## GCP_DEFAULT_SA_PROJECT_ROLE

**Default compute / App Engine service account granted a project-level role** — provider `gcp`, default severity `MEDIUM`, resource `gcp_iam_binding`

- Weaknesses: DEFAULT_SERVICE_ACCOUNT
- checkov: `CKV_GCP_46`
- nist_800_53: AC-6

## GCP_DISK_NO_CSEK

**Compute disk is not encrypted with a customer-supplied key (CSEK)** — provider `gcp`, default severity `LOW`, resource `gcp_compute_instance`

- checkov: `CKV_GCP_38`
- trivy: `AVD-GCP-0033`
- cis_gcp: 4.7
- nist_800_53: SC-12, SC-28

## GCP_FIREWALL_OPEN_RDP

**VPC firewall allows RDP from the internet** — provider `gcp`, default severity `HIGH`, resource `gcp_compute_firewall`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `compute_firewall_rdp_access_from_the_internet_allowed`
- checkov: `CKV_GCP_3`
- trivy: `AVD-GCP-0028`, `AVD-GCP-0070`
- scoutsuite: `computeengine-firewall-rule-allows-internal-traffic-rdp`
- steampipe: `compute_firewall_rule_rdp_access_restricted`
- cis_gcp: 3.7
- nist_800_53: SC-7
- pci_dss: 1.2.1
- Fix templates: gcp_firewall_open_port.tf

## GCP_FIREWALL_OPEN_SSH

**VPC firewall allows SSH from the internet** — provider `gcp`, default severity `HIGH`, resource `gcp_compute_firewall`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `compute_firewall_ssh_access_from_the_internet_allowed`
- checkov: `CKV_GCP_2`
- trivy: `AVD-GCP-0027`, `AVD-GCP-0071`
- scoutsuite: `computeengine-firewall-rule-opens-all-ports-to-all`, `computeengine-firewall-rule-allows-internal-traffic-ssh`
- steampipe: `compute_firewall_rule_ssh_access_restricted`
- cis_gcp: 3.6
- nist_800_53: SC-7
- pci_dss: 1.2.1
- Fix templates: gcp_firewall_open_port.tf

## GCP_GKE_LEGACY_ABAC

**GKE cluster with legacy ABAC authorization** — provider `gcp`, default severity `HIGH`, resource `gcp_container_cluster`

- Weaknesses: OVERPRIVILEGED_IDENTITY, K8S_API
- prowler: `gke_cluster_legacy_abac_disabled`, `gke_cluster_no_legacy_abac`
- checkov: `CKV_GCP_7`, `CKV_GCP_64`
- trivy: `AVD-GCP-0062`
- scoutsuite: `kubernetesengine-cluster-legacy-abac-enabled`, `kubernetesengine-cluster-legacy-metadata-endpoints-enabled`
- steampipe: `kubernetes_cluster_legacy_abac_disabled`
- cis_gcp: 7.3
- nist_800_53: AC-3

## GCP_IAM_PRIMITIVE_ROLE

**Primitive Owner/Editor role granted to a user or service account** — provider `gcp`, default severity `HIGH`, resource `gcp_iam_binding`

- Weaknesses: OVERPRIVILEGED_IDENTITY
- prowler: `iam_sa_user_managed_key_rotation`, `iam_no_service_roles_at_project_level`, `iam_role_assigned_to_user_or_sa_primitive`
- checkov: `CKV_GCP_42`, `CKV_GCP_117`
- trivy: `AVD-GCP-0007`
- scoutsuite: `iam-primitive-role-in-use`, `iam-sa-has-admin-privileges`
- steampipe: `iam_user_uses_corporate_login_credentials`, `iam_service_account_without_admin_privilege`, `iam_user_not_assigned_service_account_user_role_project_level`
- cis_gcp: 1.5, 1.6
- nist_800_53: AC-6
- pci_dss: 7.1.2

## GCP_INSTANCE_PUBLIC_IP

**Compute instance has an external (public) IP address** — provider `gcp`, default severity `MEDIUM`, resource `gcp_compute_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `compute_instance_public_ip`
- checkov: `CKV_GCP_40`
- trivy: `AVD-GCP-0031`
- cis_gcp: 4.9
- nist_800_53: SC-7
- pci_dss: 1.3.2
- Fix templates: gcp_instance_no_public_ip.tf

## GCP_PROJECT_SSH_KEYS_ALLOWED

**Compute instance accepts project-wide SSH keys** — provider `gcp`, default severity `MEDIUM`, resource `gcp_compute_instance`

- checkov: `CKV_GCP_32`
- trivy: `AVD-GCP-0030`
- cis_gcp: 4.3
- nist_800_53: AC-3, IA-5

## GCP_SA_IMPERSONATION_ROLE

**Service Account User / Token Creator (impersonation) role granted at project level** — provider `gcp`, default severity `HIGH`, resource `gcp_iam_binding`

- Weaknesses: OVERPRIVILEGED_IDENTITY
- checkov: `CKV_GCP_41`, `CKV_GCP_49`
- cis_gcp: 1.6
- nist_800_53: AC-6
- pci_dss: 7.1.2

## GCP_SHIELDED_VM_DISABLED

**Compute instance does not use Shielded VM (secure boot, vTPM, integrity monitoring)** — provider `gcp`, default severity `LOW`, resource `gcp_compute_instance`

- checkov: `CKV_GCP_39`
- trivy: `AVD-GCP-0041`, `AVD-GCP-0045`, `AVD-GCP-0067`
- cis_gcp: 4.8
- nist_800_53: SI-7

## GCP_SQL_NO_SSL

**Cloud SQL does not require SSL connections** — provider `gcp`, default severity `MEDIUM`, resource `gcp_sql_database_instance`

- Weaknesses: UNENCRYPTED_IN_TRANSIT, DATABASE
- prowler: `cloudsql_instance_ssl_connections`
- checkov: `CKV_GCP_6`
- trivy: `AVD-GCP-0015`
- scoutsuite: `cloudsql-instance-ssl-not-required`
- steampipe: `sql_instance_require_ssl_enabled`
- cis_gcp: 6.4
- nist_800_53: SC-8
- pci_dss: 4.1

## GCP_SQL_PUBLIC

**Cloud SQL instance has a public IP or open authorized networks** — provider `gcp`, default severity `CRITICAL`, resource `gcp_sql_database_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE, DATABASE
- prowler: `cloudsql_instance_public_ip`, `cloudsql_instance_public_access`
- checkov: `CKV_GCP_11`, `CKV_GCP_60`
- trivy: `AVD-GCP-0017`
- scoutsuite: `cloudsql-instances-public-ip`, `cloudsql-allows-root-login-from-any-host`
- steampipe: `sql_instance_not_publicly_accessible`, `sql_instance_authorized_networks_restricted`
- cis_gcp: 6.5, 6.6
- nist_800_53: SC-7
- pci_dss: 1.3.6
- hipaa: 164.312(e)(1)
- Fix templates: gcp_sql_public.tf

## GCP_VM_SERIAL_PORT

**Compute instance serial port access enabled** — provider `gcp`, default severity `MEDIUM`, resource `gcp_compute_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `compute_instance_serial_ports_in_use`
- checkov: `CKV_GCP_35`
- trivy: `AVD-GCP-0032`
- scoutsuite: `computeengine-instance-serial-port-enabled`
- steampipe: `compute_instance_serial_port_connection_disabled`
- cis_gcp: 4.5
- nist_800_53: AC-17

## GH_BRANCH_UNPROTECTED

**Default branch has no protection rules** — provider `github`, default severity `HIGH`, resource `github_repository`

- Weaknesses: BRANCH_UNPROTECTED
- prowler: `repository_default_branch_protection_enabled`, `repository_default_branch_requires_multiple_approvals`, `repository_default_branch_disallows_force_push`, `repository_default_branch_requires_status_checks`
- checkov: `CKV_GITHUB_4`, `CKV_GITHUB_5`, `CKV_GITHUB_6`, `CKV_GITHUB_7`, `CKV_GITHUB_8`
- steampipe: `repository_default_branch_protection_enabled`, `repository_branch_protection_require_pull_request_reviews`
- cis_github: 1.1.3, 1.1.9, 1.1.14
- nist_800_53: CM-3, CM-5, SA-11
- pci_dss: 6.3.2

## GH_ORG_NO_2FA

**Organization does not enforce two-factor authentication** — provider `github`, default severity `CRITICAL`, resource `github_organization`

- Weaknesses: NO_MFA, WEAK_AUTH
- prowler: `organization_members_mfa_required`
- checkov: `CKV_GITHUB_1`
- steampipe: `organization_two_factor_required`
- cis_github: 1.3.5
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1

## GH_REPO_PUBLIC

**Repository is public** — provider `github`, default severity `INFO`, resource `github_repository`

- Weaknesses: PUBLIC_DATA_STORE
- prowler: `repository_private`
- checkov: `CKV_GITHUB_13`
- steampipe: `repository_private`
- nist_800_53: AC-3

## GH_SECRET_SCANNING_DISABLED

**Secret scanning or push protection disabled** — provider `github`, default severity `MEDIUM`, resource `github_repository`

- Weaknesses: SECRET_EXPOSURE
- prowler: `repository_secret_scanning_enabled`, `repository_dependabot_enabled`
- checkov: `CKV_GITHUB_19`, `CKV_GITHUB_20`
- steampipe: `repository_secret_scanning_enabled`, `repository_vulnerability_alerts_enabled`
- cis_github: 1.1.4, 1.5.2
- nist_800_53: SA-11, RA-5

## IAC_PARSE_LIMIT

**IaC file not scanned: file exceeded parse limits** — provider `iac`, default severity `INFO`, resource `file`

- nimbus-iac: `IAC_PARSE_LIMIT`

## IAM_ADMIN_POLICY

**IAM policy grants full administrative privileges (*:*)** — provider `aws`, default severity `HIGH`, resource `aws_iam_policy`

- Weaknesses: OVERPRIVILEGED_IDENTITY
- prowler: `iam_aws_attached_policy_no_administrative_privileges`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_inline_policy_no_administrative_privileges`, `iam_policy_allows_privilege_escalation`
- checkov: `CKV_AWS_1`, `CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_107`, `CKV_AWS_108`, `CKV_AWS_109`, `CKV_AWS_110`, `CKV_AWS_111`, `CKV_AWS_274`
- trivy: `AVD-AWS-0057`
- scoutsuite: `iam-managed-policy-allows-full-privileges`, `iam-inline-policy-allows-full-privileges`, `iam-managed-policy-allows-NotActions`, `iam-inline-policy-allows-NotActions`
- steampipe: `iam_policy_no_star_star`, `iam_policy_custom_no_blocked_kms_actions`, `iam_all_policy_no_service_wild_card`
- cis_aws: 1.16
- nist_800_53: AC-6, AC-6(1)
- pci_dss: 7.1.2, 7.2
- hipaa: 164.308(a)(4)
- gdpr: Art.25
- Fix templates: iam_admin_policy.tf

## IAM_CROSS_ACCOUNT_TRUST

**IAM role trusts external or wildcard principals** — provider `aws`, default severity `HIGH`, resource `aws_iam_role`

- Weaknesses: CROSS_ACCOUNT_TRUST
- prowler: `iam_role_cross_account_readonlyaccess_policy`, `iam_role_cross_service_confused_deputy_prevention`
- checkov: `CKV_AWS_60`, `CKV_AWS_61`
- scoutsuite: `iam-assume-role-policy-allows-all`, `iam-assume-role-no-mfa`
- steampipe: `iam_role_cross_account_read_only_access_policy`, `iam_role_no_assume_role_from_any_principal`
- nist_800_53: AC-3, AC-6
- pci_dss: 7.1
- Fix templates: iam_cross_account_trust.tf

## IAM_NO_SUPPORT_ROLE

**No IAM role for AWS Support incident management** — provider `aws`, default severity `LOW`, resource `aws_iam_role`

- prowler: `iam_support_role_created`
- steampipe: `iam_support_role`
- cis_aws: 1.17
- nist_800_53: IR-7

## IAM_OIDC_TRUST_NO_SUBJECT

**Role trusts GitHub Actions OIDC tokens without a subject (repository / branch) condition** — provider `aws`, default severity `CRITICAL`, resource `aws_iam_role`

- Weaknesses: CROSS_ACCOUNT_TRUST
- nimbus-lab: `iam_role_github_oidc_trust_without_subject_condition`
- nist_800_53: AC-3, IA-8
- iso_27001: A.9.4.1
- Fix templates: iam_github_oidc_subject.tf

## IAM_POLICY_ON_USER

**IAM policy attached directly to a user instead of a group or role** — provider `aws`, default severity `LOW`, resource `aws_iam_user`

- checkov: `CKV_AWS_40`
- trivy: `AVD-AWS-0143`
- cis_aws: 1.15
- nist_800_53: AC-2, AC-6

## IAM_ROOT_NO_MFA

**Root account has no MFA** — provider `aws`, default severity `CRITICAL`, resource `aws_iam_root`

- Weaknesses: NO_MFA, OVERPRIVILEGED_IDENTITY
- prowler: `iam_root_mfa_enabled`, `iam_root_hardware_mfa_enabled`, `iam_no_root_access_key`, `iam_avoid_root_usage`
- scoutsuite: `iam-root-account-no-mfa`, `iam-root-account-no-hardware-mfa`
- steampipe: `iam_root_user_mfa_enabled`, `iam_root_user_hardware_mfa_enabled`
- cis_aws: 1.5, 1.6
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)
- gdpr: Art.32

## IAM_STALE_KEYS

**IAM access key unused or older than 90 days** — provider `aws`, default severity `MEDIUM`, resource `aws_iam_access_key`

- Weaknesses: STALE_CREDENTIALS
- prowler: `iam_user_accesskey_unused`, `iam_rotate_access_key_90_days`, `iam_user_console_access_unused`, `iam_user_no_setup_initial_access_key`
- scoutsuite: `iam-user-unused-access-key`, `iam-user-no-key-rotation`
- steampipe: `iam_user_access_key_age_90`, `iam_user_unused_credentials_90`
- cis_aws: 1.12, 1.14
- nist_800_53: IA-5, AC-2(3)
- pci_dss: 8.1.4

## IAM_USER_NOT_FEDERATED

**Access managed through IAM users instead of SSO / identity federation** — provider `aws`, default severity `LOW`, resource `aws_iam_user`

- checkov: `CKV_AWS_273`
- cis_aws: 1.21
- nist_800_53: AC-2, IA-2

## IAM_USER_NO_MFA

**IAM user with console access has no MFA** — provider `aws`, default severity `HIGH`, resource `aws_iam_user`

- Weaknesses: NO_MFA
- prowler: `iam_user_mfa_enabled_console_access`, `iam_user_hardware_mfa_enabled`
- scoutsuite: `iam-user-no-mfa`, `iam-user-without-mfa`
- steampipe: `iam_user_mfa_enabled`, `iam_user_console_access_mfa_enabled`
- cis_aws: 1.10
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)

## IAM_WEAK_PASSWORD_POLICY

**IAM password policy is weak (length < 14 or reuse allowed)** — provider `aws`, default severity `MEDIUM`, resource `aws_iam_account_password_policy`

- Weaknesses: WEAK_AUTH
- prowler: `iam_password_policy_minimum_length_14`, `iam_password_policy_reuse_24`, `iam_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_number`, `iam_password_policy_symbol`, `iam_password_policy_expires_passwords_within_90_days_or_less`
- steampipe: `iam_account_password_policy_min_length_14`, `iam_account_password_policy_reuse_24`, `iam_account_password_policy_strong_min_reuse_24`
- cis_aws: 1.8, 1.9
- nist_800_53: IA-5(1)
- pci_dss: 8.3.6, 8.3.7
- hipaa: 164.308(a)(5)(ii)(D)

## K8S_CAPABILITIES_NOT_DROPPED

**Container does not drop Linux capabilities (keeps NET_RAW or others)** — provider `kubernetes`, default severity `MEDIUM`, resource `k8s_pod`

- checkov: `CKV_K8S_28`, `CKV_K8S_37`
- trivy: `AVD-KSV-0003`, `AVD-KSV-0004`, `AVD-KSV-0106`
- nist_800_53: AC-6, CM-7

## K8S_CLUSTER_ADMIN_BINDING

**Subject bound to cluster-admin or wildcard role** — provider `kubernetes`, default severity `CRITICAL`, resource `k8s_cluster_role_binding`

- Weaknesses: CLUSTER_ADMIN, OVERPRIVILEGED_IDENTITY
- checkov: `CKV_K8S_1`, `CKV_K8S_156`, `CKV2_K8S_5`
- trivy: `KSV044`, `KSV045`, `KSV046`, `AVD-KSV-0044`, `AVD-KSV-0111`
- kubescape: `C-0035`, `C-0185`
- kube-bench: `cis-1.8:5.1.1`, `cis-1.8:5.1.3`
- steampipe: `cluster_role_binding_cluster_admin_disabled`, `role_with_wildcards_used`, `cluster_role_with_wildcards_used`
- cis_k8s: 5.1.1, 5.1.3
- nist_800_53: AC-6, AC-6(1)
- Fix templates: k8s_cluster_admin.k8s.yaml

## K8S_DEFAULT_SA_TOKEN

**Service account token auto-mounted into pod** — provider `kubernetes`, default severity `MEDIUM`, resource `k8s_pod`

- Weaknesses: SERVICE_ACCOUNT_TOKEN
- checkov: `CKV_K8S_38`
- trivy: `KSV036`, `AVD-KSV-0036`
- kubescape: `C-0034`
- kube-bench: `cis-1.8:5.1.6`
- steampipe: `pod_service_account_token_disabled`, `service_account_token_disabled`
- cis_k8s: 5.1.5, 5.1.6
- nist_800_53: AC-6, IA-5
- Fix templates: k8s_sa_token.k8s.yaml

## K8S_HOST_NETWORK

**Pod shares host network / PID / IPC namespace** — provider `kubernetes`, default severity `HIGH`, resource `k8s_pod`

- Weaknesses: HOST_ACCESS
- checkov: `CKV_K8S_17`, `CKV_K8S_18`, `CKV_K8S_19`
- trivy: `KSV008`, `KSV009`, `KSV010`, `AVD-KSV-0008`, `AVD-KSV-0009`, `AVD-KSV-0010`
- kubescape: `C-0038`, `C-0041`
- kube-bench: `cis-1.8:5.2.3`, `cis-1.8:5.2.4`, `cis-1.8:5.2.5`
- steampipe: `pod_host_network_access_disabled`, `pod_host_pid_access_disabled`, `pod_host_ipc_access_disabled`
- cis_k8s: 5.2.3, 5.2.4, 5.2.5
- nist_800_53: SC-7, AC-6
- Fix templates: k8s_host_namespaces.k8s.yaml

## K8S_HOST_PATH

**Pod mounts a hostPath volume** — provider `kubernetes`, default severity `HIGH`, resource `k8s_pod`

- Weaknesses: HOST_ACCESS
- checkov: `CKV_K8S_27`
- trivy: `KSV023`, `AVD-KSV-0023`
- kubescape: `C-0048`
- kube-bench: `cis-1.8:5.2.12`
- steampipe: `pod_volume_host_path`
- cis_k8s: 5.2.1
- nist_800_53: AC-6

## K8S_IMAGE_NOT_PINNED_BY_DIGEST

**Container image is referenced by tag, not pinned by digest** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- checkov: `CKV_K8S_43`
- nist_800_53: CM-2, SI-7

## K8S_IMAGE_PULL_POLICY_NOT_ALWAYS

**Container imagePullPolicy is not Always** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- checkov: `CKV_K8S_15`
- nist_800_53: CM-2

## K8S_NO_NETWORK_POLICY

**Namespace has no NetworkPolicy** — provider `kubernetes`, default severity `MEDIUM`, resource `k8s_namespace`

- Weaknesses: NO_NETWORK_POLICY
- checkov: `CKV2_K8S_6`
- trivy: `KSV038`, `AVD-KSV-0038`
- kubescape: `C-0260`
- kube-bench: `cis-1.8:5.3.2`
- steampipe: `namespace_network_policy_defined`, `network_policy_default_deny_ingress`, `network_policy_default_deny_egress`
- cis_k8s: 5.3.2
- nist_800_53: SC-7
- Fix templates: k8s_network_policy.k8s.yaml

## K8S_NO_RESOURCE_LIMITS

**Container has no CPU/memory limits** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- Weaknesses: NO_RESOURCE_LIMITS
- checkov: `CKV_K8S_10`, `CKV_K8S_11`, `CKV_K8S_12`, `CKV_K8S_13`
- trivy: `KSV011`, `KSV015`, `KSV016`, `KSV018`
- kubescape: `C-0009`, `C-0270`, `C-0271`
- steampipe: `pod_container_cpu_limit`, `pod_container_memory_limit`
- nist_800_53: SC-5, SC-6
- Fix templates: k8s_resource_limits.k8s.yaml

## K8S_NO_SECCOMP

**Container runs without a RuntimeDefault seccomp profile** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- checkov: `CKV_K8S_31`
- trivy: `AVD-KSV-0030`, `AVD-KSV-0104`
- nist_800_53: CM-7, SC-39

## K8S_NO_SECURITY_CONTEXT

**Pod or container has no security context** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- checkov: `CKV_K8S_29`, `CKV_K8S_30`
- trivy: `AVD-KSV-0118`
- nist_800_53: CM-6, CM-7

## K8S_PRIVILEGED_CONTAINER

**Container runs privileged** — provider `kubernetes`, default severity `CRITICAL`, resource `k8s_pod`

- Weaknesses: PRIVILEGED_CONTAINER
- checkov: `CKV_K8S_16`
- trivy: `KSV017`, `AVD-KSV-0017`
- kubescape: `C-0057`
- kube-bench: `cis-1.8:5.2.2`
- prowler: `core_minimize_privileged_containers`, `core_pod_privileged`
- steampipe: `pod_container_privilege_disabled`, `pod_security_policy_container_privilege_disabled`
- cis_k8s: 5.2.1, 5.2.2
- nist_800_53: AC-6, CM-7
- pci_dss: 2.2
- Fix templates: k8s_privileged.k8s.yaml

## K8S_PRIVILEGE_ESCALATION

**Container allows privilege escalation** — provider `kubernetes`, default severity `HIGH`, resource `k8s_pod`

- Weaknesses: PRIVILEGED_CONTAINER
- checkov: `CKV_K8S_20`
- trivy: `KSV001`, `AVD-KSV-0001`
- kubescape: `C-0016`
- kube-bench: `cis-1.8:5.2.6`
- steampipe: `pod_container_privilege_escalation_disabled`
- cis_k8s: 5.2.5
- nist_800_53: AC-6
- Fix templates: k8s_privilege_escalation.k8s.yaml

## K8S_RBAC_WILDCARD

**Role or ClusterRole grants wildcard verbs or resources** — provider `kubernetes`, default severity `HIGH`, resource `k8s_cluster_role`

- Weaknesses: OVERPRIVILEGED_IDENTITY
- prowler: `rbac_minimize_wildcard_use_roles`
- cis_k8s: 5.1.3
- nist_800_53: AC-6

## K8S_RUN_AS_ROOT

**Container may run as root** — provider `kubernetes`, default severity `MEDIUM`, resource `k8s_pod`

- Weaknesses: RUNS_AS_ROOT
- checkov: `CKV_K8S_23`, `CKV_K8S_6`, `CKV_K8S_40`
- trivy: `KSV012`, `KSV020`, `KSV021`, `AVD-KSV-0012`
- kubescape: `C-0013`
- kube-bench: `cis-1.8:5.2.7`
- steampipe: `pod_non_root_container`, `pod_container_non_root_user`
- cis_k8s: 5.2.6
- nist_800_53: AC-6
- Fix templates: k8s_run_as_root.k8s.yaml

## K8S_SECRETS_IN_ENV

**Secrets passed as environment variables** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- Weaknesses: SECRET_EXPOSURE
- checkov: `CKV_K8S_35`
- kube-bench: `cis-1.8:5.4.1`
- steampipe: `pod_container_secrets_not_in_env`
- cis_k8s: 5.4.1
- nist_800_53: IA-5

## K8S_SECRETS_RBAC_WIDE

**Subject can get / list secrets in every namespace** — provider `kubernetes`, default severity `HIGH`, resource `k8s_clusterrolebinding`

- Weaknesses: OVERPRIVILEGED_IDENTITY
- nimbus-lab: `rbac_minimize_secret_access`
- cis_k8s: 5.1.2
- nist_800_53: AC-6
- Fix templates: k8s_rbac_secrets.k8s.yaml

## K8S_SERVICE_PUBLIC_LB

**Workload exposed to the internet by a LoadBalancer service** — provider `kubernetes`, default severity `HIGH`, resource `k8s_service`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- nimbus-lab: `service_type_loadbalancer_public`
- nist_800_53: SC-7
- cis_k8s: 5.7.4
- Fix templates: k8s_service_internal_lb.k8s.yaml

## K8S_WRITABLE_ROOT_FS

**Container root filesystem is writable** — provider `kubernetes`, default severity `LOW`, resource `k8s_pod`

- checkov: `CKV_K8S_22`
- trivy: `AVD-KSV-0014`
- kubescape: `C-0017`
- nist_800_53: CM-7, SI-7

## KMS_ROTATION_DISABLED

**KMS customer key rotation disabled** — provider `aws`, default severity `LOW`, resource `aws_kms_key`

- Weaknesses: WEAK_CRYPTO
- prowler: `kms_cmk_rotation_enabled`, `cloudtrail_kms_encryption_enabled`
- checkov: `CKV_AWS_7`
- trivy: `AVD-AWS-0065`
- scoutsuite: `kms-cmk-rotation-disabled`
- steampipe: `kms_cmk_rotation_enabled`
- cis_aws: 3.6
- nist_800_53: SC-12
- pci_dss: 3.6.4
- Fix templates: kms_rotation.tf

## LAMBDA_NOT_IN_VPC

**Lambda function is not attached to a VPC** — provider `aws`, default severity `LOW`, resource `aws_lambda_function`

- checkov: `CKV_AWS_117`
- nist_800_53: SC-7

## LAMBDA_NO_CODE_SIGNING

**Lambda function does not validate code signing** — provider `aws`, default severity `LOW`, resource `aws_lambda_function`

- checkov: `CKV_AWS_272`
- nist_800_53: CM-14, SI-7

## LAMBDA_NO_TRACING

**Lambda function has X-Ray tracing disabled** — provider `aws`, default severity `LOW`, resource `aws_lambda_function`

- checkov: `CKV_AWS_50`
- trivy: `AVD-AWS-0066`
- nist_800_53: AU-12, SI-4

## LAMBDA_PUBLIC

**Lambda function URL or policy is publicly invocable** — provider `aws`, default severity `HIGH`, resource `aws_lambda_function`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- prowler: `awslambda_function_url_public`, `awslambda_function_not_publicly_accessible`
- checkov: `CKV_AWS_364`, `CKV_AWS_258`
- trivy: `AVD-AWS-0067`
- steampipe: `lambda_function_restrict_public_access`, `lambda_function_restrict_public_url`
- nist_800_53: AC-3, SC-7
- pci_dss: 1.3.1

## M365_LEGACY_AUTH

**Legacy authentication protocols allowed** — provider `m365`, default severity `HIGH`, resource `m365_tenant`

- Weaknesses: WEAK_AUTH
- prowler: `entra_legacy_authentication_blocked`, `entra_conditional_access_policy_block_legacy_authentication`, `exchange_modern_authentication_enabled`
- steampipe: `m365_legacy_auth_blocked`
- nist_800_53: IA-2, IA-5
- pci_dss: 8.3

## M365_NO_MFA_ADMIN

**Admin accounts without MFA (conditional access)** — provider `m365`, default severity `CRITICAL`, resource `m365_user`

- Weaknesses: NO_MFA, WEAK_AUTH, OVERPRIVILEGED_IDENTITY
- prowler: `entra_admin_users_mfa_enabled`, `entra_conditional_access_policy_require_mfa_for_management_api`, `entra_conditional_access_policy_require_mfa_for_administrative_roles`, `admincenter_users_admins_reduced_count`
- steampipe: `m365_admin_mfa_enabled`
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)
- gdpr: Art.32

## M365_SHAREPOINT_ANONYMOUS_LINKS

**SharePoint allows anonymous sharing links** — provider `m365`, default severity `HIGH`, resource `m365_sharepoint_tenant`

- Weaknesses: PUBLIC_DATA_STORE
- prowler: `sharepoint_external_sharing_restricted`, `sharepoint_guest_sharing_restricted`, `sharepoint_onedrive_sync_restricted_unmanaged_devices`
- steampipe: `m365_sharepoint_anonymous_links_disabled`
- nist_800_53: AC-3, AC-21
- gdpr: Art.32

## OCI_BLOCKVOL_UNENCRYPTED

**Block volume not encrypted with customer-managed key** — provider `oci`, default severity `MEDIUM`, resource `oci_core_volume`

- Weaknesses: UNENCRYPTED_AT_REST
- checkov: `CKV_OCI_3`, `CKV_OCI_2`
- steampipe: `core_volume_encryption_customer_managed_key`
- nist_800_53: SC-28
- pci_dss: 3.4

## OCI_BUCKET_PUBLIC

**Object Storage bucket is public** — provider `oci`, default severity `HIGH`, resource `oci_objectstorage_bucket`

- Weaknesses: PUBLIC_DATA_STORE
- checkov: `CKV_OCI_10`
- steampipe: `objectstorage_bucket_public_access_blocked`
- nist_800_53: AC-3
- pci_dss: 1.3.1
- gdpr: Art.32

## OCI_SECLIST_OPEN_SSH

**Security list allows SSH from the internet** — provider `oci`, default severity `HIGH`, resource `oci_core_security_list`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE
- checkov: `CKV_OCI_19`, `CKV_OCI_20`, `CKV_OCI_22`
- steampipe: `core_security_list_ingress_ssh_blocked`, `core_security_list_ingress_rdp_blocked`
- nist_800_53: SC-7
- pci_dss: 1.2.1

## OKTA_ADMIN_NO_MFA

**Okta administrator without MFA enrolled** — provider `okta`, default severity `CRITICAL`, resource `okta_user`

- Weaknesses: NO_MFA, OVERPRIVILEGED_IDENTITY
- steampipe: `okta_admin_user_mfa_enrolled`, `okta_super_admin_mfa_enrolled`
- nist_800_53: IA-2(1), AC-6
- pci_dss: 8.3.1

## OKTA_NO_MFA_POLICY

**Sign-on policy does not require MFA** — provider `okta`, default severity `CRITICAL`, resource `okta_policy`

- Weaknesses: NO_MFA, WEAK_AUTH
- steampipe: `okta_policy_mfa_enabled`, `okta_sign_on_policy_require_mfa`, `okta_factor_enrollment_required`
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)

## OKTA_SESSION_LIFETIME

**Session lifetime or idle timeout exceeds recommendation** — provider `okta`, default severity `MEDIUM`, resource `okta_policy`

- Weaknesses: WEAK_AUTH
- steampipe: `okta_sign_on_policy_session_lifetime`, `okta_sign_on_policy_idle_timeout`
- nist_800_53: AC-11, AC-12
- pci_dss: 8.1.8

## OKTA_SIGNON_MFA_EXEMPT

**Okta user signs in under a sign-on rule that does not require MFA** — provider `okta`, default severity `HIGH`, resource `okta_user`

- Weaknesses: NO_MFA
- nimbus-lab: `okta_signon_rule_mfa_exempt`
- nist_800_53: IA-2(1)
- pci_dss: 8.3.1
- hipaa: 164.312(d)
- Fix templates: okta_signon_mfa.tf

## RDS_BACKUP_RETENTION_LOW

**RDS backup retention is at the 1-day default or disabled** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: NO_BACKUP, DATABASE
- trivy: `AVD-AWS-0077`
- nist_800_53: CP-9

## RDS_LOGGING_DISABLED

**RDS instance does not export database logs** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: NO_LOGGING, DATABASE
- checkov: `CKV_AWS_129`, `CKV2_AWS_30`
- nist_800_53: AU-2, AU-12
- pci_dss: 10.2

## RDS_NO_DELETION_PROTECTION

**RDS instance has deletion protection disabled** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: NO_BACKUP, DATABASE
- checkov: `CKV_AWS_293`
- trivy: `AVD-AWS-0177`
- nist_800_53: CP-9, CM-3

## RDS_NO_IAM_AUTH

**RDS instance does not use IAM database authentication** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: WEAK_AUTH, DATABASE
- checkov: `CKV_AWS_161`
- trivy: `AVD-AWS-0176`
- nist_800_53: IA-2, AC-2

## RDS_NO_MINOR_UPGRADE

**RDS instance does not auto-apply minor version upgrades** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: UNPATCHED, DATABASE
- prowler: `rds_instance_minor_version_upgrade_enabled`
- checkov: `CKV_AWS_226`
- steampipe: `rds_db_instance_automatic_minor_version_upgrade_enabled`
- cis_aws: 2.3.2
- nist_800_53: SI-2
- pci_dss: 6.3.3

## RDS_NO_MULTI_AZ

**RDS instance is not Multi-AZ** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- Weaknesses: NO_BACKUP, DATABASE
- prowler: `rds_instance_multi_az`
- checkov: `CKV_AWS_157`
- steampipe: `rds_db_instance_multiple_az_enabled`
- nist_800_53: CP-10, SC-36
- hipaa: 164.308(a)(7)(ii)(B)

## RDS_NO_PERFORMANCE_INSIGHTS

**RDS instance does not have Performance Insights enabled** — provider `aws`, default severity `LOW`, resource `aws_db_instance`

- checkov: `CKV_AWS_353`
- trivy: `AVD-AWS-0133`
- nist_800_53: SI-4

## RDS_PUBLIC

**RDS instance is publicly accessible** — provider `aws`, default severity `CRITICAL`, resource `aws_db_instance`

- Weaknesses: PUBLIC_NETWORK_EXPOSURE, DATABASE
- prowler: `rds_instance_no_public_access`, `rds_snapshots_public_access`
- checkov: `CKV_AWS_17`
- trivy: `AVD-AWS-0082`, `AVD-AWS-0180`
- scoutsuite: `rds-instance-publicly-accessible`, `rds-snapshot-public`
- steampipe: `rds_db_instance_prohibit_public_access`, `rds_db_snapshot_prohibit_public_access`
- cis_aws: 2.3.3
- nist_800_53: SC-7, AC-4
- pci_dss: 1.3.6
- hipaa: 164.312(e)(1)
- gdpr: Art.32
- Fix templates: rds_public.tf, rds_public.cfn.yaml

## RDS_UNENCRYPTED

**RDS storage not encrypted** — provider `aws`, default severity `HIGH`, resource `aws_db_instance`

- Weaknesses: UNENCRYPTED_AT_REST, DATABASE
- prowler: `rds_instance_storage_encrypted`
- checkov: `CKV_AWS_16`
- trivy: `AVD-AWS-0080`
- scoutsuite: `rds-instance-storage-not-encrypted`
- steampipe: `rds_db_instance_encryption_at_rest_enabled`
- cis_aws: 2.3.1
- nist_800_53: SC-28
- pci_dss: 3.4
- hipaa: 164.312(a)(2)(iv)
- Fix templates: rds_unencrypted.tf

## S3_NO_CMK

**S3 bucket default encryption does not use a KMS customer-managed key** — provider `aws`, default severity `LOW`, resource `aws_s3_bucket`

- checkov: `CKV_AWS_145`
- trivy: `AVD-AWS-0132`
- nist_800_53: SC-12, SC-28

## S3_NO_LOGGING

**S3 bucket server access logging disabled** — provider `aws`, default severity `LOW`, resource `aws_s3_bucket`

- Weaknesses: NO_LOGGING
- prowler: `s3_bucket_server_access_logging_enabled`
- checkov: `CKV_AWS_18`
- trivy: `AVD-AWS-0089`
- scoutsuite: `s3-bucket-no-logging`
- steampipe: `s3_bucket_logging_enabled`
- cis_aws: 3.4
- nist_800_53: AU-2, AU-12
- pci_dss: 10.2
- hipaa: 164.312(b)
- Fix templates: s3_no_logging.tf

## S3_NO_TLS_POLICY

**S3 bucket policy does not deny insecure (HTTP) transport** — provider `aws`, default severity `MEDIUM`, resource `aws_s3_bucket`

- Weaknesses: UNENCRYPTED_IN_TRANSIT
- prowler: `s3_bucket_secure_transport_policy`
- checkov: `CKV_AWS_19_ssl`
- steampipe: `s3_bucket_enforces_ssl`
- cis_aws: 2.1.1
- nist_800_53: SC-8
- pci_dss: 4.2.1

## S3_NO_VERSIONING

**S3 bucket versioning disabled** — provider `aws`, default severity `LOW`, resource `aws_s3_bucket`

- Weaknesses: NO_BACKUP
- prowler: `s3_bucket_object_versioning`
- checkov: `CKV_AWS_21`
- trivy: `AVD-AWS-0090`
- scoutsuite: `s3-bucket-no-versioning`
- steampipe: `s3_bucket_versioning_enabled`
- nist_800_53: CP-9, CP-10
- hipaa: 164.308(a)(7)(ii)(A)
- Fix templates: s3_no_versioning.tf

## S3_PUBLIC_BUCKET

**S3 bucket allows public access** — provider `aws`, default severity `HIGH`, resource `aws_s3_bucket`

- Weaknesses: PUBLIC_DATA_STORE
- prowler: `s3_bucket_public_access`, `s3_bucket_policy_public_write_access`, `s3_bucket_public_write_acl`, `s3_bucket_public_list_acl`, `s3_account_level_public_access_blocks`, `cloudtrail_logs_s3_bucket_is_not_publicly_accessible`
- checkov: `CKV_AWS_53`, `CKV_AWS_54`, `CKV_AWS_55`, `CKV_AWS_56`, `CKV2_AWS_6`, `CKV_AWS_20`, `CKV_AWS_57`, `CKV_AWS_70`
- trivy: `AVD-AWS-0086`, `AVD-AWS-0087`, `AVD-AWS-0091`, `AVD-AWS-0092`, `AVD-AWS-0093`, `AVD-AWS-0094`
- scoutsuite: `s3-bucket-AllUsers-read`, `s3-bucket-AllUsers-write`, `s3-bucket-AllUsers-read_acp`, `s3-bucket-AllUsers-write_acp`, `s3-bucket-AuthenticatedUsers-read`, `s3-bucket-AuthenticatedUsers-write`, `s3-bucket-world-policy-star`, `s3-bucket-world-policy-arn-star`
- steampipe: `s3_bucket_restrict_public_read_access`, `s3_bucket_restrict_public_write_access`, `s3_public_access_block_bucket`, `s3_bucket_policy_restrict_public_access`
- cis_aws: 2.1.4
- nist_800_53: AC-3, AC-6, SC-7
- pci_dss: 1.3.1, 1.3.4
- hipaa: 164.312(a)(1)
- gdpr: Art.32
- iso_27001: A.8.3, A.13.1.3
- Fix templates: s3_public_bucket.tf, s3_public_bucket.cfn.yaml

## S3_UNENCRYPTED

**S3 bucket has no default encryption** — provider `aws`, default severity `MEDIUM`, resource `aws_s3_bucket`

- Weaknesses: UNENCRYPTED_AT_REST
- prowler: `s3_bucket_default_encryption`
- checkov: `CKV_AWS_19`, `CKV2_AWS_67`
- trivy: `AVD-AWS-0088`
- scoutsuite: `s3-bucket-no-default-encryption`
- steampipe: `s3_bucket_default_encryption_enabled`
- cis_aws: 2.1.1
- nist_800_53: SC-28
- pci_dss: 3.4
- hipaa: 164.312(a)(2)(iv)
- gdpr: Art.32
- Fix templates: s3_unencrypted.tf, s3_unencrypted.cfn.yaml

## SECRET_HARDCODED

**Hard-coded secret in code or configuration** — provider `iac`, default severity `CRITICAL`, resource `secret`

- Weaknesses: SECRET_EXPOSURE
- checkov: `CKV_SECRET_1`, `CKV_SECRET_2`, `CKV_SECRET_3`, `CKV_SECRET_4`, `CKV_SECRET_5`, `CKV_SECRET_6`, `CKV_SECRET_13`, `CKV_SECRET_14`, `CKV_SECRET_19`
- trivy: `aws-access-key-id`, `aws-secret-access-key`, `github-pat`, `gcp-service-account`, `private-key`, `generic-secret`
- nist_800_53: IA-5(7), SA-11
- pci_dss: 6.3.1, 8.2.1
- gdpr: Art.32

## THREAT_DETECTION_DISABLED

**GuardDuty / Security Hub not enabled** — provider `aws`, default severity `MEDIUM`, resource `aws_guardduty_detector`

- Weaknesses: NO_LOGGING
- prowler: `guardduty_is_enabled`, `securityhub_enabled`, `guardduty_no_high_severity_findings`
- steampipe: `guardduty_enabled`, `securityhub_enabled`
- cis_aws: 4.16
- nist_800_53: SI-4, RA-5
- pci_dss: 11.5

<!-- END GENERATED CATALOG -->
