package graph

//go:generate go run ./gen -out ../../docs/graph-schema.md

import (
	"sort"
	"strings"
	"sync"
)

// TypeSpec is one canonical node type (P1-GRAPH G1, plan v3 IG4). Class drives entry-point and
// target detection exactly as before; the flags are typed facts later stages consume instead
// of substring guesses (IsAdminCapable, Crown: not yet read by scoring).
type TypeSpec struct {
	Type     string   `json:"type"`     // canonical id: aws_iam_role, k8s_service_account, ...
	Class    string   `json:"class"`    // Class* constant
	Provider string   `json:"provider"` // aws | azure | gcp | oci | kubernetes | github | m365 | okta | any
	Display  string   `json:"display"`
	IDFormat string   `json:"id_format,omitempty"` // the node id collectors emit for this type
	Aliases  []string `json:"aliases,omitempty"`   // other tools' names (Terraform, CloudFormation, ASFF, k8s kind)
	// IsIdentity / IsDataStore mirror Class (identity / datastore) for callers that want a flag.
	IsIdentity  bool `json:"is_identity"`
	IsDataStore bool `json:"is_data_store"`
	// IsAdminCapable: a principal, or a grant, that can carry administrator rights over its scope.
	IsAdminCapable bool `json:"is_admin_capable"`
	// Crown: crown-jewel by default (secrets, keys, managed databases), before tags or config.
	Crown bool `json:"crown"`
	// Review: why the class is the legacy heuristic's and not the right one (reclassify only
	// with a groundtruth + noise re-baseline).
	Review string `json:"review,omitempty"`
}

func (s TypeSpec) review(why string) TypeSpec { s.Review = why; return s }

const (
	admin = 1 << iota
	crown
)

func spec(typ, class, provider, display, idFormat string, flags int, aliases ...string) TypeSpec {
	return TypeSpec{Type: typ, Class: class, Provider: provider, Display: display, IDFormat: idFormat, Aliases: aliases,
		IsIdentity: class == ClassIdentity, IsDataStore: class == ClassDataStore,
		IsAdminCapable: flags&admin != 0, Crown: flags&crown != 0}
}

// registry is the closed table. Every type a collector, GuessType or the lab emits must be
// here (TestRegistryCoversCollectorTypes); every class must equal what the legacy substring
// heuristic gave it unless reviewed (TestRegistryClassMatchesLegacy), so groundtruth holds.
var registry = []TypeSpec{
	spec("internet", ClassInternet, "any", "The Internet", "internet", 0),

	// ---- accounts / top-level scopes (graph.AttachFindings creates <provider>_account)
	spec("aws_account", ClassAccount, "aws", "AWS account", "aws:account:<account-id> | arn:aws:iam::<account-id>:root (external)", 0, "AWS::Organizations::Account", "AwsAccount"),
	spec("azure_subscription", ClassAccount, "azure", "Azure subscription", "azure:account:<subscription-id>", 0, "microsoft.resources/subscriptions"),
	spec("azure_account", ClassAccount, "azure", "Azure account (finding scope)", "azure:account:<subscription-id>", 0),
	spec("gcp_project", ClassAccount, "gcp", "GCP project", "gcp:account:<project-id>", 0, "google_project", "cloudresourcemanager.googleapis.com/Project"),
	spec("gcp_account", ClassAccount, "gcp", "GCP account (finding scope)", "gcp:account:<project-id>", 0),
	spec("oci_account", ClassAccount, "oci", "OCI tenancy (finding scope)", "oci:account:<tenancy>", 0),
	spec("k8s_cluster_account", ClassAccount, "kubernetes", "Kubernetes cluster (scope)", "kubernetes:account:<context>", 0),
	spec("kubernetes_account", ClassAccount, "kubernetes", "Kubernetes cluster (finding scope)", "kubernetes:account:<cluster>", 0),
	spec("github_account", ClassAccount, "github", "GitHub account (scope)", "github:account:<org>", 0),
	spec("m365_tenant", ClassAccount, "m365", "Microsoft 365 tenant", "m365:tenant/<tenant-id>", 0),
	spec("m365_account", ClassAccount, "m365", "Microsoft 365 account (finding scope)", "m365:account:<tenant>", 0),
	spec("okta_tenant", ClassAccount, "okta", "Okta tenant", "okta:account:<domain>", 0),
	spec("okta_account", ClassAccount, "okta", "Okta account (finding scope)", "okta:account:<domain>", 0),

	// ---- AWS identity
	spec("aws_iam_role", ClassIdentity, "aws", "IAM role", "arn:aws:iam::<account>:role/<path/name>", admin, "AWS::IAM::Role", "AwsIamRole"),
	spec("aws_iam_user", ClassIdentity, "aws", "IAM user", "arn:aws:iam::<account>:user/<name>", admin, "AWS::IAM::User", "AwsIamUser"),
	spec("aws_iam_group", ClassIdentity, "aws", "IAM group", "arn:aws:iam::<account>:group/<name>", admin, "AWS::IAM::Group", "AwsIamGroup"),
	spec("aws_iam_policy", ClassIdentity, "aws", "IAM policy", "arn:aws:iam::<account|aws>:policy/<name> | <role-arn>/inline/<name>", admin, "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AwsIamPolicy"),
	spec("aws_iam_root", ClassIdentity, "aws", "Account root user", "arn:aws:iam::<account>:root", admin),
	spec("aws_iam_identity_provider", ClassIdentity, "aws", "IAM identity provider (OIDC/SAML)", "arn:aws:iam::<account>:oidc-provider/<host> | saml-provider/<name>", 0, "aws_iam_openid_connect_provider", "aws_iam_saml_provider"),
	spec("aws_iam_instance_profile", ClassIdentity, "aws", "IAM instance profile", "arn:aws:iam::<account>:instance-profile/<name>", admin, "AWS::IAM::InstanceProfile"),
	spec("aws_iam_access_key", ClassIdentity, "aws", "IAM access key", "<access-key-id>", 0, "AwsIamAccessKey"),

	// ---- AWS compute / cluster
	spec("aws_instance", ClassCompute, "aws", "EC2 instance", "arn:aws:ec2:<region>:<account>:instance/<id>", 0, "AWS::EC2::Instance", "AwsEc2Instance"),
	spec("aws_lambda_function", ClassCompute, "aws", "Lambda function", "arn:aws:lambda:<region>:<account>:function:<name>", 0, "AWS::Lambda::Function", "AwsLambdaFunction"),
	spec("aws_bedrockagent_agent", ClassCompute, "aws", "Bedrock agent (AI agent runtime; runs as its service role)", "arn:aws:bedrock:<region>:<account>:agent/<id>", 0, "aws_bedrock_agent", "AWS::Bedrock::Agent"),
	spec("aws_eks_cluster", ClassCluster, "aws", "EKS cluster", "arn:aws:eks:<region>:<account>:cluster/<name>", 0, "AWS::EKS::Cluster", "AwsEksCluster"),

	// ---- AWS data
	spec("aws_s3_bucket", ClassDataStore, "aws", "S3 bucket", "arn:aws:s3:::<bucket>", 0, "AWS::S3::Bucket", "AwsS3Bucket"),
	spec("aws_db_instance", ClassDataStore, "aws", "RDS DB instance", "arn:aws:rds:<region>:<account>:db:<id>", crown, "AWS::RDS::DBInstance", "AwsRdsDbInstance"),
	spec("aws_rds_cluster", ClassDataStore, "aws", "RDS/Aurora cluster", "arn:aws:rds:<region>:<account>:cluster:<id>", crown, "AWS::RDS::DBCluster", "AwsRdsDbCluster"),
	spec("aws_dynamodb_table", ClassDataStore, "aws", "DynamoDB table", "arn:aws:dynamodb:<region>:<account>:table/<name>", crown, "AWS::DynamoDB::Table", "AwsDynamoDbTable"),
	spec("aws_secretsmanager_secret", ClassDataStore, "aws", "Secrets Manager secret", "arn:aws:secretsmanager:<region>:<account>:secret:<name>", crown, "AWS::SecretsManager::Secret", "AwsSecretsManagerSecret"),
	spec("aws_kms_key", ClassDataStore, "aws", "KMS key", "arn:aws:kms:<region>:<account>:key/<id>", crown, "AWS::KMS::Key", "AwsKmsKey"),
	spec("aws_ebs_volume", ClassDataStore, "aws", "EBS volume", "arn:aws:ec2:<region>:<account>:volume/<id>", 0, "AWS::EC2::Volume", "AwsEc2Volume"),
	spec("aws_ebs_snapshot", ClassDataStore, "aws", "EBS snapshot", "arn:aws:ec2:<region>::snapshot/<id>", 0, "AwsEc2Snapshot"),

	// ---- AWS network
	spec("aws_security_group", ClassNetwork, "aws", "Security group", "arn:aws:ec2:<region>:<account>:security-group/<sg-id>", 0, "AWS::EC2::SecurityGroup", "AwsEc2SecurityGroup"),
	spec("aws_vpc", ClassNetwork, "aws", "VPC", "arn:aws:ec2:<region>:<account>:vpc/<vpc-id>", 0, "AWS::EC2::VPC", "AwsEc2Vpc"),
	spec("aws_subnet", ClassNetwork, "aws", "Subnet", "arn:aws:ec2:<region>:<account>:subnet/<subnet-id>", 0, "AWS::EC2::Subnet", "AwsEc2Subnet"),
	spec("aws_eip", ClassNetwork, "aws", "Elastic IP", "arn:aws:ec2:<region>:<account>:elastic-ip/<alloc-id>", 0, "AWS::EC2::EIP", "AwsEc2Eip"),
	spec("aws_lb", ClassNetwork, "aws", "Load balancer", "arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/<type>/<name>/<id>", 0, "aws_alb", "AwsElbv2LoadBalancer"),
	spec("aws_network_acl", ClassNetwork, "aws", "Network ACL", "arn:aws:ec2:<region>:<account>:network-acl/<acl-id>", 0, "AWS::EC2::NetworkAcl", "AwsEc2NetworkAcl"),

	// ---- legacy heuristic class kept so analysis does not move (see TypeSpec.Review)
	spec("aws_cloudfront_distribution", ClassCompute, "aws", "CloudFront distribution", "arn:aws:cloudfront::<account>:distribution/<id>", 0, "AWS::CloudFront::Distribution", "AwsCloudFrontDistribution").review("edge network service; legacy class compute"),
	spec("aws_ssm_parameter", ClassCompute, "aws", "SSM parameter", "arn:aws:ssm:<region>:<account>:parameter/<name>", 0, "AWS::SSM::Parameter", "AwsSsmParameter").review("parameter store (may hold secrets); legacy class compute"),
	spec("aws_ecs_service", ClassCompute, "aws", "ECS service", "arn:aws:ecs:<region>:<account>:service/<cluster>/<name>", 0, "AWS::ECS::Service", "AwsEcsService"),
	spec("aws_cloudtrail", ClassCompute, "aws", "CloudTrail trail", "arn:aws:cloudtrail:<region>:<account>:trail/<name>", 0, "AWS::CloudTrail::Trail", "AwsCloudTrailTrail").review("audit log trail; legacy class compute"),

	// ---- Azure
	spec("azure_virtual_machine", ClassCompute, "azure", "Virtual machine", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<name>", 0,
		"azurerm_virtual_machine", "azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "microsoft.compute/virtualmachines"),
	spec("azure_kubernetes_cluster", ClassCluster, "azure", "AKS cluster", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerService/managedClusters/<name>", 0,
		"azurerm_kubernetes_cluster", "microsoft.containerservice/managedclusters"),
	spec("azure_network_security_group", ClassNetwork, "azure", "Network security group", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/networkSecurityGroups/<name>", 0,
		"azurerm_network_security_group", "microsoft.network/networksecuritygroups"),
	spec("azure_public_ip", ClassNetwork, "azure", "Public IP address", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/publicIPAddresses/<name>", 0,
		"azurerm_public_ip", "microsoft.network/publicipaddresses"),
	spec("azure_virtual_network", ClassNetwork, "azure", "Virtual network", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<name>", 0,
		"azurerm_virtual_network", "microsoft.network/virtualnetworks"),
	spec("azure_private_endpoint", ClassCompute, "azure", "Private endpoint", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/privateEndpoints/<name>", 0,
		"azurerm_private_endpoint").review("network plumbing; legacy class compute"),
	spec("azure_storage_account", ClassDataStore, "azure", "Storage account", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<name>", 0,
		"azurerm_storage_account", "microsoft.storage/storageaccounts"),
	spec("azure_sql_server", ClassDataStore, "azure", "Azure SQL server", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Sql/servers/<name>", crown,
		"azurerm_sql_server", "azurerm_mssql_server", "microsoft.sql/servers"),
	spec("azure_key_vault", ClassDataStore, "azure", "Key Vault", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>", crown,
		"azurerm_key_vault", "microsoft.keyvault/vaults"),
	spec("azure_managed_disk", ClassDataStore, "azure", "Managed disk", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/disks/<name>", 0,
		"azurerm_managed_disk", "microsoft.compute/disks"),
	spec("azure_user_assigned_identity", ClassIdentity, "azure", "User-assigned managed identity", "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<name>", admin,
		"azurerm_user_assigned_identity", "microsoft.managedidentity/userassignedidentities"),
	spec("azure_managed_identity", ClassIdentity, "azure", "Managed identity (system-assigned)", "<principal-id>", admin),

	// ---- GCP
	spec("gcp_compute_instance", ClassCompute, "gcp", "Compute Engine instance", "//compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>", 0,
		"google_compute_instance", "compute.googleapis.com/Instance"),
	spec("gcp_container_cluster", ClassCluster, "gcp", "GKE cluster", "//container.googleapis.com/projects/<p>/locations/<l>/clusters/<name>", 0,
		"google_container_cluster", "container.googleapis.com/Cluster"),
	spec("gcp_compute_firewall", ClassNetwork, "gcp", "VPC firewall rule", "<firewall selfLink>", 0,
		"google_compute_firewall", "compute.googleapis.com/Firewall"),
	spec("gcp_compute_address", ClassNetwork, "gcp", "External IP address", "//compute.googleapis.com/projects/<p>/regions/<r>/addresses/<name>", 0,
		"google_compute_address", "compute.googleapis.com/Address"),
	spec("gcp_compute_disk", ClassDataStore, "gcp", "Persistent disk", "//compute.googleapis.com/projects/<p>/zones/<z>/disks/<name>", 0,
		"google_compute_disk", "compute.googleapis.com/Disk"),
	spec("gcp_storage_bucket", ClassDataStore, "gcp", "Cloud Storage bucket", "//storage.googleapis.com/projects/_/buckets/<bucket>", 0,
		"google_storage_bucket", "storage.googleapis.com/Bucket"),
	spec("gcp_sql_database_instance", ClassDataStore, "gcp", "Cloud SQL instance", "//sqladmin.googleapis.com/projects/<p>/instances/<name>", crown,
		"google_sql_database_instance", "sqladmin.googleapis.com/Instance"),
	spec("gcp_service_account", ClassIdentity, "gcp", "Service account", "//iam.googleapis.com/projects/<p>/serviceAccounts/<email>", admin,
		"google_service_account", "iam.googleapis.com/ServiceAccount"),
	spec("gcp_iam_role", ClassIdentity, "gcp", "IAM role (project binding)", "//cloudresourcemanager.googleapis.com/projects/<p>/roles/<role> | //iam.googleapis.com/<custom-role>", admin, "iam.googleapis.com/Role"),
	spec("gcp_user", ClassIdentity, "gcp", "Google user", "gcp:user/<email>", admin),
	spec("gcp_group", ClassIdentity, "gcp", "Google group", "gcp:group/<email>", admin),

	// ---- Kubernetes
	spec("k8s_namespace", ClassCluster, "kubernetes", "Namespace", "namespace/<name>", 0, "kubernetes_namespace", "Namespace"),
	spec("k8s_service_account", ClassIdentity, "kubernetes", "Service account", "<ns>/serviceaccount/<name>", admin, "kubernetes_service_account", "ServiceAccount"),
	spec("k8s_cluster_role", ClassIdentity, "kubernetes", "ClusterRole", "cluster/clusterrole/<name>", admin, "kubernetes_cluster_role", "ClusterRole"),
	spec("k8s_cluster_role_binding", ClassIdentity, "kubernetes", "ClusterRoleBinding", "cluster/clusterrolebinding/<name>", admin, "kubernetes_cluster_role_binding", "ClusterRoleBinding"),
	spec("k8s_role", ClassIdentity, "kubernetes", "Role", "<ns>/role/<name>", admin, "kubernetes_role", "Role"),
	spec("k8s_role_binding", ClassIdentity, "kubernetes", "RoleBinding", "<ns>/rolebinding/<name>", admin, "kubernetes_role_binding", "RoleBinding"),
	spec("k8s_pod", ClassCompute, "kubernetes", "Pod", "<ns>/pod/<name>", 0, "kubernetes_pod", "Pod"),
	spec("k8s_deployment", ClassCompute, "kubernetes", "Deployment", "<ns>/deployment/<name>", 0, "kubernetes_deployment", "Deployment"),
	spec("k8s_node", ClassCompute, "kubernetes", "Node", "cluster/node/<name>", 0, "Node"),
	spec("container_image", ClassImage, "any", "Container image", "image/<ref>", 0),

	// ---- SaaS / CI
	spec("github_organization", ClassSaaS, "github", "GitHub organization", "github:org/<org>", 0),
	spec("github_repository", ClassSaaS, "github", "GitHub repository", "github:repo/<org>/<repo>", 0),
	spec("m365_user", ClassIdentity, "m365", "Entra ID / M365 user", "m365:user/<id>", admin),
	spec("okta_user", ClassIdentity, "okta", "Okta user", "okta:user/<id>", admin),
	spec("okta_group", ClassIdentity, "okta", "Okta group", "okta:group/<id>", 0),
	spec("okta_policy", ClassIdentity, "okta", "Okta policy", "okta:policy/<id>", 0),
}

var (
	byName = func() map[string]*TypeSpec {
		m := map[string]*TypeSpec{}
		for i := range registry {
			s := &registry[i]
			m[strings.ToLower(s.Type)] = s
			for _, a := range s.Aliases {
				m[strings.ToLower(a)] = s
			}
		}
		return m
	}()

	unregMu sync.Mutex
	unreg   = map[string]bool{}
)

// Registry returns a copy of every registered type, sorted by provider then type.
func Registry() []TypeSpec {
	out := make([]TypeSpec, len(registry))
	copy(out, registry)
	for i := range out {
		out[i].Aliases = append([]string(nil), registry[i].Aliases...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Lookup resolves a type or alias (case-insensitive) to its spec.
func Lookup(t string) (TypeSpec, bool) {
	s, ok := byName[strings.ToLower(strings.TrimSpace(t))]
	if !ok {
		return TypeSpec{}, false
	}
	return *s, true
}

// Registered reports whether t (or an alias of it) is a registered type.
func Registered(t string) bool {
	_, ok := byName[strings.ToLower(strings.TrimSpace(t))]
	return ok
}

// ClassFor derives a node class from a resource type string from any tool: the registry
// first; an unregistered non-empty type falls back to the legacy substring heuristic and is
// recorded for UnregisteredTypes (the coverage table's "unknown type" rows).
func ClassFor(t string) string {
	if s, ok := byName[strings.ToLower(strings.TrimSpace(t))]; ok {
		return s.Class
	}
	if t != "" {
		unregMu.Lock()
		unreg[t] = true
		unregMu.Unlock()
	}
	return legacyClassFor(t)
}

// UnregisteredTypes lists (sorted) every non-empty type ClassFor could not resolve since the
// process started (or the last ResetUnregisteredTypes).
func UnregisteredTypes() []string {
	unregMu.Lock()
	defer unregMu.Unlock()
	out := make([]string, 0, len(unreg))
	for t := range unreg {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ResetUnregisteredTypes clears the UnregisteredTypes record.
func ResetUnregisteredTypes() {
	unregMu.Lock()
	unreg = map[string]bool{}
	unregMu.Unlock()
}

// UnregisteredTypes counts this graph's nodes by unregistered non-empty type.
func (g *Graph) UnregisteredTypes() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := map[string]int{}
	for _, n := range g.nodes {
		if n.Type != "" && !Registered(n.Type) {
			out[n.Type]++
		}
	}
	return out
}
