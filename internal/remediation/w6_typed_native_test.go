package remediation

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-ENGINE item 2 (competitive delta r4 #9; bar: AWS remediation plans / CrowdStrike plan
// coverage): the lab-native checks behind the generic stubs in `plan --top 20` (instance SSH/HTTPS
// exposure, LoadBalancer services, the Bedrock agent, GitHub OIDC trust without sub, K8s secret
// RBAC, Okta MFA-exempt sign-on) and GCP_INSTANCE_PUBLIC_IP map to canonical ids with typed
// templates and sidecars. Findings are enriched through the catalog exactly as ingest does.
func TestLabNativeChecksHaveTypedTemplates(t *testing.T) {
	type tc struct {
		checkID, resID, name, typ, provider string
		format                              Format
		wantCanonical, wantTpl              string
		wants                               []string
		attrs                               map[string]any
	}
	cases := []tc{
		{"ec2_instance_port_ssh_exposed_to_internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60001", "nimbus-lab-web-01", "aws_instance", "aws", Terraform,
			"EC2_INSTANCE_PORT_EXPOSED", "ec2_instance_port_exposed.tf", []string{`from_port   = 22`, `aws ec2 modify-instance-attribute`, `variable "nimbus_lab_web_01_allowed_cidrs"`}, map[string]any{"exposure_cidrs": []any{"0.0.0.0/0"}}},
		{"ec2_instance_port_https_exposed_to_internet", "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60005", "nimbus-lab-media-01", "aws_instance", "aws", Terraform,
			"EC2_INSTANCE_PORT_EXPOSED", "ec2_instance_port_exposed.tf", []string{`from_port   = 443`}, nil},
		{"compute_instance_public_ip", "//compute.googleapis.com/projects/nimbus-lab-gcp/zones/us-central1-a/instances/nimbus-lab-gce-web", "nimbus-lab-gce-web", "gcp_compute_instance", "gcp", Terraform,
			"GCP_INSTANCE_PUBLIC_IP", "gcp_instance_no_public_ip.tf", []string{`gcloud compute instances delete-access-config`}, nil},
		{"iam_role_github_oidc_trust_without_subject_condition", "arn:aws:iam::111111111111:role/nimbus-lab-gha-legacy-deploy", "nimbus-lab-gha-legacy-deploy", "aws_iam_role", "aws", Terraform,
			"IAM_OIDC_TRUST_NO_SUBJECT", "iam_github_oidc_subject.tf", []string{`token.actions.githubusercontent.com:sub`, `token.actions.githubusercontent.com:aud`}, nil},
		{"bedrock_agent_publicly_invocable", "arn:aws:bedrock:us-east-1:111111111111:agent/NIMBUSLAB01", "NIMBUSLAB01", "aws_bedrockagent_agent", "aws", Terraform,
			"BEDROCK_AGENT_PUBLIC", "bedrock_agent_private.tf", []string{`authorization_type = "AWS_IAM"`}, nil},
		{"okta_signon_rule_mfa_exempt", "okta:user/00u0nimbuslab0contractor", "contractor@nimbus-lab.example", "okta_user", "okta", Terraform,
			"OKTA_SIGNON_MFA_EXEMPT", "okta_signon_mfa.tf", []string{`mfa_required`, `resource "okta_policy_rule_signon"`}, nil},
		{"service_type_loadbalancer_public", "analytics/pod/report-worker-0", "report-worker-0", "k8s_pod", "kubernetes", Kubernetes,
			"K8S_SERVICE_PUBLIC_LB", "k8s_service_internal_lb.k8s.yaml", []string{`loadBalancerSourceRanges`, `aws-load-balancer-internal`}, map[string]any{"namespace": "analytics"}},
		{"rbac_minimize_secret_access", "cluster/clusterrolebinding/storefront-secrets-reader", "storefront-secrets-reader", "k8s_clusterrolebinding", "kubernetes", Kubernetes,
			"K8S_SECRETS_RBAC_WIDE", "k8s_rbac_secrets.k8s.yaml", []string{`kind: Role`, `resources: ["secrets"]`, `resourceNames:`}, map[string]any{"subject": "storefront", "namespace": "web"}},
	}
	for _, c := range cases {
		f := model.Finding{ID: "lab-x", Source: "nimbus-lab", CheckID: c.checkID, Provider: c.provider, Severity: model.High, Status: model.Fail,
			Account: "111111111111", Region: "us-east-1", Resource: model.Resource{ID: c.resID, Name: c.name, Type: c.typ, Attributes: c.attrs}}
		ws := map[string]bool{}
		catalog.Default().Enrich(&f)
		for _, w := range f.Weaknesses {
			ws[w] = true
		}
		if f.CanonicalID != c.wantCanonical {
			t.Errorf("%s → canonical %q, want %s", c.checkID, f.CanonicalID, c.wantCanonical)
			continue
		}
		fix, err := Generate(f, c.format)
		if err != nil {
			t.Errorf("%s: %v", c.checkID, err)
			continue
		}
		if fix.Generic || fix.Template != c.wantTpl || fix.Metadata == nil {
			t.Errorf("%s: template %q generic=%v meta=%v, want typed %s", c.checkID, fix.Template, fix.Generic, fix.Metadata != nil, c.wantTpl)
			continue
		}
		if c.format == Terraform {
			typedTF(t, f, c.wantTpl)
		}
		mustContain(t, c.wantTpl, fix.Content, c.wants...)
	}
}
