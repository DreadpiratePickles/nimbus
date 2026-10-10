package remediation

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W5 (competitive delta r3 #10, walkthrough E8/E13): the fixes on the lab's top attack paths are
// typed Terraform, not generic stubs, and every remediation plan verifies with
// `cloud-posture verify <issue-id>` instead of pointing at SQL with a stale Track G caveat.

// labFinding mirrors the shape of the lab's seeded findings (lab/local/out/estate.findings.json).
func labFinding(canonical, provider, id, name, typ string, ws []string, attrs map[string]any) model.Finding {
	return model.Finding{ID: "lab-x", CanonicalID: canonical, Provider: provider, Severity: model.High, Status: model.Fail, Account: "111111111111", Region: "us-east-1",
		Source: "nimbus-lab", Weaknesses: ws, Resource: model.Resource{ID: id, Name: name, Type: typ, Attributes: attrs}}
}

// typedTF renders a finding as Terraform and checks it is a typed template that parses as HCL
// with every var.X declared (the same gate TestTerraformTemplatesParseAndDeclareSymbols uses).
func typedTF(t *testing.T, f model.Finding, wantTpl string) string {
	t.Helper()
	fix, err := Generate(f, Terraform)
	if err != nil {
		t.Fatalf("%s: %v", f.CanonicalID, err)
	}
	if fix.Generic || fix.Template != wantTpl {
		t.Fatalf("%s: template %q generic=%v, want typed %s\n%s", f.CanonicalID, fix.Template, fix.Generic, wantTpl, fix.Content)
	}
	if fix.Metadata == nil {
		t.Fatalf("%s: typed fix without sidecar metadata", f.CanonicalID)
	}
	und, err := iac.UndeclaredSymbols([]byte(fix.Content), fix.FileName)
	if err != nil {
		t.Fatalf("%s: rendered Terraform does not parse: %v\n%s", wantTpl, err, fix.Content)
	}
	if len(und) > 0 {
		t.Errorf("%s: undeclared %v", wantTpl, und)
	}
	if strings.Count(fix.Content, "{") != strings.Count(fix.Content, "}") {
		t.Errorf("%s: unbalanced braces", wantTpl)
	}
	return fix.Content
}

func mustContain(t *testing.T, what, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s lacks %q\n%s", what, w, out)
		}
	}
}

func TestLambdaPublicURLHasTypedTemplate(t *testing.T) {
	f := labFinding("LAMBDA_PUBLIC", "aws", "arn:aws:lambda:us-east-1:111111111111:function:nimbus-lab-export", "nimbus-lab-export", "aws_lambda_function",
		[]string{"PUBLIC_NETWORK_EXPOSURE"}, map[string]any{"function_url_auth_type": "NONE"})
	out := typedTF(t, f, "lambda_function_url_auth.tf")
	mustContain(t, "lambda fix", out,
		`resource "aws_lambda_function_url" "nimbus_lab_export"`,
		`function_name      = "nimbus-lab-export"`,
		`authorization_type = "AWS_IAM"`,
		`to = aws_lambda_function_url.nimbus_lab_export`,
		`variable "nimbus_lab_export_invoker_arns"`,
		`function_url_auth_type = "AWS_IAM"`,
		`--auth-type=AWS_IAM`)
	if regexp.MustCompile(`authorization_type\s*=\s*"NONE"`).MatchString(out) {
		t.Errorf("fix still sets AuthType NONE")
	}
	if fs := Formats("LAMBDA_PUBLIC"); len(fs) == 0 || fs[0] != Terraform {
		t.Errorf("Formats(LAMBDA_PUBLIC) = %v, want [terraform]", fs)
	}
}

func TestEKSPublicEndpointOffersPrivateOrRestrictedCIDRs(t *testing.T) {
	f := labFinding("EKS_PUBLIC_ENDPOINT", "aws", "arn:aws:eks:us-east-1:111111111111:cluster/nimbus-lab-eks", "nimbus-lab-eks", "aws_eks_cluster",
		[]string{"PUBLIC_NETWORK_EXPOSURE", "K8S_API"}, map[string]any{"endpoint_public_access": true, "public_access_cidrs": []any{"0.0.0.0/0"}})
	out := typedTF(t, f, "eks_public_endpoint.tf")
	mustContain(t, "eks fix", out,
		`endpoint_private_access = true`,
		`endpoint_public_access  = var.nimbus_lab_eks_keep_public_endpoint`,
		`public_access_cidrs     = var.nimbus_lab_eks_keep_public_endpoint ? var.nimbus_lab_eks_public_access_cidrs : null`,
		`variable "nimbus_lab_eks_public_access_cidrs"`,
		`default     = false`,
		`0.0.0.0/0`) // the validation rejects it
	if !strings.Contains(out, "vpc_config[0].subnet_ids") {
		t.Errorf("EKS fix must leave the live subnets alone (ignore_changes)")
	}
}

func TestRDSPublicSetsPubliclyAccessibleFalse(t *testing.T) {
	f := labFinding("RDS_PUBLIC", "aws", "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-orders", "nimbus-lab-orders", "aws_db_instance",
		[]string{"PUBLIC_NETWORK_EXPOSURE", "DATABASE"}, map[string]any{"publicly_accessible": true, "engine": "postgres"})
	out := typedTF(t, f, "rds_public.tf")
	mustContain(t, "rds fix", out, `resource "aws_db_instance" "nimbus_lab_orders"`, `publicly_accessible = false`, `prevent_destroy = true`)
}

func TestCrossAccountTrustWithoutExternalIdRequiresCondition(t *testing.T) {
	f := labFinding("IAM_CROSS_ACCOUNT_TRUST", "aws", "arn:aws:iam::111111111111:role/nimbus-lab-vendor-access", "nimbus-lab-vendor-access", "aws_iam_role",
		[]string{"CROSS_ACCOUNT_TRUST"}, map[string]any{"external_id_required": false, "trust_principals": []any{"arn:aws:iam::999999999999:root"}})
	out := typedTF(t, f, "iam_cross_account_trust.tf")
	mustContain(t, "cross-account fix", out,
		`default     = ["999999999999"]`, // the account the live trust policy names, not a wildcard prompt
		`variable = "sts:ExternalId"`,
		`variable = "aws:PrincipalOrgID"`,
		`variable "nimbus_lab_vendor_access_principal_org_id"`,
		`precondition {`, // the finding is "no ExternalId": one of the two conditions is required
		`var.nimbus_lab_vendor_access_external_id != null || var.nimbus_lab_vendor_access_principal_org_id != null`)
	// A wildcard-trust finding without the ExternalId flag keeps the condition optional.
	g := f
	g.Resource.Attributes = map[string]any{"trusted_accounts": []any{"222222222222"}}
	if out := typedTF(t, g, "iam_cross_account_trust.tf"); strings.Contains(out, "precondition {") {
		t.Errorf("ExternalId must stay optional when the finding is not about a missing ExternalId\n%s", out)
	}
}

func TestBranchProtectionHasTypedTemplate(t *testing.T) {
	f := labFinding("GH_BRANCH_UNPROTECTED", "github", "github.com/nimbus-lab/infra-live", "nimbus-lab/infra-live", "github_repository",
		[]string{"BRANCH_UNPROTECTED"}, map[string]any{"branch_protection": false, "default_branch": "main"})
	out := typedTF(t, f, "gh_branch_protection.tf")
	mustContain(t, "branch protection fix", out,
		`resource "github_branch_protection" "nimbus_lab_infra_live"`,
		`pattern                 = "main"`,
		`allows_force_pushes     = false`,
		`required_approving_review_count = var.nimbus_lab_infra_live_required_approvals`)
}

// Every sidecar's verify text names `cloud-posture verify` and none still carries the stale
// "until finding lifecycle lands (Track G)" caveat.
func TestSidecarsVerifyWithIssueVerify(t *testing.T) {
	ents, _ := fs.ReadDir(templateFS, "templates")
	n := 0
	for _, e := range ents {
		base, ok := strings.CutSuffix(e.Name(), metaSuffix)
		if !ok {
			continue
		}
		n++
		raw, _ := fs.ReadFile(templateFS, "templates/"+e.Name())
		for _, stale := range []string{"Until finding lifecycle lands", "Track G"} {
			if strings.Contains(string(raw), stale) {
				t.Errorf("%s still says %q", e.Name(), stale)
			}
		}
		m, err := TemplateMetadata(base)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if !strings.Contains(m.Validation.Note, "cloud-posture verify <issue-id>") {
			t.Errorf("%s: validation.note does not name `cloud-posture verify <issue-id>`: %q", e.Name(), m.Validation.Note)
		}
	}
	if n < 45 {
		t.Errorf("expected >= 45 sidecars (43 + lambda + branch protection), got %d", n)
	}
}
