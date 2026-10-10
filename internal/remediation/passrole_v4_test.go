package remediation

import (
	"encoding/json"
	"strings"
	"testing"
)

// Delta r2 #12: a PassRole scoping fix for privilege-escalation hops (P13): template + sidecar,
// and a policy diff that replaces the escalation role (or "*") in the PassRole statement with
// the roles the principal may still pass, conditioned on iam:PassedToService.
const samDoc = `{"Version":"2012-10-17","Statement":[
 {"Sid":"LaunchBuilders","Effect":"Allow","Action":["ec2:RunInstances","ec2:DescribeInstances"],"Resource":"*"},
 {"Sid":"PassBuilderRole","Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role"}]}`

func TestV4PassRolePolicyDiff(t *testing.T) {
	admin := "arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role"
	d, err := ScopePassRole(samDoc, []string{admin}, []string{"arn:aws:iam::111111111111:role/builder"}, "ec2.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Changed || strings.Contains(d.After, admin) || !strings.Contains(d.After, "iam:PassedToService") || !strings.Contains(d.After, "role/builder") {
		t.Errorf("diff:\n%s", d.After)
	}
	if !strings.Contains(d.After, "ec2:RunInstances") {
		t.Errorf("unrelated statement lost:\n%s", d.After)
	}
	var doc map[string]any
	if json.Unmarshal([]byte(d.After), &doc) != nil {
		t.Errorf("after is not JSON")
	}
	// "*" with a mixed statement: PassRole is split out and scoped; other actions keep "*".
	d2, _ := ScopePassRole(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]}`, nil, nil, "ec2.amazonaws.com")
	if !d2.Changed || !strings.Contains(d2.After, "ec2:RunInstances") || strings.Contains(d2.After, `"iam:PassRole"`) {
		t.Errorf("wildcard, no roles kept: PassRole must be removed, RunInstances kept:\n%s", d2.After)
	}
	// Nothing to change.
	d3, _ := ScopePassRole(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, []string{admin}, nil, "")
	if d3.Changed {
		t.Errorf("unrelated policy changed")
	}
}

func TestV4PassRoleTemplate(t *testing.T) {
	fix, err := PassRoleFix(PassRoleInput{Principal: "arn:aws:iam::111111111111:user/nimbus-lab-dev-sam", Role: "arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role",
		Technique: "iam:PassRole+ec2:RunInstances", Statement: "arn:aws:iam::111111111111:user/nimbus-lab-dev-sam/inline-policy#PassBuilderRole", Document: samDoc})
	if err != nil {
		t.Fatal(err)
	}
	if fix.Template != "iam_passrole_scope.tf" || fix.Metadata == nil || fix.Generic {
		t.Fatalf("fix %+v", fix)
	}
	for _, want := range []string{"iam:PassRole", "iam:PassedToService", "ec2.amazonaws.com", "passable_roles", "# Policy diff", "nimbus-lab-ec2-admin-role"} {
		if !strings.Contains(fix.Content, want) {
			t.Errorf("content lacks %q:\n%s", want, fix.Content)
		}
	}
	if !strings.Contains(fix.Metadata.Validation.SQL, "nimbus-lab-dev-sam") || !strings.Contains(fix.Metadata.Validation.SQL, "can_assume") {
		t.Errorf("validation SQL %q", fix.Metadata.Validation.SQL)
	}
	if !strings.HasPrefix(fix.Apply, "terraform") {
		t.Errorf("apply %q", fix.Apply)
	}
}
