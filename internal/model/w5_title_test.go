package model

import "testing"

// W5-ISSUES item 2 / r3 E7: a credential-entry path Issue is titled after what the compromised
// credential reaches, never "<entry> → <entry>".
func TestPathIssueTitleCredentialEntry(t *testing.T) {
	nodes := map[string]PathNode{
		"arn:aws:iam::1:user/ops-jane":   {Name: "ops-jane", Attrs: map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}},
		"arn:aws:iam::1:role/vendor":     {Name: "vendor", Attrs: map[string]any{"attached_policies": []string{"arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/AdministratorAccess"}}},
		"arn:aws:iam::1:user/dev-sam":    {Name: "dev-sam"},
		"arn:aws:iam::1:role/ec2-admin":  {Name: "ec2-admin", Attrs: map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}},
		"arn:aws:iam::1:user/no-policy":  {Name: "no-policy"},
		"arn:aws:s3:::customer-pii":      {Name: "customer-pii"},
		"github.com/acme/infra-live":     {Name: "acme/infra-live"},
		"arn:aws:iam::1:role/gha-deploy": {Name: "gha-deploy"},
	}
	look := func(id string) (PathNode, bool) { n, ok := nodes[id]; return n, ok }
	entry := func(res, weak string) Step { return Step{Stage: 1, Relation: "entry", Resource: res, Weakness: weak} }
	cases := []struct {
		p    AttackPath
		want string
	}{
		{AttackPath{Name: "ops-jane → ops-jane", Steps: []Step{entry("arn:aws:iam::1:user/ops-jane", "NO_MFA")}},
			"credential compromise of ops-jane → AdministratorAccess"},
		{AttackPath{Name: "vendor → vendor", Steps: []Step{entry("arn:aws:iam::1:role/vendor", "CROSS_ACCOUNT_TRUST")}},
			"external trust abuse of vendor → AdministratorAccess"},
		{AttackPath{Name: "dev-sam → ec2-admin", Steps: []Step{entry("arn:aws:iam::1:user/dev-sam", "NO_MFA"), {Stage: 2, Relation: "can_assume", Resource: "arn:aws:iam::1:role/ec2-admin"}}},
			"credential compromise of dev-sam → ec2-admin (AdministratorAccess)"},
		{AttackPath{Name: "no-policy → no-policy", Steps: []Step{entry("arn:aws:iam::1:user/no-policy", "STALE_CREDENTIALS")}},
			"credential compromise of no-policy → its own permissions"},
		{AttackPath{Name: "acme/infra-live → gha-deploy", Steps: []Step{entry("github.com/acme/infra-live", "BRANCH_UNPROTECTED"), {Stage: 2, Relation: "can_assume", Resource: "arn:aws:iam::1:role/gha-deploy"}}},
			"pipeline compromise of acme/infra-live → gha-deploy"},
		// Internet paths and rule chains keep their engine name.
		{AttackPath{Name: "Internet → customer-pii → exfiltration", Steps: []Step{{Stage: 1, Relation: "exposes", Resource: "arn:aws:s3:::customer-pii"}}},
			"Internet → customer-pii → exfiltration"},
		{AttackPath{Name: "Public control plane", RuleID: "CHAIN_EKS", Steps: []Step{entry("arn:aws:iam::1:user/ops-jane", "PUBLIC_NETWORK_EXPOSURE")}},
			"Public control plane"},
	}
	for _, c := range cases {
		if got := PathIssueTitle(c.p, look); got != c.want {
			t.Errorf("%q: got %q, want %q", c.p.Name, got, c.want)
		}
	}
	// No lookup: falls back to the last path segment of the id.
	if got := PathIssueTitle(cases[0].p, nil); got != "credential compromise of ops-jane → its own permissions" {
		t.Errorf("nil lookup: %q", got)
	}
}
