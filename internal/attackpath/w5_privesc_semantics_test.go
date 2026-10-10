package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// The ported IAM privesc rules follow Prowler's (pathfinding.cloud's) target semantics:
// CreateAccessKey / CreateLoginProfile / UpdateLoginProfile take over OTHER users,
// UpdateAssumeRolePolicy targets other roles, Put/AttachUserPolicy anchor on users only,
// Put/AttachRolePolicy on roles only, CreatePolicyVersion targets a customer-managed policy
// attached to the principal, and a principal that is already admin is never an escalation.
func TestIAMPrivescRulesFollowUpstreamTargets(t *testing.T) {
	const acct = "123456789012"
	arn := func(s string) string { return "arn:aws:iam::" + acct + ":" + s }
	pol := func(actions ...string) map[string]any {
		acts := make([]any, len(actions))
		for i, a := range actions {
			acts[i] = a
		}
		return map[string]any{"inline_policy_document": map[string]any{"Version": "2012-10-17",
			"Statement": []any{map[string]any{"Effect": "Allow", "Action": acts, "Resource": "*"}}}}
	}
	g := graph.New()
	add := func(id, typ string, attrs map[string]any) {
		if attrs == nil {
			attrs = map[string]any{}
		}
		g.AddNode(&graph.Node{ID: id, Type: typ, Provider: "aws", Account: acct, Attributes: attrs})
	}
	add(arn("user/admin"), "aws_iam_user", pol("*"))
	add(arn("user/dev"), "aws_iam_user", pol("iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
		"iam:UpdateAssumeRolePolicy", "iam:PutUserPolicy", "iam:AttachUserPolicy", "iam:PutGroupPolicy", "iam:CreatePolicyVersion", "s3:GetObject"))
	add(arn("user/victim"), "aws_iam_user", pol("s3:GetObject"))
	add(arn("role/app"), "aws_iam_role", pol("iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreateAccessKey"))
	add(arn("group/devs"), "aws_iam_group", nil)
	add(arn("policy/dev-managed"), "aws_iam_policy", map[string]any{"policy_document": map[string]any{"Version": "2012-10-17",
		"Statement": []any{map[string]any{"Effect": "Allow", "Action": "logs:*", "Resource": "*"}}}})
	g.AddEdge(arn("user/dev"), arn("group/devs"), graph.EdgeMemberOf, nil)
	g.AddEdge(arn("user/dev"), arn("policy/dev-managed"), graph.EdgeHasPolicy, nil)
	g.AddEdge(arn("user/dev"), "arn:aws:iam::aws:policy/ReadOnlyAccess", graph.EdgeHasPolicy, nil)
	g.EvaluatePermissions()

	rules, err := LibraryPathRules()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]PathRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	got := func(id string) map[[2]string]bool {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("rule %s missing", id)
		}
		out := map[[2]string]bool{}
		for _, m := range MatchPathRule(g, r) {
			out[[2]string{strings.TrimPrefix(m.Anchor, "arn:aws:iam::"+acct+":"), strings.TrimPrefix(m.Target, "arn:aws:iam::"+acct+":")}] = true
		}
		return out
	}
	want := map[string][][2]string{
		"aws-iam-privesc-create-access-key":         {{"user/dev", "user/victim"}, {"user/dev", "user/admin"}, {"role/app", "user/victim"}, {"role/app", "user/dev"}, {"role/app", "user/admin"}},
		"aws-iam-privesc-create-login-profile":      {{"user/dev", "user/victim"}, {"user/dev", "user/admin"}},
		"aws-iam-privesc-update-login-profile":      {{"user/dev", "user/victim"}, {"user/dev", "user/admin"}},
		"aws-iam-privesc-update-assume-role-policy": {{"user/dev", "role/app"}},
		"aws-iam-privesc-put-user-policy":           {{"user/dev", "user/dev"}},
		"aws-iam-privesc-attach-user-policy":        {{"user/dev", "user/dev"}},
		"aws-iam-privesc-put-role-policy":           {{"role/app", "role/app"}},
		"aws-iam-privesc-attach-role-policy":        {{"role/app", "role/app"}},
		"aws-iam-privesc-put-group-policy":          {{"user/dev", "group/devs"}},
		"aws-iam-privesc-create-policy-version":     {{"user/dev", "policy/dev-managed"}},
	}
	for id, pairs := range want {
		m := got(id)
		exp := map[[2]string]bool{}
		for _, p := range pairs {
			exp[p] = true
			if !m[p] {
				t.Errorf("%s: missing %s -> %s (got %v)", id, p[0], p[1], m)
			}
		}
		for p := range m {
			if !exp[p] {
				t.Errorf("%s: unexpected %s -> %s", id, p[0], p[1])
			}
		}
	}
}
