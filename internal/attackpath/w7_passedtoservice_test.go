package attackpath

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
)

// W7-ENGINE item 7 (verification 7 defect 5): the rule engine evaluates iam:PassedToService. A
// PassRole limited to a service the rule does not exploit (lambda for EC2-001) is no match; one
// limited to the exploited service (ec2) is the verified match it was before the condition. The
// verifier's two adversarial fixtures are the tests (their own expect blocks).
func TestPassedToServiceConditionIsEvaluated(t *testing.T) {
	for _, f := range []string{"cond_wrong_service.yaml", "cond_right_service.yaml"} {
		r, err := LoadPathRuleFile(filepath.Join("testdata", "verify7", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := RunPathRuleTests(r); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// The PassRole fix (remediation.ScopePassRole, recommended by passRoleCommand) removes the match
// because it drops the escalation role; the iam:PassedToService condition it adds names the
// exploited service (ec2), so the condition alone would not, and the recommendation says so.
func TestPassRoleScopeFixRemovesTheMatchOnlyByDroppingTheRole(t *testing.T) {
	lib, ok := LibraryPathRule(ec2RuleID)
	if !ok {
		t.Fatal("no EC2-001 rule")
	}
	const dev, admin = "arn:aws:iam::123456789012:user/dev", "arn:aws:iam::123456789012:role/admin"
	doc := map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": []any{"ec2:RunInstances"}, "Resource": "*"},
		map[string]any{"Sid": "Pass", "Effect": "Allow", "Action": "iam:PassRole", "Resource": []any{admin, "arn:aws:iam::123456789012:role/app"}},
	}}
	matches := func(policy any) []PathRuleMatch {
		r := lib
		r.Tests.Fixture.Nodes = []PathRuleFixtureNode{
			{ID: dev, Type: "aws_iam_user", Account: "123456789012", Attributes: map[string]any{"inline_policy_document": policy}},
			{ID: admin, Type: "aws_iam_role", Account: "123456789012", Attributes: map[string]any{"trust_principals": []any{"ec2.amazonaws.com"},
				"instance_profile": "arn:aws:iam::123456789012:instance-profile/admin", "attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}},
		}
		var out []PathRuleMatch
		for _, m := range MatchPathRule(r.FixtureGraph(), r) {
			if m.Anchor == dev && m.Target == admin {
				out = append(out, m)
			}
		}
		return out
	}
	if len(matches(doc)) != 1 {
		t.Fatalf("control: unscoped PassRole must match")
	}
	diff, err := remediation.ScopePassRole(doc, []string{admin}, nil, "ec2.amazonaws.com")
	if err != nil {
		t.Fatal(err)
	}
	var after any
	if err := json.Unmarshal([]byte(diff.After), &after); err != nil {
		t.Fatal(err)
	}
	if got := matches(after); len(got) != 0 {
		t.Errorf("scoped policy still matches: %+v", got)
	}
	// Condition only (role kept) on the exploited service: still an escalation.
	condOnly := map[string]any{"Version": "2012-10-17", "Statement": []any{
		map[string]any{"Effect": "Allow", "Action": []any{"ec2:RunInstances"}, "Resource": "*"},
		map[string]any{"Effect": "Allow", "Action": "iam:PassRole", "Resource": admin, "Condition": map[string]any{"StringEquals": map[string]any{"iam:PassedToService": "ec2.amazonaws.com"}}},
	}}
	if len(matches(condOnly)) != 1 {
		t.Errorf("PassedToService=ec2 with the role kept must still match")
	}
	if cmd := passRoleCommand(graph.New(), dev, admin); !strings.Contains(cmd, "drop "+admin) || !strings.Contains(cmd, "alone does not") {
		t.Errorf("recommendation must say dropping the role is the fix, not the condition: %s", cmd)
	}
}
