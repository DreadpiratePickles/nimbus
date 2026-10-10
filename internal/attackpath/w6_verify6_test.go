package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 6 defects routed to W6-ENGINE (items 6–8), from the verifier's probes
// (scratchpad/verify-6/tree-corr/internal/attackpath/zz_verify6_a_privesc*_test.go, zz_verify6_b_fold_test.go).

const v6 = "arn:aws:iam::123456789012:"

func v6Doc(stmts ...map[string]any) map[string]any {
	l := []any{}
	for _, s := range stmts {
		l = append(l, s)
	}
	return map[string]any{"Version": "2012-10-17", "Statement": l}
}

func v6Allow(action, res any) map[string]any {
	return map[string]any{"Effect": "Allow", "Action": action, "Resource": res}
}

func v6Graph() *graph.Graph {
	g := graph.New()
	user := func(name string, doc map[string]any) {
		g.AddNode(&graph.Node{ID: v6 + "user/" + name, Type: "aws_iam_user", Name: name, Provider: "aws", Account: "123456789012",
			Attributes: map[string]any{"inline_policy_document": doc}})
	}
	user("pass-star", v6Doc(v6Allow("iam:PassRole", "*"), v6Allow("lambda:CreateFunction", "*")))
	user("notaction-iam", v6Doc(map[string]any{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
	user("cond-deny-unless", v6Doc(v6Allow("iam:PutUserPolicy", "*"),
		map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": map[string]any{"BoolIfExists": map[string]any{"aws:MultiFactorAuthPresent": "false"}}}))
	user("hard-deny", v6Doc(v6Allow("iam:PutUserPolicy", "*"), map[string]any{"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "*"}))
	user("admin", v6Doc(v6Allow("*", "*")))
	g.AddNode(&graph.Node{ID: v6 + "role/lambda-exec", Type: "aws_iam_role", Name: "lambda-exec", Provider: "aws", Account: "123456789012",
		Attributes: map[string]any{"trust_principals": []any{"lambda.amazonaws.com"}, "attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}})
	g.AddNode(&graph.Node{ID: v6 + "role/ec2-admin", Type: "aws_iam_role", Name: "ec2-admin", Provider: "aws", Account: "123456789012",
		Attributes: map[string]any{"trust_principals": []any{"ec2.amazonaws.com"}, "attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}})
	g.AddNode(&graph.Node{ID: "arn:aws:ec2:us-east-1:123456789012:instance/i-1", Type: "aws_instance", Name: "i-1", Provider: "aws", Account: "123456789012"})
	g.AddEdge("arn:aws:ec2:us-east-1:123456789012:instance/i-1", v6+"role/ec2-admin", graph.EdgeRunsAs, nil)
	g.EvaluatePermissions()
	return g
}

func v6Matches(t *testing.T, g *graph.Graph, ruleID string) map[string]PathRuleMatch {
	t.Helper()
	r, ok := LibraryPathRule(ruleID)
	if !ok {
		t.Fatalf("no library rule %s", ruleID)
	}
	out := map[string]PathRuleMatch{}
	for _, m := range MatchPathRule(g, r) {
		out[strings.TrimPrefix(m.Anchor, v6)+" -> "+strings.TrimPrefix(m.Target, v6)] = m
	}
	return out
}

// Item 6: three privesc false negatives.
func TestV6PrivescFalseNegatives(t *testing.T) {
	g := v6Graph()
	// (a) iam:PassRole on * is an escalation grant, not "admin": the anchor must stay.
	if _, ok := v6Matches(t, g, "aws-lambda-privesc-passrole-create-function")["user/pass-star -> role/lambda-exec"]; !ok {
		t.Error("PassRole on * + lambda:CreateFunction: no match (anchor dropped as admin)")
	}
	// (b) Allow NotAction iam:* is not *:*: it cannot touch IAM but can run SSM commands.
	if _, ok := v6Matches(t, g, "aws-ssm-privesc-send-command")["user/notaction-iam -> arn:aws:ec2:us-east-1:123456789012:instance/i-1"]; !ok {
		t.Error("NotAction iam:* principal dropped as allowed *:*; want the ssm send-command match")
	}
	// (c) Deny-unless-MFA guardrail: an MFA session still escalates (inferred, said so).
	m, ok := v6Matches(t, g, "aws-iam-privesc-put-user-policy")["user/cond-deny-unless -> user/cond-deny-unless"]
	if !ok {
		t.Error("deny-unless-MFA guardrail hid the PutUserPolicy self-escalation")
	} else if m.Confidence != string(model.ConfidenceInferred) || !strings.Contains(strings.Join(m.Because, " "), "MFA") {
		t.Errorf("deny-unless-MFA match should be inferred and say MFA: %s %v", m.Confidence, m.Because)
	}
	// Near-misses stay misses: an unconditional Deny and a real *:* admin.
	pu := v6Matches(t, g, "aws-iam-privesc-put-user-policy")
	if _, ok := pu["user/hard-deny -> user/hard-deny"]; ok {
		t.Error("unconditional Deny PutUserPolicy matched")
	}
	if _, ok := pu["user/admin -> user/admin"]; ok {
		t.Error("a *:* admin is an anchor (an escalation adds nothing)")
	}
}

// Item 7: --max-hops 0 is an error, never silently 6.
func TestV6QueryMaxHopsZeroIsAnError(t *testing.T) {
	g, _ := labGraph(t, false)
	if _, err := Query(g, labOptions(), PathQuery{From: "internet", To: "type:aws_s3_bucket", MaxHops: 0}); err == nil || !strings.Contains(err.Error(), "max-hops") {
		t.Fatalf("MaxHops 0: want a max-hops error, got %v", err)
	}
}

// Item 8: Merge with two same-id paths keeps the higher-scoring one whatever the input order;
// equal scores → the lexicographically smaller hop list.
func TestV6MergeSameIDDeterministic(t *testing.T) {
	mk := func(score float64, hops ...string) model.AttackPath {
		p := model.AttackPath{ID: "dup", RuleID: "GRAPH_TRAVERSAL", Score: score, Severity: PathSeverity(score)}
		for i, h := range hops {
			p.Steps = append(p.Steps, model.Step{Stage: i + 1, Resource: h, Relation: "next"})
		}
		return p
	}
	lo, hi := mk(3, "A", "B"), mk(8, "A", "C", "B")
	for _, in := range [][2][]model.AttackPath{{{lo}, {hi}}, {{hi}, {lo}}, {{lo, hi}, nil}, {{hi, lo}, nil}} {
		out := Merge(in[0], in[1])
		if len(out) != 1 || out[0].Score != 8 {
			t.Fatalf("Merge kept %+v, want the 8.0 path", out)
		}
	}
	x, y := mk(5, "A", "Z"), mk(5, "A", "B")
	for _, in := range [][]model.AttackPath{{x, y}, {y, x}} {
		out := Merge(in, nil)
		if len(out) != 1 || out[0].Steps[1].Resource != "B" {
			t.Fatalf("equal-score same-id tie kept %v, want hop list A>B", out[0].Steps)
		}
	}
}
