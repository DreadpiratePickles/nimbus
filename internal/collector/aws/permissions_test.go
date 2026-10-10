package aws

import (
	"errors"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	webRole = "arn:aws:iam::" + acct + ":role/web-role"
	alice   = "arn:aws:iam::" + acct + ":user/alice"
	pii     = "arn:aws:s3:::prod-customer-data"
	logsB   = "arn:aws:s3:::logs"
	dbArn   = "arn:aws:rds:us-east-1:" + acct + ":db:orders"
	secArn  = "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:db-pass"
	keyArn  = "arn:aws:kms:us-east-1:" + acct + ":key/k1"
)

func edgeAt(g *graph.Graph, from, to, kind string) *graph.Edge {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return e
		}
	}
	return nil
}

// Principal -> store edges come from the evaluator (statement + confidence); policy nodes no
// longer draw grants_access_to; raw documents are stored on the nodes.
func TestCollectEvaluatorEdges(t *testing.T) {
	_, g := collect(t, fixture())
	cases := []struct {
		from, to, stmt string
	}{
		{webRole, pii, "arn:aws:iam::aws:policy/AmazonS3FullAccess#0"},
		{webRole, logsB, "arn:aws:iam::aws:policy/AmazonS3FullAccess#0"},
		{webRole, secArn, webRole + "/inline-policy/secrets#0"},
		{alice, dbArn, "arn:aws:iam::" + acct + ":policy/full#0"},
		{alice, pii, "arn:aws:iam::" + acct + ":policy/full#0"},
	}
	for _, c := range cases {
		e := edgeAt(g, c.from, c.to, graph.EdgeGrantsAccessTo)
		if e == nil {
			t.Errorf("missing %s -grants_access_to-> %s", c.from, c.to)
			continue
		}
		p, ok := e.Permission()
		if !ok || p.Statement != c.stmt || p.Effect != model.EffectAllow {
			t.Errorf("%s -> %s permission = %+v, want statement %s", c.from, c.to, p, c.stmt)
		}
		if e.Confidence() != model.ConfidenceVerified {
			t.Errorf("%s -> %s confidence = %q", c.from, c.to, e.Confidence())
		}
	}
	if edgeAt(g, webRole, dbArn, graph.EdgeGrantsAccessTo) != nil {
		t.Error("S3-only role must not reach the database")
	}
	for _, e := range g.Edges() {
		if e.Kind == graph.EdgeGrantsAccessTo && strings.Contains(e.From, ":policy/") {
			t.Errorf("policy node still draws grants_access_to: %s -> %s", e.From, e.To)
		}
	}
	if n, _ := g.Node("arn:aws:iam::" + acct + ":policy/full"); n.Attributes["policy_document"] == nil || n.Attributes["policy_arn"] != "arn:aws:iam::"+acct+":policy/full" {
		t.Errorf("policy node attrs = %v", n.Attributes)
	}
	if n, _ := g.Node(webRole); !strings.Contains(n.Attributes["trust_policy"].(string), "ec2.amazonaws.com") || n.Attributes["iam_policies_complete"] != true {
		t.Errorf("role attrs = %v", n.Attributes)
	}
	if n, _ := g.Node(core.AccountNodeID("aws", acct)); n.Attributes["scp_status"] != "not_in_org" {
		t.Errorf("account scp_status = %v", n.Attributes["scp_status"])
	}
	// Cross-account trust with no recorded caller policy: inferred, caller_permission unknown.
	e := edgeAt(g, core.AccountNodeID("aws", "222222222222"), "arn:aws:iam::"+acct+":role/vendor", graph.EdgeCanAssume)
	if e == nil || e.Confidence() != model.ConfidenceInferred || e.Attr["caller_permission"] != "unknown" {
		t.Errorf("vendor can_assume = %v", e)
	}
}

// A bucket policy Deny and a KMS key policy that does not enable IAM remove the edges.
func TestCollectResourcePolicies(t *testing.T) {
	f := fixture()
	f.bucketPolicy = map[string]string{"prod-customer-data": `{"Version":"2012-10-17","Statement":[{"Sid":"DenyWeb","Effect":"Deny","Principal":{"AWS":"` + webRole + `"},"Action":"s3:GetObject","Resource":"` + pii + `/*"}]}`}
	f.keyPolicy = map[string]string{"k1": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + acct + `:role/key-admin"},"Action":"kms:*","Resource":"*"}]}`}
	_, g := collect(t, f)
	if edgeAt(g, webRole, pii, graph.EdgeGrantsAccessTo) != nil {
		t.Error("bucket policy Deny left the read edge")
	}
	if n, _ := g.Node(webRole); !strings.Contains(deniedOf(n), "DenyWeb") {
		t.Errorf("denied record = %s", deniedOf(n))
	}
	if edgeAt(g, alice, keyArn, graph.EdgeGrantsAccessTo) != nil {
		t.Error("key policy without the IAM delegation must block kms:Decrypt")
	}
	if n, _ := g.Node(pii); n.Attributes["resource_policy"] == nil || n.Attributes["resource_policy_status"] != "collected" {
		t.Errorf("bucket attrs = %v", n.Attributes)
	}
}

func deniedOf(n *graph.Node) string {
	var b strings.Builder
	if l, ok := n.Attributes[graph.AttrDeniedEdges].([]any); ok {
		for _, x := range l {
			if m, ok := x.(map[string]any); ok {
				b.WriteString(m["denied_by"].(string) + " ")
			}
		}
	}
	return b.String()
}

// SCPs along the OU chain (root -> OU -> account) are collected and enforced.
func TestCollectSCPChain(t *testing.T) {
	f := fixture()
	f.org = &fakeOrg{
		parents: map[string][]OrgParent{acct: {{ID: "ou-ab12-data", Type: "ORGANIZATIONAL_UNIT"}}, "ou-ab12-data": {{ID: "r-ab12", Type: "ROOT"}}},
		attached: map[string][]OrgPolicy{
			"r-ab12":       {{ID: "p-FullAWSAccess", Name: "FullAWSAccess", AWSManaged: true}},
			"ou-ab12-data": {{ID: "p-FullAWSAccess", Name: "FullAWSAccess", AWSManaged: true}, {ID: "p-noread", Name: "deny-pii-read"}},
			acct:           {{ID: "p-FullAWSAccess", Name: "FullAWSAccess", AWSManaged: true}},
		},
		content: map[string]string{
			"p-FullAWSAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			"p-noread":        `{"Version":"2012-10-17","Statement":[{"Sid":"NoPII","Effect":"Deny","Action":"s3:GetObject","Resource":"` + pii + `/*"}]}`,
		},
	}
	res, g := collect(t, f)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	an, _ := g.Node(core.AccountNodeID("aws", acct))
	if an.Attributes["scp_status"] != "collected" {
		t.Fatalf("scp_status = %v", an.Attributes["scp_status"])
	}
	if lv, _ := an.Attributes["scp_levels"].([]any); len(lv) != 3 {
		t.Fatalf("scp_levels = %v, want root, OU, account", an.Attributes["scp_levels"])
	}
	if edgeAt(g, webRole, pii, graph.EdgeGrantsAccessTo) != nil || edgeAt(g, alice, pii, graph.EdgeGrantsAccessTo) != nil {
		t.Error("OU SCP deny left a read edge to the PII bucket")
	}
	if edgeAt(g, webRole, logsB, graph.EdgeGrantsAccessTo) == nil {
		t.Error("SCP deny is scoped to the PII bucket; logs stays readable")
	}
	if n, _ := g.Node(webRole); !strings.Contains(deniedOf(n), "scp p-noread#NoPII") {
		t.Errorf("denied record = %s", deniedOf(n))
	}
}

// A member account cannot read Organizations: the denied call is a coverage row and the
// edges drop to inferred (SCPs unknown).
func TestCollectSCPDenied(t *testing.T) {
	f := fixture()
	f.org = &fakeOrg{fail: map[string]error{"ListParents": apiErr("AccessDeniedException")}}
	res, g := collect(t, f)
	found := false
	for _, err := range res.Errors {
		var ce *core.CollectError
		if errors.As(err, &ce) && strings.Contains(ce.API, "organizations:ListParents") && ce.Reason == core.ReasonAccessDenied {
			found = true
		}
	}
	if !found {
		t.Fatalf("no access_denied coverage row for organizations:ListParents: %v", res.Errors)
	}
	if an, _ := g.Node(core.AccountNodeID("aws", acct)); an.Attributes["scp_status"] != "denied" {
		t.Errorf("scp_status = %v", an.Attributes["scp_status"])
	}
	if e := edgeAt(g, webRole, pii, graph.EdgeGrantsAccessTo); e == nil || e.Confidence() != model.ConfidenceInferred {
		t.Errorf("edge with unknown SCPs = %v", e)
	}
}

// A policy document the evaluator cannot parse falls back to the statement heuristic: hint.
func TestCollectHeuristicFallbackIsHint(t *testing.T) {
	f := fixture()
	rd := &f.auth.RoleDetailList[0]
	rd.RolePolicyList[0].PolicyDocument = strPtr(`{"Statement":{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:` + acct + `:secret:db-*","Condition":{"StringEquals":{"aws:x":{"nested":1}}}}}`)
	_, g := collect(t, f)
	e := edgeAt(g, webRole, secArn, graph.EdgeGrantsAccessTo)
	if e == nil || e.Confidence() != model.ConfidenceHint {
		t.Fatalf("fallback edge = %v", e)
	}
	if n, _ := g.Node(webRole); n.Attributes["iam_policies_complete"] == true {
		t.Error("a role with an unparseable policy is not complete")
	}
}

func strPtr(s string) *string { return &s }
