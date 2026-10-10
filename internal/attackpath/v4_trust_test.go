package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Defect 10a/b (verify-4 D1/D2): trust conditions are read. A role whose trust is limited to the
// caller's organisation (aws:PrincipalOrgID) is not an external entry; a trust that requires
// sts:ExternalId (or binds sts:SourceIdentity) is likelihood 0.3, not the 0.8 of an open
// foreign-root trust, and gets no identity floor.
const (
	v4tAdmin = "arn:aws:iam::111111111111:role/admin"
	v4tRole  = "arn:aws:iam::111111111111:role/xacct"
)

func v4tGraph(attrs map[string]any) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: v4tRole, Type: "aws_iam_role", Name: "xacct", Provider: "aws", Account: "111111111111",
		Weaknesses: []string{"CROSS_ACCOUNT_TRUST"}, Attributes: attrs})
	g.AddNode(&graph.Node{ID: v4tAdmin, Type: "aws_iam_role", Name: "admin", Provider: "aws", Account: "111111111111",
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}, Attributes: map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}})
	g.AddEdge(v4tRole, v4tAdmin, graph.EdgeCanAssume, nil)
	return g
}

func trustDoc(cond map[string]any) map[string]any {
	st := map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": "arn:aws:iam::222222222222:root"}}
	if cond != nil {
		st["Condition"] = cond
	}
	return map[string]any{"Version": "2012-10-17", "Statement": []any{st}}
}

func TestV4TrustConditions(t *testing.T) {
	root := []any{"arn:aws:iam::222222222222:root"}
	cases := []struct {
		name    string
		attrs   map[string]any
		wantLik float64 // entry likelihood; 0 = no entry, no path
		maxBest float64 // best path score must stay below
	}{
		{"org via trust_conditions", map[string]any{"trust_principals": root,
			"trust_conditions": map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-abc123"}}}, UnknownOrgTrustEntry, 7}, // own org unknown: inferred, kept, never floored (W7)
		{"org via trust_policy", map[string]any{"trust_principals": root,
			"trust_policy": trustDoc(map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-abc123"}})}, UnknownOrgTrustEntry, 7},
		{"org via JSON assume_role_policy", map[string]any{"assume_role_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"},"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`}, UnknownOrgTrustEntry, 7},
		{"org via trust_policy, own org known", map[string]any{"trust_principals": root, "organization_id": "o-abc123",
			"trust_policy": trustDoc(map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-abc123"}})}, 0, 0.01},
		{"externalid via trust_policy", map[string]any{"trust_principals": root,
			"trust_policy": trustDoc(map[string]any{"StringEquals": map[string]any{"sts:ExternalId": "x-123"}})}, 0.3, 7},
		{"externalid via attribute", map[string]any{"trust_principals": root, "external_id_required": true}, 0.3, 7},
		{"sourceidentity bound", map[string]any{"trust_principals": root,
			"trust_policy": trustDoc(map[string]any{"StringEquals": map[string]any{"sts:SourceIdentity": "alice"}})}, 0.3, 7},
		{"open foreign root (control)", map[string]any{"trust_principals": root}, ExternalRootEntry, 11},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := v4tGraph(c.attrs)
			n, _ := g.Node(v4tRole)
			lik, why := crossAccountEntry(g, n)
			if lik != c.wantLik {
				t.Errorf("entry likelihood %.2f (%s), want %.2f", lik, why, c.wantLik)
			}
			an := Traverse(g, DefaultTraversalOptions())
			best := 0.0
			for _, p := range an.Paths {
				if p.Score > best {
					best = p.Score
				}
				if c.wantLik < 0.7 && ToxicCombination(p) != "" {
					t.Errorf("floored: %s %.2f %s", p.Name, p.Score, ToxicCombination(p))
				}
			}
			if best >= c.maxBest {
				t.Errorf("best path %.2f, want < %.2f", best, c.maxBest)
			}
		})
	}
	// D2: ExternalId-protected entry + PassRole privesc into admin is not floored to 7.
	g := graph.New()
	g.AddNode(&graph.Node{ID: v4tRole, Type: "aws_iam_role", Name: "xacct", Provider: "aws", Account: "111111111111",
		Weaknesses: []string{"CROSS_ACCOUNT_TRUST"}, Attributes: map[string]any{"trust_principals": root, "external_id_required": true}})
	g.AddNode(&graph.Node{ID: v4tAdmin, Type: "aws_iam_role", Name: "admin", Provider: "aws", Account: "111111111111",
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}, Attributes: map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}})
	g.AddEdge(v4tRole, v4tAdmin, graph.EdgeCanAssume, map[string]any{graph.AttrTechnique: "iam:PassRole+ec2:RunInstances"})
	for _, p := range Traverse(g, DefaultTraversalOptions()).Paths {
		if p.Score >= 7 || ToxicCombination(p) != "" {
			t.Errorf("D2: ExternalId entry + privesc floored: %.2f %q", p.Score, ToxicCombination(p))
		}
	}
}
