package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// W7-ENGINE item 4 (r5 #15, verification 6 C1; bar: AWS trust evaluation with
// aws:PrincipalOrgID). The role's own organisation id comes from the account node
// (organization_id, collected by organizations:DescribeOrganization) or the role itself:
//
//	condition org == own org          → not an external entry (no path)
//	condition org is a foreign org    → external entry (path kept, open)
//	own org unknown (or denied)       → inferred entry, path kept at the protected-trust likelihood
func TestPrincipalOrgIDTrustSemantics(t *testing.T) {
	root := []any{"arn:aws:iam::222222222222:root"}
	doc := v5tDoc(v5tAllow(v5tC("StringEquals", "aws:PrincipalOrgID", "o-mine")))
	build := func(acctAttrs map[string]any) *graph.Graph {
		g := v4tGraph(map[string]any{"trust_principals": root, "trust_policy": doc})
		if acctAttrs != nil {
			g.AddNode(&graph.Node{ID: "aws:account:111111111111", Type: "aws_account", Class: graph.ClassAccount, Provider: "aws", Account: "111111111111", Attributes: acctAttrs})
		}
		return g
	}
	cases := []struct {
		name     string
		acct     map[string]any
		lik      float64
		inferred bool
		why      string
		path     bool
	}{
		{"same org (collected)", map[string]any{"organization_id": "o-mine", "organization_id_status": "collected"}, 0, false, "same organisation", false},
		{"foreign org (collected)", map[string]any{"organization_id": "o-other", "organization_id_status": "collected"}, ExternalRootEntry, false, "", true},
		{"own account in no organisation", map[string]any{"organization_id_status": "not_in_org"}, ExternalRootEntry, false, "", true},
		{"own org unknown", nil, UnknownOrgTrustEntry, true, "unknown", true},
		{"own org denied", map[string]any{"organization_id_status": "denied"}, UnknownOrgTrustEntry, true, "unknown", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := build(c.acct)
			n, _ := g.Node(v4tRole)
			lik, why, inferred := crossAccountEntryEval(g, n)
			if lik != c.lik || inferred != c.inferred || !strings.Contains(why, c.why) {
				t.Errorf("entry %.2f inferred=%v (%s), want %.2f inferred=%v containing %q", lik, inferred, why, c.lik, c.inferred, c.why)
			}
			an := Traverse(g, DefaultTraversalOptions())
			if got := len(an.Paths) > 0; got != c.path {
				t.Fatalf("paths %d, want path=%v", len(an.Paths), c.path)
			}
			if c.inferred {
				for _, p := range an.Paths {
					if p.Steps[0].Evidence["confidence"] != "inferred" {
						t.Errorf("entry step of %s not labelled inferred: %v", p.Name, p.Steps[0].Evidence)
					}
					if p.Score >= 7 || ToxicCombination(p) != "" {
						t.Errorf("an unknown-org entry is floored: %.2f %q", p.Score, ToxicCombination(p))
					}
				}
			}
		})
	}
}
