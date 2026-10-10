package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// P1-PLANDIFF / planning decision on P12: the CI-entry floor. An unprotected default branch (or
// any-contributor write) + an OIDC role trust whose subject is wildcard / unpinned ⇒ likelihood
// floor 0.7 to admin-level targets, tagged toxic_combination ci-entry. It never applies to a
// pinned subject, a protected repository, a non-admin target, or an unknown subject.

func ciGraph(repoWeak []string, edgeAttr, roleAttrs map[string]any, roleWeak []string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "github.com/acme/infra", Type: "github_repository", Name: "acme/infra", Provider: "github", Weaknesses: repoWeak, FindingIDs: []string{"f-repo"}})
	g.AddNode(&graph.Node{ID: "arn:aws:iam::1:role/deploy", Type: "aws_iam_role", Name: "deploy", Provider: "aws", Account: "1", Attributes: roleAttrs, Weaknesses: roleWeak, FindingIDs: []string{"f-role"}})
	g.AddEdge("github.com/acme/infra", "arn:aws:iam::1:role/deploy", graph.EdgeCanAssume, edgeAttr)
	return g
}

func ciPath(t *testing.T, g *graph.Graph) *model.AttackPath {
	t.Helper()
	an := Traverse(g, DefaultTraversalOptions())
	for i := range an.Paths {
		if pathEntry(an.Paths[i]) == "github.com/acme/infra" {
			return &an.Paths[i]
		}
	}
	return nil
}

func TestCIEntryFloorP12Shape(t *testing.T) {
	admin := map[string]any{"attached_policies": []any{"arn:aws:iam::aws:policy/AdministratorAccess"}}
	for name, edge := range map[string]map[string]any{
		"edge via text":     {"via": "GitHub OIDC sub repo:acme/infra:*"},
		"edge oidc_subject": {"oidc_subject": "repo:acme/infra:ref:refs/heads/*"},
	} {
		p := ciPath(t, ciGraph([]string{"BRANCH_UNPROTECTED"}, edge, admin, []string{"OVERPRIVILEGED_IDENTITY"}))
		if p == nil {
			t.Fatalf("%s: no path", name)
		}
		if p.Score != 7 || ToxicCombination(*p) != ToxicCIEntry {
			t.Errorf("%s: score %.2f toxic %q, want 7.00 ci-entry", name, p.Score, ToxicCombination(*p))
		}
		if b := lastBecause(*p); !strings.Contains(b, "toxic combination ci-entry") || !strings.Contains(b, "unpinned") {
			t.Errorf("%s: because %q lacks the ci-entry reason", name, b)
		}
		ev := p.Steps[len(p.Steps)-1].Evidence
		if ev["oidc_subject_class"] != "unpinned" {
			t.Errorf("%s: hop evidence %v lacks oidc_subject_class", name, ev)
		}
	}
	// Subject read from the role's trust policy (no sub condition = wildcard).
	trust := map[string]any{"attached_policies": []any{"AdministratorAccess"}, "trust_policy": map[string]any{"Statement": []any{map[string]any{
		"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Principal": map[string]any{"Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"}}}}}
	if p := ciPath(t, ciGraph([]string{"BRANCH_UNPROTECTED"}, nil, trust, nil)); p == nil || p.Score != 7 || ToxicCombination(*p) != ToxicCIEntry {
		t.Errorf("trust-policy wildcard: %+v", p)
	}
}

func TestCIEntryFloorDoesNotApply(t *testing.T) {
	admin := map[string]any{"attached_policies": []any{"AdministratorAccess"}}
	cases := map[string]*graph.Graph{
		"pinned subject":  ciGraph([]string{"BRANCH_UNPROTECTED"}, map[string]any{"via": "GitHub OIDC sub repo:acme/infra:ref:refs/heads/main"}, admin, nil),
		"unknown subject": ciGraph([]string{"BRANCH_UNPROTECTED"}, map[string]any{"via": "federated trust"}, admin, nil),
		"other repo":      ciGraph([]string{"BRANCH_UNPROTECTED"}, map[string]any{"oidc_subject": "repo:acme/other:*"}, admin, nil),
		"non-admin role":  ciGraph([]string{"BRANCH_UNPROTECTED"}, map[string]any{"via": "GitHub OIDC sub repo:acme/infra:*"}, map[string]any{"attached_policies": []any{"ReadOnlyAccess"}}, nil),
	}
	for name, g := range cases {
		p := ciPath(t, g)
		if p != nil && (ToxicCombination(*p) == ToxicCIEntry || p.Score >= 7) {
			t.Errorf("%s: floored: %.2f %q", name, p.Score, ToxicCombination(*p))
		}
	}
	// Protected repository: no entry at all, so no path (F05).
	if p := ciPath(t, ciGraph(nil, map[string]any{"via": "GitHub OIDC sub repo:acme/infra:*"}, admin, nil)); p != nil {
		t.Errorf("protected repo produced a path: %.2f", p.Score)
	}
}

func TestCIEntryFloorLabP12(t *testing.T) {
	gt := groundTruth(t)
	g, _ := labGraph(t, true)
	an := Traverse(g, labOptions())
	p := bestMatchPath(gt["P12"], an.Paths)
	if p == nil || p.Score < 7 || ToxicCombination(*p) != ToxicCIEntry {
		t.Fatalf("P12: %+v, want >= 7 with ci-entry", p)
	}
	if f := bestMatchPath(gt["F05"], an.Paths); f != nil {
		t.Errorf("F05 (pinned, protected) reported: %.2f", f.Score)
	}
}
