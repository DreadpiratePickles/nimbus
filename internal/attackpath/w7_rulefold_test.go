package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-ENGINE (r5 #3): a verified rule match whose escalation hop is a sub-path of an emitted
// traversal path (the prefix ends on the escalation target and a longer complete path continues
// past it) folds into every carrying path as also_matches_rule; no rule-match path is emitted.
func TestRuleMatchSubPathFoldsIntoLongerPath(t *testing.T) {
	r := PathRule{ID: "aws-test-privesc", Title: "Test escalation", VerifiedByEdge: &PathRuleEdgeProof{Kind: "can_assume"},
		Credit: &PathRuleCredit{Source: "Prowler", Licence: "Apache-2.0", UpstreamID: "aws-test-privesc"}}
	m := PathRuleMatch{RuleID: r.ID, Title: r.Title, Anchor: "dev", Target: "role", Confidence: "verified", Because: []string{"dev may iam:PassRole on role"}}
	step := func(res, rel string) model.Step {
		return model.Step{Resource: res, Relation: rel, Evidence: map[string]any{"edge": rel}}
	}
	prefix := model.AttackPath{ID: "prefix", RuleID: "GRAPH_TRAVERSAL", Score: 6, Steps: []model.Step{
		{Resource: "dev", Relation: "entry", Evidence: map[string]any{"entry": true}}, step("role", "can_assume")}}
	longer := model.AttackPath{ID: "longer", RuleID: "GRAPH_TRAVERSAL", Score: 8, Steps: append(append([]model.Step(nil), prefix.Steps...), step("bucket", "can_access"))}
	other := model.AttackPath{ID: "other", RuleID: "GRAPH_TRAVERSAL", Score: 9, Steps: []model.Step{
		{Resource: "dev", Relation: "entry"}, step("role2", "can_assume")}}

	paths := []model.AttackPath{other, longer, prefix}
	out, id, ok := foldRuleMatch(r, m, paths, false)
	if !ok {
		t.Fatalf("the escalation dev → role lies on two emitted paths; foldRuleMatch found no carrier")
	}
	if id != "longer" {
		t.Errorf("folded into %q, want the best-scoring carrier %q", id, "longer")
	}
	tagged := map[string]bool{}
	for _, p := range out {
		for _, x := range AlsoMatchesRules(p) {
			if x == r.ID {
				tagged[p.ID] = true
			}
		}
	}
	if !tagged["longer"] || !tagged["prefix"] || tagged["other"] {
		t.Errorf("tagged %v, want longer and prefix only", tagged)
	}
	if AlsoMatchesRules(paths[1]) != nil {
		t.Errorf("input paths were mutated")
	}
	// A wrong edge kind on the hop is not the escalation the rule proves: no fold.
	wrong := longer
	wrong.Steps = append([]model.Step(nil), longer.Steps...)
	wrong.Steps[1] = step("role", "member_of")
	if _, _, ok := foldRuleMatch(r, m, []model.AttackPath{wrong}, false); ok {
		t.Errorf("folded into a path whose dev → role hop is not a can_assume edge")
	}
}
