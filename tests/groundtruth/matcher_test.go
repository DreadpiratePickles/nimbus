package groundtruth

import "testing"

// Item 7: a path may continue past the labelled target through optional hops (the ClusterRole
// behind a binding) and still match; anything else after the target, or a missing target,
// does not match.
func TestMatcherOptionalTrailingHop(t *testing.T) {
	g := gtPath{Entry: "internet", Target: "crb", Hops: []string{"pod", "sa", "crb"}, OptionalHops: []string{"clusterrole"}}
	mk := func(rs ...string) *reportedPath {
		p := &reportedPath{}
		for _, r := range rs {
			p.Steps = append(p.Steps, reportedStep{Resource: r, Relation: "runs_as"})
		}
		p.normalize()
		return p
	}
	for _, c := range []struct {
		steps []string
		want  bool
	}{
		{[]string{"pod", "sa", "crb"}, true},
		{[]string{"pod", "sa", "crb", "clusterrole"}, true},
		{[]string{"pod", "sa", "clusterrole"}, false},       // target missing
		{[]string{"pod", "sa", "crb", "other"}, false},      // unlabelled hop
		{[]string{"pod", "sa", "clusterrole", "crb"}, true}, // optional hop before target
		{[]string{"pod", "crb", "sa"}, false},               // ends on a required hop that is not the target
	} {
		if got := matches(g, mk(c.steps...)); got != c.want {
			t.Errorf("%v: matches=%v, want %v", c.steps, got, c.want)
		}
	}
}

// W7-ENGINE (r5 #3): two reported paths (two Issues) on the same entry and the same ordered hops
// are one chain: the matcher counts it once, keeps the higher score and reports the collapse, so a
// duplicate Issue can neither inflate precision nor a label's match count.
func TestDistinctChainsCollapsesDuplicateHops(t *testing.T) {
	mk := func(id, rule string, score float64, entryRel string, rs ...string) *reportedPath {
		p := &reportedPath{ID: id, RuleID: rule, Score: score}
		for i, r := range rs {
			rel := "can_assume"
			if i == 0 {
				rel = entryRel
			}
			p.Steps = append(p.Steps, reportedStep{Resource: r, Relation: rel})
		}
		p.normalize()
		return p
	}
	in := []*reportedPath{
		mk("trav", "GRAPH_TRAVERSAL", 7.0, "entry", "dev-sam", "ec2-admin-role"),
		mk("rule", "aws-ec2-privesc-passrole-iam", 7.5, "entry", "dev-sam", "ec2-admin-role"),
		mk("other", "GRAPH_TRAVERSAL", 9.0, "entry", "dev-sam", "ec2-admin-role", "bucket"),
		mk("inet", "GRAPH_TRAVERSAL", 6.0, "exposed", "dev-sam", "ec2-admin-role"), // internet entry: another chain
	}
	out, dups := distinctChains(in)
	if len(out) != 3 || dups != 1 {
		t.Fatalf("distinct chains %d (dups %d), want 3 (1)", len(out), dups)
	}
	for _, p := range out {
		if p.target == "ec2-admin-role" && p.entry == "dev-sam" && p.Score != 7.5 {
			t.Errorf("collapsed chain keeps score %.2f, want the higher 7.5", p.Score)
		}
	}
}
