package groundtruth

import "testing"

// matchNoiseTP: a reported path is a TP when it is the labelled chain or a sub-chain sharing its
// entry and target; a network-control entry may be skipped on an internet path; any hop off the
// chain, or a different target, makes it a false positive.
func TestMatchNoiseTP(t *testing.T) {
	tp := noiseTP{ID: "TP1", Entry: "sg", Target: "data", Chain: []string{"sg", "host", "role", "data"}}
	types := map[string]string{"sg": "aws_security_group", "host": "aws_instance"}
	path := func(first string, rest ...string) *reportedPath {
		p := &reportedPath{Steps: []reportedStep{{Resource: first, Relation: "exposes", Weakness: "PUBLIC_NETWORK_EXPOSURE"}}}
		for _, r := range rest {
			p.Steps = append(p.Steps, reportedStep{Resource: r, Relation: "grants_access_to"})
		}
		p.normalize()
		return p
	}
	cases := []struct {
		name string
		p    *reportedPath
		want bool
	}{
		{"full chain", path("sg", "host", "role", "data"), true},
		{"sub-chain without the role", path("sg", "host", "data"), true},
		{"starts at the workload behind the SG", path("host", "role", "data"), true},
		{"starts mid-chain at the role", path("role", "data"), false},
		{"hop off the chain", path("sg", "host", "other-role", "data"), false},
		{"different target", path("sg", "host", "role"), false},
	}
	for _, c := range cases {
		if got := matchNoiseTP(tp, c.p, types); got != c.want {
			t.Errorf("%s: matchNoiseTP = %v, want %v", c.name, got, c.want)
		}
	}
	// A non-network entry may not be skipped.
	repo := noiseTP{ID: "TP2", Entry: "repo", Target: "role", Chain: []string{"repo", "role"}}
	p := &reportedPath{Steps: []reportedStep{{Resource: "role", Relation: "entry", Weakness: "OVERPRIVILEGED_IDENTITY"}}}
	p.normalize()
	if matchNoiseTP(repo, p, types) {
		t.Error("a path that drops a non-network entry must not match")
	}
}
