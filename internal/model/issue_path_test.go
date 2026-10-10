package model

import (
	"regexp"
	"testing"
)

func labPath(middle string) AttackPath {
	return AttackPath{ID: "x", RuleID: "GRAPH_TRAVERSAL", Score: 7.6, Severity: Critical, Steps: []Step{
		{Stage: 1, Relation: "exposes", Resource: middle, Evidence: map[string]any{"edge": "exposes", "confidence": "verified"}},
		{Stage: 2, Relation: "allows_traffic_to", Resource: "i-web", Evidence: map[string]any{"edge": "allows_traffic_to", "confidence": "verified"}},
		{Stage: 3, Relation: "runs_as", Resource: "role/web", Evidence: map[string]any{"edge": "runs_as", "confidence": "inferred"}},
	}}
}

// P1-ISSUES item 10: the path Issue id is sha256(kind|entry|anchor|rule)[:16], hex.
func TestPathIssueIDShape(t *testing.T) {
	id := PathIssueID(IssuePath, "internet", "role/web", PathRuleTraversal)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("id %q is not 16 hex-encoded bytes", id)
	}
	if id != PathIssueID(IssuePath, "internet", "role/web", PathRuleTraversal) {
		t.Fatal("PathIssueID is not deterministic")
	}
	for _, other := range []string{
		PathIssueID(IssueChokepoint, "internet", "role/web", PathRuleTraversal),
		PathIssueID(IssuePath, "user/jane", "role/web", PathRuleTraversal),
		PathIssueID(IssuePath, "internet", "role/batch", PathRuleTraversal),
		PathIssueID(IssuePath, "internet", "role/web", "CHAIN_X"),
		PathIssueID(IssuePath, "internet|role/web", "", PathRuleTraversal), // separator is not ambiguous for these
	} {
		if other == id {
			t.Errorf("distinct key collided with %s", id)
		}
	}
}

// Middle hops are evidence: they change the secondary key, never the Issue key.
func TestPathIssueKeyIgnoresMiddleHop(t *testing.T) {
	a, b := labPath("sg-1"), labPath("sg-2")
	ea, aa, ra := PathIssueKey(a)
	eb, ab, rb := PathIssueKey(b)
	if ea != "internet" || aa != "role/web" || ra != PathRuleTraversal {
		t.Fatalf("key = (%s, %s, %s), want (internet, role/web, traversal)", ea, aa, ra)
	}
	if ea != eb || aa != ab || ra != rb {
		t.Fatalf("a plumbing hop changed the Issue key: %s/%s/%s vs %s/%s/%s", ea, aa, ra, eb, ab, rb)
	}
	if PathSecondaryKey(a) == PathSecondaryKey(b) {
		t.Fatal("secondary key must change when a hop changes")
	}
	if PathSecondaryKey(a) != PathSecondaryKey(labPath("sg-1")) {
		t.Fatal("secondary key is not deterministic")
	}
	// identity entry: the entry step's resource is the entry
	id := AttackPath{RuleID: "GRAPH_TRAVERSAL", Steps: []Step{{Relation: "entry", Resource: "user/jane", Evidence: map[string]any{"entry": true}}}}
	if e, an, _ := PathIssueKey(id); e != "user/jane" || an != "user/jane" {
		t.Errorf("identity entry key = %s, %s", e, an)
	}
	// rule chains keep their rule id
	if _, _, r := PathIssueKey(AttackPath{RuleID: "CHAIN_PUBLIC_ADMIN", Steps: a.Steps}); r != "CHAIN_PUBLIC_ADMIN" {
		t.Errorf("rule = %s", r)
	}
}

func TestPathConfidenceIsWeakestEdge(t *testing.T) {
	if c := PathConfidence(labPath("sg")); c != ConfidenceInferred {
		t.Errorf("confidence = %s, want inferred (weakest hop)", c)
	}
	p := labPath("sg")
	p.Steps[1].Evidence["confidence"] = "hint"
	if c := PathConfidence(p); c != ConfidenceHint {
		t.Errorf("confidence = %s, want hint", c)
	}
	p.Steps[1].Evidence["confidence"] = "verified"
	p.Steps[2].Evidence["confidence"] = "verified"
	if c := PathConfidence(p); c != ConfidenceVerified {
		t.Errorf("confidence = %s, want verified", c)
	}
	delete(p.Steps[2].Evidence, "confidence") // unlabelled edge: not proven, so inferred
	if c := PathConfidence(p); c != ConfidenceInferred {
		t.Errorf("unlabelled edge confidence = %s, want inferred", c)
	}
}

func TestScoreBand(t *testing.T) {
	for s, want := range map[float64]string{10: "Critical", 9: "Critical", 8.99: "High", 7: "High", 5: "Medium", 4.99: "Low", 0: "Low"} {
		if got := ScoreBand(s); got != want {
			t.Errorf("ScoreBand(%v) = %s, want %s", s, got, want)
		}
	}
}
