package attackpath_test

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Delta r2 #12: P13 (dev-sam iam:PassRole + ec2:RunInstances → EC2 admin role) has a cuttable
// fix: scoping iam:PassRole (an edge fix on the escalation edge, rendered by the
// iam_passrole_scope.tf template), so the minimum fix set covers it and plan coverage rises.
func TestV4PassRoleFixCoversP13(t *testing.T) {
	r := v4Lab(t)
	const sam = "arn:aws:iam::111111111111:user/nimbus-lab-dev-sam"
	const admin = "arn:aws:iam::111111111111:role/nimbus-lab-ec2-admin-role"
	p13 := ""
	for _, p := range r.an.Paths {
		if p.RuleID == "GRAPH_TRAVERSAL" && p.Steps[0].Resource == sam && p.Steps[len(p.Steps)-1].Resource == admin {
			p13 = p.ID
		}
	}
	if p13 == "" {
		t.Fatal("P13 path not found")
	}
	var fx *attackpath.Fix
	for i, f := range r.an.MinFixSet {
		for _, id := range f.Breaks {
			if id == p13 {
				fx = &r.an.MinFixSet[i]
			}
		}
	}
	t.Logf("min fix set %d fixes, coverage %.1f%%, verified %v", len(r.an.MinFixSet), r.an.MinFixCoverage, r.an.MinFixVerified)
	if fx == nil {
		t.Fatalf("no minimum-fix-set fix breaks P13")
	}
	if fx.Weakness != attackpath.WeaknessPassRoleEscalation || fx.Edge == nil || fx.Edge.From != sam || fx.Edge.To != admin || fx.Edge.Kind != graph.EdgeCanAssume {
		t.Errorf("P13 fix %+v (edge %+v)", fx, fx.Edge)
	}
	// Before the PassRole fix: 19 fixes, 91.0 %. The one path left is ops-jane (an admin user
	// with no MFA and a stale key: two independent entry weaknesses, no single cut).
	if !r.an.MinFixVerified || r.an.MinFixCoverage <= 91.0 {
		t.Errorf("coverage %.1f%% verified %v, want > 91.0%% verified", r.an.MinFixCoverage, r.an.MinFixVerified)
	}
	if fx != nil {
		pr, ok := attackpath.PassRoleFixOf(r.g, *fx)
		if !ok || pr.Technique == "" || pr.Statement == "" {
			t.Errorf("PassRoleFixOf: %+v %v", pr, ok)
		}
		t.Logf("P13 fix: %s", fx.Command)
	}
}
