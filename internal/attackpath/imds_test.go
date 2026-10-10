package attackpath

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// imdsGraph: internet → instance (exposed on the given ports) → runs_as admin role.
func imdsGraph(ports string, weak ...string) *graph.Graph {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "i-web", Type: "aws_instance", Name: "web", Provider: "aws", Account: "1",
		Weaknesses: append([]string{"PUBLIC_NETWORK_EXPOSURE"}, weak...), FindingIDs: []string{"f-web"}})
	g.AddNode(&graph.Node{ID: "role-admin", Type: "aws_iam_role", Name: "web-role", Provider: "aws", Account: "1",
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}, FindingIDs: []string{"f-admin"}})
	g.AddEdge(graph.InternetNodeID, "i-web", graph.EdgeExposes, map[string]any{"ports": ports, "exposure": "wide", "exposure_cidrs": []string{"0.0.0.0/0"}})
	g.AddEdge("i-web", "role-admin", graph.EdgeRunsAs, map[string]any{"instance_profile": "web-profile"})
	return g
}

func credHop(t *testing.T, an *Analysis) (float64, bool) {
	t.Helper()
	for _, p := range an.Paths {
		for _, s := range p.Steps {
			if s.Resource == "role-admin" {
				l, ok := s.Evidence["likelihood"].(float64)
				if !ok {
					t.Fatalf("step evidence lacks likelihood: %v", s.Evidence)
				}
				return l, true
			}
		}
	}
	return 0, false
}

// Item 5 (planning decision): the instance → role hop is 1.0 with IMDSv1 on an internet-exposed
// instance (SSRF), 0.6 with a known-exploited/critical vulnerability on an exposed instance,
// otherwise 0.1 (unknown code execution needed), which keeps the path below the reporting
// threshold. A remote-login port open to the internet (SSH/RDP) is a known access route: 0.5.
func TestIMDSv1Semantics(t *testing.T) {
	cases := []struct {
		name     string
		g        *graph.Graph
		want     float64
		reported bool
	}{
		{"imdsv1 exposed web", imdsGraph("443", "IMDSV1_ENABLED"), 1.0, true},
		// Engine round 2 CVE gate: UNPATCHED with no CVE ids to check against KEV / EPSS is
		// "exploitability unknown" (0.3, confidence hint), no longer a flat 0.6.
		{"cve exposed web", imdsGraph("443", "UNPATCHED"), 0.3, true},
		{"imdsv1 and cve", imdsGraph("443", "IMDSV1_ENABLED", "UNPATCHED"), 1.0, true},
		{"ssh open", imdsGraph("22"), 0.5, true},
		{"plain exposed web", imdsGraph("443"), 0.1, false},
	}
	for _, c := range cases {
		an := Traverse(c.g, DefaultTraversalOptions())
		got, found := credHop(t, an)
		if found != c.reported {
			t.Errorf("%s: path reported=%v, want %v (%+v)", c.name, found, c.reported, an.Paths)
			continue
		}
		if found && got != c.want {
			t.Errorf("%s: instance→role likelihood %.2f, want %.2f", c.name, got, c.want)
		}
	}
	// IMDSv1 on an instance that is not internet-exposed does not give SSRF from the internet.
	g := imdsGraph("443", "IMDSV1_ENABLED")
	g.RemoveEdge(graph.InternetNodeID, "i-web", graph.EdgeExposes)
	g.AddNode(&graph.Node{ID: "u", Type: "aws_iam_user", Name: "dev", Weaknesses: []string{"NO_MFA"}})
	g.AddEdge("u", "i-web", graph.EdgeAllowsTrafficTo, nil) // lateral foothold only
	if l, ok := credHop(t, Traverse(g, DefaultTraversalOptions())); ok {
		t.Errorf("unexposed IMDSv1 instance still yields a reported path (hop %.2f)", l)
	}
}

// Consequence: disabling IMDSv1 on a non-vulnerable exposed instance breaks the path (verified
// by Simulate); on a vulnerable one it only reduces it.
func TestIMDSv1FixBreaksPathOnlyWithoutCVE(t *testing.T) {
	for _, c := range []struct {
		name   string
		g      *graph.Graph
		breaks bool
	}{
		{"web, no CVE", imdsGraph("443", "IMDSV1_ENABLED"), true},
		{"web with CVE", imdsGraph("443", "IMDSV1_ENABLED", "UNPATCHED"), false},
	} {
		an := Traverse(c.g, DefaultTraversalOptions())
		if len(an.Paths) != 1 {
			t.Fatalf("%s: want 1 path, got %+v", c.name, an.Paths)
		}
		fix := Fix{NodeID: "i-web", Weakness: "IMDSV1_ENABLED"}
		removed, _ := Simulate(c.g, []Fix{fix})
		inBreak := false
		for _, fx := range an.BreakFixes {
			if fx.NodeID == "i-web" && fx.Weakness == "IMDSV1_ENABLED" {
				inBreak = len(fx.Breaks) == 1
			}
		}
		if (removed == 1) != c.breaks || inBreak != c.breaks {
			t.Errorf("%s: Simulate removed %d, classified break=%v; want break=%v", c.name, removed, inBreak, c.breaks)
		}
	}
}
