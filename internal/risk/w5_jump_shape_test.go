package risk

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 5 C11 / jump-01: a VM reached only through an internet-exposed NSG
// (internet -exposes-> nsg -allows_traffic_to-> vm) scores like a VM with its own internet edge
// (exposure wide, inferred), not "no exposure data" (3.6 Low vs 5.0 Medium).
func TestJumpShapeScoresLikeDirectExposure(t *testing.T) {
	now := time.Now()
	build := func(direct bool) *graph.Graph {
		g := graph.New()
		g.AddNode(&graph.Node{ID: "nsg", Type: "azure_network_security_group", Attributes: map[string]any{graph.AttrReachability: "unknown", graph.AttrReachUnknown: "nsg rules"}})
		g.AddNode(&graph.Node{ID: "vm", Type: "azure_virtual_machine", Criticality: "production"})
		g.AddEdge(graph.InternetNodeID, "nsg", graph.EdgeExposes, nil)
		g.AddEdge("nsg", "vm", graph.EdgeAllowsTrafficTo, nil)
		if direct {
			g.AddEdge(graph.InternetNodeID, "vm", graph.EdgeExposes, nil)
		}
		return g
	}
	score := func(g *graph.Graph) (float64, float64, string) {
		f := model.Finding{ID: "cve", Status: model.Fail, Severity: model.High, Resource: model.Resource{ID: "vm"}, Weaknesses: []string{"VULNERABLE_SOFTWARE"}, FirstSeen: now}
		r := Prioritize([]model.Finding{f}, g, nil, Weights{}, 0, now)
		for _, fa := range r[0].Explanation.Factors {
			if fa.Name == "exposure" {
				return r[0].Score, fa.Multiplier, fa.Reason
			}
		}
		return r[0].Score, 0, ""
	}
	js, jm, jr := score(build(false))
	ds, _, _ := score(build(true))
	if jm < 1.39 || js < ds-0.05 {
		t.Fatalf("jump shape: score %.1f exposure ×%.2f %q; direct %.1f", js, jm, jr, ds)
	}
}
