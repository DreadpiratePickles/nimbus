package core

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// RM4: a targeted re-collect returns the anchor and its one-hop neighbours only.
func TestOneHopAndSubgraph(t *testing.T) {
	g := graph.New()
	for _, id := range []string{"bucket", "role", "instance", "sg", "far"} {
		g.AddNode(&graph.Node{ID: id, Type: "aws_" + id, Weaknesses: []string{"W_" + id}})
	}
	g.AddEdge(graph.InternetNodeID, "instance", graph.EdgeExposes, nil)
	g.AddEdge("instance", "sg", graph.EdgeAttachedTo, nil)
	g.AddEdge("instance", "role", "runs_as", nil)
	g.AddEdge("role", "bucket", "grants_access_to", nil)
	g.AddEdge("far", "role", "can_assume", nil)

	keep := OneHop(g, []string{"instance", "missing"})
	for _, id := range []string{"instance", "sg", "role", graph.InternetNodeID} {
		if !keep[id] {
			t.Errorf("one-hop set lacks %s: %v", id, keep)
		}
	}
	for _, id := range []string{"bucket", "far", "missing"} {
		if keep[id] {
			t.Errorf("one-hop set must not contain %s", id)
		}
	}
	sub := Subgraph(g, keep)
	if _, ok := sub.Node("bucket"); ok {
		t.Errorf("subgraph carries a two-hop node")
	}
	n, ok := sub.Node("instance")
	if !ok || len(n.Weaknesses) != 1 {
		t.Fatalf("subgraph node lost its weaknesses: %+v", n)
	}
	n.Weaknesses = nil // the fragment is a copy
	if orig, _ := g.Node("instance"); len(orig.Weaknesses) != 1 {
		t.Errorf("subgraph shares nodes with the source graph")
	}
	var kinds []string
	for _, e := range sub.Edges() {
		kinds = append(kinds, e.From+">"+e.To)
	}
	if len(sub.Edges()) != 3 {
		t.Errorf("subgraph edges = %v, want internet>instance, instance>sg, instance>role", kinds)
	}
}

func TestTargetResultInconclusive(t *testing.T) {
	r := &TargetResult{}
	if r.Inconclusive() {
		t.Errorf("clean result reported inconclusive")
	}
	r.Unsupported = []string{"arn:aws:rds:x"}
	if !r.Inconclusive() {
		t.Errorf("unsupported ids must make the read inconclusive")
	}
	r = &TargetResult{}
	r.Errors = append(r.Errors, NewCollectError("s3", errString("AccessDenied")))
	if !r.Inconclusive() {
		t.Errorf("partial errors must make the read inconclusive")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// W7-VERIFY: a kept neighbour's internet exposure travels with the fragment. verify removes the
// stored internet edges of every node the fragment covers, so a fragment anchored on a security
// group / firewall rule / NSG that dropped the internet edge of the instance it guards would
// "confirm" a fix that never happened.
func TestOneHopKeepsNeighbourExposure(t *testing.T) {
	g := graph.New()
	for _, id := range []string{"sg", "instance", "other"} {
		g.AddNode(&graph.Node{ID: id, Type: "aws_" + id})
	}
	g.AddEdge(graph.InternetNodeID, "instance", graph.EdgeExposes, nil)
	g.AddEdge(graph.InternetNodeID, "other", graph.EdgeExposes, nil)
	g.AddEdge("sg", "instance", graph.EdgeAllowsTrafficTo, nil)
	keep := OneHop(g, []string{"sg"})
	if !keep[graph.InternetNodeID] || !keep["instance"] || keep["other"] {
		t.Fatalf("keep = %v, want sg, instance and the internet (not other)", keep)
	}
	sub := Subgraph(g, keep)
	found := false
	for _, e := range sub.Out(graph.InternetNodeID) {
		if e.To == "other" {
			t.Errorf("fragment carries an unrelated exposure")
		}
		found = found || e.To == "instance"
	}
	if !found {
		t.Errorf("fragment lost the guarded instance's internet exposure")
	}
}
