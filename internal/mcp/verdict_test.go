package mcp

import (
	"encoding/json"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// One verdict everywhere (delta r2 #1/#8): MCP `paths` rows and `issue` answers carry
// graph.Verdict for the node their exposure statement is about, the same struct and Label the
// CLI prints, so an agent never re-derives (and contradicts) reachability.

func verdictOf(t *testing.T, v any) graph.Verdict {
	t.Helper()
	b, _ := json.Marshal(v)
	var out graph.Verdict
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("verdict %s: %v", b, err)
	}
	return out
}

func TestPathsRowsCarryEntryVerdict(t *testing.T) {
	fx := newFixture(t)
	g, err := storeReader{st: fx.st}.LoadGraph()
	if err != nil {
		t.Fatal(err)
	}
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	checked := 0
	for _, p := range variantsOf(c.toolOK("paths", map[string]any{"limit": 200})) {
		pm := p.(map[string]any)
		hops := pm["hops"].([]any)
		if len(hops) == 0 {
			continue
		}
		entry := hops[0].(map[string]any)["resource"].(string)
		raw, ok := pm["verdict"]
		if !ok {
			t.Fatalf("path %v has no verdict", pm["id"])
		}
		got, want := verdictOf(t, raw), g.Verdict(entry)
		if got != want {
			t.Errorf("path %v: verdict %+v, want graph.Verdict(%s) %+v", pm["id"], got, entry, want)
		}
		if got.Status != "" {
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no path row carries a non-empty verdict")
	}
}

func TestIssueCarriesResourceVerdictBlocked(t *testing.T) {
	fx := newFixture(t)
	issues, err := fx.st.Issues(storeIssueFilterAll())
	if err != nil {
		t.Fatal(err)
	}
	g, err := storeReader{st: fx.st}.LoadGraph()
	if err != nil {
		t.Fatal(err)
	}
	var single *model.Issue // a single Issue on a resource with no internet route yet
	for i := range issues {
		if issues[i].Kind == model.IssueSingle && issues[i].ResourceID != "" && g.Verdict(issues[i].ResourceID).Routes == 0 {
			single = &issues[i]
			break
		}
	}
	if single == nil {
		t.Fatal("fixture has no single Issue off the internet")
	}
	// The network analysis disproves the exposure of the Issue's resource.
	if _, ok := g.Node(single.ResourceID); !ok {
		g.AddNode(&graph.Node{ID: single.ResourceID, Name: "r", Type: "aws_db_instance", Class: graph.ClassDataStore})
	}
	g.AddEdge(graph.InternetNodeID, single.ResourceID, graph.EdgeExposes, map[string]any{
		graph.AttrReachability: graph.VerdictBlocked, graph.AttrReachBlocker: "route table rtb-1 has no route to an internet gateway"})
	saveGraph(t, fx.st, g)
	want := g.Verdict(single.ResourceID)
	if want.Status != graph.VerdictBlocked {
		t.Fatalf("setup: verdict %+v", want)
	}

	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("issue", map[string]any{"id": single.ID})
	raw, ok := res["verdict"]
	if !ok {
		t.Fatalf("issue answer has no verdict: %v", res)
	}
	if got := verdictOf(t, raw); got != want {
		t.Fatalf("issue verdict %+v, want %+v", got, want)
	}
}
