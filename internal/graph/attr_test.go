package graph_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// TestEdgeAttrContract sets every contract attribute on a graph edge through the typed
// helpers, then round-trips the edge through JSON and through the store's graph_edges table
// exactly as cli.saveGraph / cli.loadGraph do (json.Marshal(e.Attr) into the attr TEXT
// column; json.Unmarshal into map[string]any; AddEdge), and reads every value back typed.
func TestEdgeAttrContract(t *testing.T) {
	perm := model.PermissionAttr{
		Actions:   []string{"s3:GetObject"},
		Resources: []string{"arn:aws:s3:::lab-pii/*"},
		Statement: "arn:aws:iam::111111111111:policy/export#ExportRead",
		PolicyARN: "arn:aws:iam::111111111111:policy/export",
		Effect:    model.EffectAllow,
	}
	exp := model.Exposure{Width: model.ExposureNarrow, CIDRs: []string{"198.51.100.0/24"}, Reason: "sg-1 allows 198.51.100.0/24 on 22"}

	g := graph.New()
	g.AddNode(&graph.Node{ID: "arn:aws:iam::111111111111:role/app", Type: "aws_iam_role"})
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::lab-pii", Type: "aws_s3_bucket"})
	g.AddEdge("arn:aws:iam::111111111111:role/app", "arn:aws:s3:::lab-pii", graph.EdgeGrantsAccessTo, map[string]any{"via": "export"})
	e := g.Out("arn:aws:iam::111111111111:role/app")[0]
	clone := g.Clone() // helpers copy-on-write: the clone's edge must not change
	e.SetPermission(perm)
	e.SetConfidence(model.ConfidenceInferred)
	e.SetExposure(exp)
	e.SetBecause("export policy allows s3:GetObject on lab-pii")
	if ce := clone.Out("arn:aws:iam::111111111111:role/app")[0]; ce.Attr["actions"] != nil {
		t.Fatalf("setter mutated a shared attr map: %v", ce.Attr)
	}

	check := func(stage string, e *graph.Edge) {
		t.Helper()
		if p, ok := e.Permission(); !ok || !reflect.DeepEqual(p, perm) {
			t.Errorf("%s: Permission() = %+v, %v", stage, p, ok)
		}
		if c := e.Confidence(); c != model.ConfidenceInferred {
			t.Errorf("%s: Confidence() = %q", stage, c)
		}
		if x, ok := e.Exposure(); !ok || !reflect.DeepEqual(x, exp) {
			t.Errorf("%s: Exposure() = %+v, %v", stage, x, ok)
		}
		if b := e.Because(); b != "export policy allows s3:GetObject on lab-pii" {
			t.Errorf("%s: Because() = %q", stage, b)
		}
		if e.Attr["via"] != "export" {
			t.Errorf("%s: non-contract key lost: %v", stage, e.Attr)
		}
		if _, err := e.Attrs(); err != nil {
			t.Errorf("%s: Attrs(): %v", stage, err)
		}
	}
	check("in memory", e)

	// JSON (dashboard / graph export) round trip.
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var je graph.Edge
	if err := json.Unmarshal(b, &je); err != nil {
		t.Fatal(err)
	}
	check("json", &je)

	// graph_edges round trip through the real store.
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var edges []store.GraphEdge
	for _, x := range g.Edges() {
		attr, _ := json.Marshal(x.Attr)
		edges = append(edges, store.GraphEdge{From: x.From, To: x.To, Kind: x.Kind, Attr: attr})
	}
	if err := st.ReplaceGraph(nil, edges); err != nil {
		t.Fatal(err)
	}
	_, loaded, err := st.LoadGraph()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("LoadGraph: %d edges, %v", len(loaded), err)
	}
	var attr map[string]any
	if err := json.Unmarshal(loaded[0].Attr, &attr); err != nil {
		t.Fatal(err)
	}
	g2 := graph.New()
	g2.AddEdge(loaded[0].From, loaded[0].To, loaded[0].Kind, attr)
	check("graph_edges", g2.Out(loaded[0].From)[0])
}

// An edge with no contract attributes reads as absent, not as zero values that look real.
func TestEdgeAttrAbsent(t *testing.T) {
	g := graph.New()
	g.AddEdge("a", "b", graph.EdgeAttachedTo, nil)
	e := g.Out("a")[0]
	if _, ok := e.Permission(); ok {
		t.Error("Permission present on a bare edge")
	}
	if _, ok := e.Exposure(); ok {
		t.Error("Exposure present on a bare edge")
	}
	if e.Confidence() != "" {
		t.Errorf("confidence on a bare edge: %q", e.Confidence())
	}
	if e.Because() == "" {
		t.Error("AddEdge must still derive because")
	}
}
