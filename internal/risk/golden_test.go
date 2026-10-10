package risk

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var update = flag.Bool("update", false, "rewrite python/tests/fixtures/go_risk.json")

const (
	pyInput  = "../../python/tests/fixtures/risk_input.json"
	pyGolden = "../../python/tests/fixtures/go_risk.json"
)

// TestPythonGolden ranks the Python test estate with the Go score and compares it with the golden file
// the Python tests consume, so Python can never show a number Go did not produce.
func TestPythonGolden(t *testing.T) {
	data, err := os.ReadFile(pyInput)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Now      time.Time       `json:"now"`
		Findings []model.Finding `json:"findings"`
		Graph    struct {
			Nodes []*graph.Node `json:"nodes"`
			Edges []graph.Edge  `json:"edges"`
		} `json:"graph"`
		Paths []model.AttackPath `json:"paths"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	for _, n := range in.Graph.Nodes {
		g.AddNode(n)
	}
	for _, e := range in.Graph.Edges {
		g.AddEdge(e.From, e.To, e.Kind, e.Attr)
	}
	ranked := PrioritizeWith(in.Findings, g, in.Paths, Options{Intel: intel.Snapshot(), Now: in.Now})
	for i := range ranked {
		ranked[i].Finding.Raw = nil
	}
	got, err := json.MarshalIndent(ranked, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile(pyGolden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(pyGolden)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/risk -run TestPythonGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Go ranking of the Python fixture drifted from %s; if intended, bump ScoreVersion, add a changelog entry and run with -update", pyGolden)
	}
}
