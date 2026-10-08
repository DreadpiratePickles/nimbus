package risk

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestPrioritize(t *testing.T) {
	now := time.Now()
	g := graph.New()
	g.AddNode(&graph.Node{ID: "db", Type: "aws_db_instance", Sensitive: true, Criticality: "production", Owner: ""})
	g.AddNode(&graph.Node{ID: "vol", Type: "aws_ebs_volume", Criticality: "dev", Owner: "team-a"})
	g.AddEdge(graph.InternetNodeID, "db", graph.EdgeExposes, nil)
	hi := model.Finding{ID: "a", Status: model.Fail, Severity: model.Critical, Resource: model.Resource{ID: "db"}, Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "DATABASE"}, Compliance: map[string][]string{"pci_dss": {"1.3.6"}}, FirstSeen: now}
	lo := model.Finding{ID: "b", Status: model.Fail, Severity: model.Low, Resource: model.Resource{ID: "vol"}, Weaknesses: []string{"NO_BACKUP"}, FirstSeen: now.Add(-48 * time.Hour)}
	pass := model.Finding{ID: "c", Status: model.Pass, Severity: model.Critical}
	paths := []model.AttackPath{{ID: "p", Score: 8.5, FindingIDs: []string{"a"}}}
	ranked := Prioritize([]model.Finding{lo, hi, pass}, g, paths, Weights{}, 0, now)
	if len(ranked) != 2 || ranked[0].Finding.ID != "a" {
		t.Fatalf("ranking: %+v", ranked)
	}
	top := ranked[0]
	if top.Band != "Critical" || top.Score < 9 || top.SLADays != 7 || top.AttackPaths != 1 {
		t.Errorf("top: %+v", top)
	}
	want := []string{"internet exposed", "sensitive data", "production", "pci_dss", "orphaned", "attack path"}
	for _, w := range want {
		found := false
		for _, r := range top.Reasons {
			if contains(r, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("reason %q missing: %v", w, top.Reasons)
		}
	}
	if ranked[1].Band != "Low" || ranked[1].Owner != "team-a" {
		t.Errorf("low: %+v", ranked[1])
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
