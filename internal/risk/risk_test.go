package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
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
	if top.Band != "Critical" || top.Score < 9 || top.SLADays != 0 || !top.DueAt.IsZero() || top.AttackPaths != 1 || top.ScoreVersion != ScoreVersion {
		t.Errorf("top: %+v", top)
	}
	// compliance and ownership are ×1.0 since 2.1.0: they leave Reasons but stay in the explanation.
	want := []string{"internet exposed", "sensitive data", "production", "attack path"}
	for _, f := range top.Explanation.Factors {
		if f.Name == "compliance_scope" && (f.Multiplier != 1 || !strings.Contains(f.Reason, "pci_dss")) {
			t.Errorf("compliance_scope: %+v", f)
		}
		if f.Name == "ownership" && (f.Multiplier != 1 || !strings.Contains(f.Reason, "orphaned")) {
			t.Errorf("ownership: %+v", f)
		}
	}
	for _, w := range want {
		found := false
		for _, r := range top.Reasons {
			if strings.Contains(r, w) {
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
	if ranked[0].Explanation == nil || ranked[1].Explanation == nil {
		t.Error("every ranked finding carries an explanation")
	}
}

func TestBands(t *testing.T) {
	cases := map[float64]string{10: "Critical", 9: "Critical", 8.9: "High", 7: "High", 6.9: "Medium", 5: "Medium", 4.9: "Low", 0: "Low"}
	for s, want := range cases {
		if got := BandFor(s); got != want {
			t.Errorf("BandFor(%v) = %s, want %s", s, got, want)
		}
	}
}

func TestCrownJewelLevelsFromNodeCriticality(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "x", Type: "aws_instance", Criticality: "very_high", Owner: "o"})
	f := model.Finding{ID: "x", Status: model.Fail, Severity: model.Medium, Resource: model.Resource{ID: "x"}, FirstSeen: time.Now().Add(-72 * time.Hour)}
	r := PrioritizeWith([]model.Finding{f}, g, nil, Options{Now: time.Now()})[0]
	// 2.2.0: raw 4.0 × very_high 2.0 = 8.0 is above the 7.0 knee: 7 + 3(1 − e^(−1/4.5)) = 7.6.
	if r.Score != 7.6 || r.Explanation.Raw != 8.0 {
		t.Errorf("MEDIUM 4.0 × very_high 2.0 = raw 8.0 → 7.6, got %.1f raw %.2f (%s)", r.Score, r.Explanation.Raw, factorSummary(r))
	}
	// a config matcher wins over node criticality
	jf := func(n *graph.Node) (string, string, bool) { return "low", "rule x", true }
	r = PrioritizeWith([]model.Finding{f}, g, nil, Options{Now: time.Now(), CrownJewel: jf})[0]
	if r.Score != 4.0 {
		t.Errorf("config level low ×1.0 must win, got %.1f", r.Score)
	}
}

// TestConfigCrownJewelHook reads levels from the config crown_jewels block (config.MatchCrownJewel).
func TestConfigCrownJewelHook(t *testing.T) {
	if JewelFromConfig(&config.Config{}) != nil {
		t.Error("no rules must mean no matcher")
	}
	cfg := &config.Config{CrownJewels: []config.CrownJewelRule{
		{Name: "payments-db", Level: "very_high", Types: []string{"aws_db_*"}, Tags: map[string]string{"app": "payments"}},
		{Name: "all-dbs", Level: "medium", Types: []string{"aws_db_*"}},
	}}
	jf := JewelFromConfig(cfg)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "pay", Type: "aws_db_instance", Name: "pay", Owner: "o", Attributes: map[string]any{"tags": map[string]any{"app": "payments"}}})
	g.AddNode(&graph.Node{ID: "other", Type: "aws_db_instance", Name: "other", Owner: "o", Criticality: "production"})
	g.AddNode(&graph.Node{ID: "vm", Type: "aws_instance", Name: "vm", Owner: "o"})
	mk := func(id string) model.Finding {
		return model.Finding{ID: id, Status: model.Fail, Severity: model.Medium, Resource: model.Resource{ID: id}, FirstSeen: time.Now().Add(-72 * time.Hour)}
	}
	got := map[string]Ranked{}
	for _, r := range PrioritizeWith([]model.Finding{mk("pay"), mk("other"), mk("vm")}, g, nil, Options{CrownJewel: jf, Now: time.Now()}) {
		got[r.Finding.ID] = r
	}
	crit := func(id string) Factor {
		for _, f := range got[id].Explanation.Factors {
			if f.Name == "criticality" {
				return f
			}
		}
		return Factor{}
	}
	if f := crit("pay"); f.Multiplier != 2.0 || !strings.Contains(strings.Join(f.Evidence, " "), "payments-db") {
		t.Errorf("pay: highest level very_high ×2.0 from rule payments-db, got %+v", f)
	}
	if f := crit("other"); f.Multiplier != 1.2 {
		t.Errorf("other: config medium ×1.2 must win over node criticality production, got %+v", f)
	}
	if f := crit("vm"); f.Status != StatusNotScored {
		t.Errorf("vm: no rule and no criticality → not scored, got %+v", f)
	}
}
