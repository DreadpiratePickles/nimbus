package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func factorNamed(r Ranked, name string) *Factor {
	for i, f := range r.Explanation.Factors {
		if f.Name == name {
			return &r.Explanation.Factors[i]
		}
	}
	return nil
}

// offPathEstate: an exposure-only website bucket (CRITICAL finding, wide, production), a host on
// a complete path, an admin role and a PII bucket no path reaches.
func offPathEstate() ([]model.Finding, *graph.Graph, []model.AttackPath) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "www", Type: "aws_s3_bucket", Criticality: "production", Owner: "web", Attributes: map[string]any{"exposure": "wide"}})
	g.AddNode(&graph.Node{ID: "host", Type: "aws_instance", Criticality: "production", Owner: "app", Attributes: map[string]any{"exposure": "wide"}})
	g.AddNode(&graph.Node{ID: "admin", Type: "aws_iam_role", Owner: "sec", Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	g.AddNode(&graph.Node{ID: "pii", Type: "aws_s3_bucket", Owner: "data", Attributes: map[string]any{"dspm_labels": []any{"pii"}, "exposure": "none"}})
	f := func(id, res string, sev model.Severity, weak ...string) model.Finding {
		return model.Finding{ID: id, Status: model.Fail, Severity: sev, CanonicalID: "X", Resource: model.Resource{ID: res}, Weaknesses: weak, FirstSeen: now.Add(-72 * time.Hour)}
	}
	fs := []model.Finding{
		f("www-public", "www", model.Critical, "PUBLIC_DATA_STORE"),
		f("host-logging", "host", model.High, "NO_LOGGING"), // on the path by resource, not by finding id
		f("admin-policy", "admin", model.High, "OVERPRIVILEGED_IDENTITY"),
		f("pii-noenc", "pii", model.Critical, "UNENCRYPTED_AT_REST"),
	}
	paths := []model.AttackPath{{ID: "p", Score: 7, Steps: []model.Step{{Resource: "host"}, {Resource: "crown"}}}}
	return fs, g, paths
}

func TestOffPathCapsExposureOnlyFindings(t *testing.T) {
	fs, g, paths := offPathEstate()
	by := map[string]Ranked{}
	for _, r := range PrioritizeWith(fs, g, paths, Options{Now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}) {
		by[r.Finding.ID] = r
	}
	www := by["www-public"]
	off := factorNamed(www, "off_path")
	if off == nil || off.Multiplier != 0.5 || off.Status != StatusScored || off.Reason != "no attack path reaches an impact target from this resource" {
		t.Fatalf("www off_path: %+v", off)
	}
	// 7.0 × 1.4 × 1.3 × 0.5 = 6.37 (data not scored): under the ceiling, Medium
	if www.Score != 6.4 || www.Band != "Medium" {
		t.Errorf("www: %.1f %s (%s)", www.Score, www.Band, factorSummary(www))
	}
	if o := factorNamed(by["host-logging"], "off_path"); o == nil || o.Multiplier != 1 || !strings.Contains(o.Reason, "on a complete attack path") {
		t.Errorf("host on the path by resource: %+v", o)
	}
	for _, id := range []string{"admin-policy", "pii-noenc"} {
		if o := factorNamed(by[id], "off_path"); o == nil || o.Multiplier != 1 || !strings.Contains(o.Reason, "impact target") {
			t.Errorf("%s is an impact target, not capped: %+v", id, o)
		}
	}
	// admin role with no path: 5.5 × 1.25 = 6.875 → Medium by weight, not by the cap
	if r := by["admin-policy"]; r.Score != 6.9 || r.Band != "Medium" {
		t.Errorf("unreachable admin role: %.1f %s (%s)", r.Score, r.Band, factorSummary(r))
	}
}

func TestOffPathCeilingIsExplained(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "h", Type: "aws_instance", Criticality: "production", Owner: "o", Attributes: map[string]any{"exposure": "wide"}})
	f := model.Finding{ID: "kev", Status: model.Fail, Severity: model.Critical, CheckID: "CVE-2021-44228", Resource: model.Resource{ID: "h"}}
	r := PrioritizeWith([]model.Finding{f}, g, nil, Options{Now: time.Now()})[0]
	// 7.0 × 1.4 × 1.3 × 1.5 (KEV) × 0.5 = 9.555 → capped at 6.9
	last := r.Explanation.Factors[len(r.Explanation.Factors)-1]
	if r.Score != 6.9 || r.Band != "Medium" || last.Name != "off_path_cap" || !strings.Contains(last.Reason, "at most Medium") {
		t.Fatalf("score %.1f %s, last factor %+v", r.Score, r.Band, last)
	}
	prod := r.Explanation.Base
	for _, x := range r.Explanation.Factors {
		prod *= x.Multiplier
	}
	if d := prod - r.Score; d > 0.01 || d < -0.01 {
		t.Errorf("base × factors = %.4f, score %.1f", prod, r.Score)
	}
}

func TestOffPathNotScoredWithoutAnalysis(t *testing.T) {
	fs, g, paths := offPathEstate()
	for _, o := range []struct {
		name string
		g    *graph.Graph
		opt  Options
	}{{"nil graph", nil, Options{}}, {"NoAnalysis", g, Options{NoAnalysis: true}}} {
		for _, r := range PrioritizeWith(fs, o.g, paths, o.opt) {
			off := factorNamed(r, "off_path")
			if off == nil || off.Status != StatusNotScored || off.Multiplier != 1 {
				t.Errorf("%s %s: off_path %+v", o.name, r.Finding.ID, off)
			}
			if r.Score > 6.9 && factorNamed(r, "off_path_cap") != nil {
				t.Errorf("%s %s: capped without analysis", o.name, r.Finding.ID)
			}
		}
	}
}

func TestOffPathReadsAnalysis(t *testing.T) {
	fs, g, _ := offPathEstate()
	an := &attackpath.Analysis{
		ReachesCrownJewel: map[string]bool{"host": true, "www": false},
		Exposures:         []attackpath.Exposure{{NodeID: "www", Width: "wide", Because: "internet → www (public website)"}},
	}
	by := map[string]Ranked{}
	for _, r := range PrioritizeWith(fs, g, nil, Options{Analysis: an, Now: time.Now()}) {
		by[r.Finding.ID] = r
	}
	if o := factorNamed(by["host-logging"], "off_path"); o == nil || o.Multiplier != 1 {
		t.Errorf("ReachesCrownJewel[host]=true must count as on a path: %+v", o)
	}
	o := factorNamed(by["www-public"], "off_path")
	if o == nil || o.Multiplier != 0.5 || !strings.Contains(strings.Join(o.Evidence, "|"), "exposure only (wide)") {
		t.Errorf("www: Exposures evidence missing: %+v", o)
	}
}

// TestExplicitClassificationBeatsNameHeuristic: a node the graph marks sensitive by name, but
// classified public / none, is not a sensitive data store (same rule as the path engine).
func TestExplicitClassificationBeatsNameHeuristic(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "b", Type: "aws_s3_bucket", Sensitive: true, Owner: "o",
		Attributes: map[string]any{"exposure": "wide", "tags": map[string]any{"data_classification": "public"}}})
	f := model.Finding{ID: "f", Status: model.Fail, Severity: model.High, Resource: model.Resource{ID: "b"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}}
	r := PrioritizeWith([]model.Finding{f}, g, nil, Options{Now: time.Now()})[0]
	d := factorNamed(r, "data_sensitivity")
	if d == nil || d.Multiplier != DefaultWeights.DataNonSensitive || !strings.Contains(strings.Join(d.Evidence, " "), "overrides") {
		t.Errorf("data_sensitivity: %+v", d)
	}
	if o := factorNamed(r, "off_path"); o == nil || o.Multiplier != DefaultWeights.OffPath {
		t.Errorf("non-sensitive public bucket off path must be capped: %+v", o)
	}
}
