package risk

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// testdataFixture parses every scanner sample in ../../testdata into findings, a graph and one path.
func testdataFixture(t *testing.T) ([]model.Finding, *graph.Graph, []model.AttackPath) {
	t.Helper()
	files, _ := filepath.Glob("../../testdata/*")
	var fs []model.Finding
	for _, p := range files {
		got, _, err := adapters.ParseFile(p, "", adapters.Options{})
		if err != nil {
			continue
		}
		fs = append(fs, got...)
	}
	if len(fs) < 10 {
		t.Fatalf("testdata produced only %d findings", len(fs))
	}
	g := graph.New()
	g.AttachFindings(fs)
	var ids []string
	for _, f := range fs {
		if f.Status == model.Fail && len(ids) < 3 {
			ids = append(ids, f.ID)
		}
	}
	return fs, g, []model.AttackPath{{ID: "p1", Name: "fixture path", Score: 8.2, FindingIDs: ids}, {ID: "p2", Name: "second", Score: 6.0, FindingIDs: ids[:1]}}
}

func TestExplainReproducesScore(t *testing.T) {
	fs, g, paths := testdataFixture(t)
	ranked := PrioritizeWith(fs, g, paths, Options{Intel: intel.Snapshot(), Now: time.Now()})
	if len(ranked) == 0 {
		t.Fatal("nothing ranked")
	}
	_, cfs, cg, cpaths, jf := buildCalibration(t)
	ranked = append(ranked, PrioritizeWith(cfs, cg, cpaths, Options{Intel: intel.Snapshot(), CrownJewel: jf, Now: calNow})...)
	for _, r := range ranked {
		e := Explain(r)
		prod := e.Base
		for _, f := range e.Factors {
			prod *= f.Multiplier
		}
		if math.Abs(prod-r.Score) > 0.01 {
			t.Errorf("%s: base × factors = %.4f, score %.1f; %+v", r.Finding.ID, prod, r.Score, e.Factors)
		}
		if e.Score != r.Score || e.Version != ScoreVersion {
			t.Errorf("%s: explanation score/version %v %q", r.Finding.ID, e.Score, e.Version)
		}
		if len(e.TopPaths) > 3 {
			t.Errorf("%s: %d top paths", r.Finding.ID, len(e.TopPaths))
		}
		for _, f := range e.Factors {
			if f.Status == StatusNotScored && f.Multiplier != 1 {
				t.Errorf("%s: not-scored factor %s has multiplier %v", r.Finding.ID, f.Name, f.Multiplier)
			}
			if f.Reason == "" {
				t.Errorf("%s: factor %s has no reason", r.Finding.ID, f.Name)
			}
		}
	}
}

func TestExplainListsMissingInputs(t *testing.T) {
	f := model.Finding{ID: "bare", Status: model.Fail, Severity: model.High, CanonicalID: "X", Resource: model.Resource{ID: "nowhere", Type: "aws_s3_bucket"}, FirstSeen: time.Now().Add(-72 * time.Hour)}
	r := PrioritizeWith([]model.Finding{f}, nil, nil, Options{Now: time.Now()})[0]
	e := Explain(r)
	want := []string{"exposure", "data_sensitivity", "criticality", "exploitability", "off_path"}
	for _, w := range want {
		found := false
		for _, m := range e.Missing {
			if strings.HasPrefix(m, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("Missing lacks %q: %v", w, e.Missing)
		}
		for _, fac := range e.Factors {
			if fac.Name == w && fac.Status != StatusNotScored {
				t.Errorf("factor %s should be not scored: %+v", w, fac)
			}
		}
	}
	if r.Score != 5.5 || r.Band != "Medium" { // 5.5 HIGH; orphaned ×1.0 since 2.1.0; everything else not scored
		t.Errorf("bare HIGH with nothing known should be 5.5 Medium, got %.1f %s", r.Score, r.Band)
	}
	// once the inputs exist they are scored and leave Missing
	g := graph.New()
	g.AddNode(&graph.Node{ID: "nowhere", Type: "aws_s3_bucket", Criticality: "production", Attributes: map[string]any{"exposure": "wide", "dspm_labels": []any{"PII"}}})
	f.CheckID = "CVE-2021-44228"
	r = PrioritizeWith([]model.Finding{f}, g, nil, Options{Intel: intel.Snapshot(), Now: time.Now()})[0]
	if m := Explain(r).Missing; len(m) != 0 {
		t.Errorf("all inputs present, Missing should be empty: %v", m)
	}
}

func TestExplainTopPaths(t *testing.T) {
	f := model.Finding{ID: "a", Status: model.Fail, Severity: model.High, Resource: model.Resource{ID: "a"}}
	var paths []model.AttackPath
	for i, s := range []float64{5, 9.5, 7, 8, 6} {
		paths = append(paths, model.AttackPath{ID: string(rune('p' + i)), Name: "n", Score: s, FindingIDs: []string{"a"}})
	}
	r := PrioritizeWith([]model.Finding{f}, nil, paths, Options{Now: time.Now()})[0]
	e := Explain(r)
	if len(e.TopPaths) != 3 || e.TopPaths[0].Score != 9.5 || e.TopPaths[2].Score != 7 {
		t.Errorf("top paths: %+v", e.TopPaths)
	}
	if r.AttackPaths != 5 || r.MaxPathScore != 9.5 {
		t.Errorf("path counts: %d %.1f", r.AttackPaths, r.MaxPathScore)
	}
}

func TestCapIsExplained(t *testing.T) {
	_, ranked := rankCalibration(t)
	sawOffPathCap := false
	for _, r := range ranked {
		var off *Factor
		for i, f := range r.Explanation.Factors {
			if f.Name == "off_path" {
				off = &r.Explanation.Factors[i]
			}
		}
		if off == nil {
			t.Errorf("%s: no off_path factor in %+v", r.Finding.ID, r.Explanation.Factors)
			continue
		}
		if off.Multiplier != 1 { // capped off-path finding: Medium at most, cap explained
			if r.Score > 6.9 {
				t.Errorf("%s: off-path finding scored %.1f > 6.9", r.Finding.ID, r.Score)
			}
			if off.Reason != "no attack path reaches an impact target from this resource" {
				t.Errorf("%s: off_path reason %q", r.Finding.ID, off.Reason)
			}
			if r.Explanation.Raw > 6.9 {
				sawOffPathCap = true
				last := r.Explanation.Factors[len(r.Explanation.Factors)-1]
				if last.Name != "off_path_cap" || r.Score != 6.9 {
					t.Errorf("%s: raw %.2f off path should end with an off_path_cap factor at 6.9, got %+v (score %.1f)", r.Finding.ID, r.Explanation.Raw, last, r.Score)
				}
			}
			continue
		}
		// 2.2.0: no flat cap; a raw product above the knee is explained by the combination factor
		// (optionally followed by rounding), and the score stays below 10 until raw ≈ 25.
		if r.Explanation.Raw > DefaultWeights.CombineKnee {
			if factorNamed(r, "combination") == nil || factorNamed(r, "cap") != nil {
				t.Errorf("%s: raw %.2f should carry a combination factor and no cap: %+v", r.Finding.ID, r.Explanation.Raw, r.Explanation.Factors)
			}
			if want := math.Round(combine(r.Explanation.Raw, DefaultWeights)*10) / 10; r.Score != want {
				t.Errorf("%s: raw %.2f scored %.1f, combination gives %.1f", r.Finding.ID, r.Explanation.Raw, r.Score, want)
			}
		}
	}
	if !sawOffPathCap {
		t.Error("calibration set has no off-path finding whose raw score exceeds the 6.9 ceiling")
	}
}
