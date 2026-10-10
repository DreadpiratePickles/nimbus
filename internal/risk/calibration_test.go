package risk

import (
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/intel"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

type calScenario struct {
	ID              string              `yaml:"id"`
	Severity        string              `yaml:"severity"`
	CanonicalID     string              `yaml:"canonical_id"`
	Weaknesses      []string            `yaml:"weaknesses"`
	Compliance      map[string][]string `yaml:"compliance"`
	CVEs            []string            `yaml:"cves"`
	Type            string              `yaml:"type"`
	Exposure        string              `yaml:"exposure"`
	Sensitive       bool                `yaml:"sensitive"`
	Labels          []string            `yaml:"labels"`
	Criticality     string              `yaml:"criticality"`
	Owner           string              `yaml:"owner"`
	ModifiedHrsAgo  float64             `yaml:"modified_hours_ago"`
	FirstSeenHrsAgo float64             `yaml:"first_seen_hours_ago"`
	Jewel           string              `yaml:"jewel"`
	RunsAsAdmin     bool                `yaml:"runs_as_admin"`
	PathScore       float64             `yaml:"path_score"`
	SCPDenied       bool                `yaml:"scp_denied"`
	NoNode          bool                `yaml:"no_node"`
	Analysis        string              `yaml:"analysis"` // "" / "present": path analysis ran; "none": findings-only
	Tags            map[string]string   `yaml:"tags"`
	Band            string              `yaml:"band"`
	Score           *float64            `yaml:"score"`
}

type calibration struct {
	Scenarios []calScenario `yaml:"scenarios"`
	Order     [][]string    `yaml:"order"`
}

var calNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// buildCalibration turns the YAML scenarios into findings, one graph, paths and a jewel lookup.
func buildCalibration(t *testing.T) (calibration, []model.Finding, *graph.Graph, []model.AttackPath, JewelFunc) {
	t.Helper()
	data, err := os.ReadFile("testdata/calibration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cal calibration
	if err := yaml.Unmarshal(data, &cal); err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	var fs []model.Finding
	var paths []model.AttackPath
	jewels := map[string]string{}
	for _, s := range cal.Scenarios {
		first := 72.0
		if s.FirstSeenHrsAgo > 0 {
			first = s.FirstSeenHrsAgo
		}
		f := model.Finding{ID: s.ID, Source: "calibration", CheckID: s.CanonicalID, CanonicalID: s.CanonicalID, Severity: model.ParseSeverity(s.Severity),
			Status: model.Fail, Provider: "aws", Account: "111111111111", Weaknesses: s.Weaknesses, Compliance: s.Compliance,
			Resource: model.Resource{ID: s.ID, Type: s.Type, Name: s.ID}, FirstSeen: calNow.Add(-time.Duration(first * float64(time.Hour)))}
		if len(s.CVEs) > 0 {
			f.CheckID = s.CVEs[0]
			cves := make([]any, len(s.CVEs))
			for i, c := range s.CVEs {
				cves[i] = c
			}
			f.Resource.Attributes = map[string]any{"cves": cves}
		}
		if s.Owner != "" && s.NoNode {
			f.Resource.Attributes = map[string]any{"tags": map[string]any{"owner": s.Owner}}
		}
		fs = append(fs, f)
		if s.NoNode {
			continue
		}
		n := &graph.Node{ID: s.ID, Type: s.Type, Name: s.ID, Provider: "aws", Account: "111111111111", Attributes: map[string]any{},
			Sensitive: s.Sensitive, Criticality: s.Criticality, Owner: s.Owner, Weaknesses: s.Weaknesses}
		if s.Exposure != "" {
			n.Attributes["exposure"] = s.Exposure
		}
		if len(s.Labels) > 0 {
			l := make([]any, len(s.Labels))
			for i, x := range s.Labels {
				l[i] = x
			}
			n.Attributes["dspm_labels"] = l
		}
		if s.ModifiedHrsAgo > 0 {
			n.ModifiedAt = calNow.Add(-time.Duration(s.ModifiedHrsAgo * float64(time.Hour))).Format(time.RFC3339)
		}
		if s.SCPDenied {
			n.Attributes["scp_denied"] = true
		}
		if len(s.Tags) > 0 {
			tags := map[string]any{}
			for k, v := range s.Tags {
				tags[k] = v
			}
			n.Attributes["tags"] = tags
		}
		g.AddNode(n)
		if s.Exposure == "wide" || s.Exposure == "narrow" || s.Exposure == "trusted" {
			g.AddEdge(graph.InternetNodeID, s.ID, graph.EdgeAllowsTrafficTo, map[string]any{"exposure": s.Exposure})
		}
		if s.RunsAsAdmin {
			role := s.ID + "-role"
			g.AddNode(&graph.Node{ID: role, Type: "aws_iam_role", Name: role, Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
			g.AddEdge(s.ID, role, graph.EdgeRunsAs, nil)
		}
		if s.Jewel != "" {
			jewels[s.ID] = s.Jewel
		}
		if s.PathScore > 0 {
			paths = append(paths, model.AttackPath{ID: "path-" + s.ID, Name: "path through " + s.ID, Score: s.PathScore, FindingIDs: []string{s.ID}})
		}
	}
	jf := func(n *graph.Node) (string, string, bool) {
		if n == nil {
			return "", "", false
		}
		l, ok := jewels[n.ID]
		return l, "calibration rule for " + n.ID, ok
	}
	return cal, fs, g, paths, jf
}

// rankCalibration scores the scenarios in two runs over the same graph: those with
// `analysis: none` as findings-only input (Options.NoAnalysis: off_path not scored), the rest
// as if path analysis ran (the scenario paths are its complete paths). The merged list is
// sorted the way PrioritizeWith sorts.
func rankCalibration(t *testing.T) (calibration, []Ranked) {
	t.Helper()
	cal, fs, g, paths, jf := buildCalibration(t)
	none := map[string]bool{}
	for _, s := range cal.Scenarios {
		switch s.Analysis {
		case "", "present":
		case "none":
			none[s.ID] = true
		default:
			t.Fatalf("%s: analysis %q (want present|none)", s.ID, s.Analysis)
		}
	}
	var withA, withoutA []model.Finding
	for _, f := range fs {
		if none[f.ID] {
			withoutA = append(withoutA, f)
		} else {
			withA = append(withA, f)
		}
	}
	o := Options{Intel: intel.Snapshot(), CrownJewel: jf, Now: calNow}
	ranked := PrioritizeWith(withA, g, paths, o)
	o.NoAnalysis = true
	ranked = append(ranked, PrioritizeWith(withoutA, g, paths, o)...)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Explanation.Raw != b.Explanation.Raw {
			return a.Explanation.Raw > b.Explanation.Raw
		}
		return a.Finding.ID < b.Finding.ID
	})
	return cal, ranked
}

func TestCalibration(t *testing.T) {
	cal, ranked := rankCalibration(t)
	if len(cal.Scenarios) < 40 {
		t.Fatalf("calibration set must have >= 40 scenarios, has %d", len(cal.Scenarios))
	}
	pos := map[string]int{}
	byID := map[string]Ranked{}
	for i, r := range ranked {
		pos[r.Finding.ID] = i
		byID[r.Finding.ID] = r
	}
	for _, s := range cal.Scenarios {
		r, ok := byID[s.ID]
		if !ok {
			t.Errorf("%s: not ranked", s.ID)
			continue
		}
		if r.Band != s.Band {
			t.Errorf("%s: band %s (score %.1f), want %s; factors: %s", s.ID, r.Band, r.Score, s.Band, factorSummary(r))
		}
		if s.Score != nil && math.Abs(r.Score-*s.Score) > 1e-9 {
			t.Errorf("%s: score %.1f, want %.1f; factors: %s", s.ID, r.Score, *s.Score, factorSummary(r))
		}
		if r.ScoreVersion != ScoreVersion {
			t.Errorf("%s: score_version %q", s.ID, r.ScoreVersion)
		}
	}
	for _, chain := range cal.Order {
		for i := 0; i+1 < len(chain); i++ {
			a, b := chain[i], chain[i+1]
			if pos[a] >= pos[b] {
				t.Errorf("order: %s (%.1f) must rank above %s (%.1f)", a, byID[a].Score, b, byID[b].Score)
			}
		}
	}
}

func factorSummary(r Ranked) string {
	s := fmt.Sprintf("base %.2f", r.Explanation.Base)
	for _, f := range r.Explanation.Factors {
		if f.Multiplier != 1 {
			s += fmt.Sprintf(" × %s %.3f", f.Name, f.Multiplier)
		}
	}
	return s
}
