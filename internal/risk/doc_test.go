package risk

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestWeightsDocumented fails when the published table in docs/scoring.md drifts from DefaultWeights.
func TestWeightsDocumented(t *testing.T) {
	fh, err := os.Open("../../docs/scoring.md")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	doc := map[string]float64{}
	in := false
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.Contains(line, "<!-- weights:begin -->"):
			in = true
		case strings.Contains(line, "<!-- weights:end -->"):
			in = false
		case in && strings.HasPrefix(line, "| `"):
			cells := strings.Split(line, "|")
			key := strings.Trim(strings.TrimSpace(cells[1]), "`")
			v, err := strconv.ParseFloat(strings.TrimPrefix(strings.TrimSpace(cells[3]), "×"), 64)
			if err != nil {
				t.Fatalf("docs/scoring.md row %q: value %q: %v", key, cells[3], err)
			}
			doc[key] = v
		}
	}
	code := map[string]float64{}
	for _, row := range DefaultWeights.Table() {
		code[row.Key] = row.Value
	}
	if len(code) == 0 || !reflect.DeepEqual(doc, code) {
		for k, v := range code {
			if dv, ok := doc[k]; !ok || dv != v {
				t.Errorf("weight %s: code %v, docs/scoring.md %v (present=%v)", k, v, dv, ok)
			}
		}
		for k := range doc {
			if _, ok := code[k]; !ok {
				t.Errorf("docs/scoring.md documents %s which is not in DefaultWeights", k)
			}
		}
	}
	data, _ := os.ReadFile("../../docs/scoring.md")
	if !strings.Contains(string(data), "### "+ScoreVersion) {
		t.Errorf("docs/scoring.md changelog has no entry for score_version %s", ScoreVersion)
	}
}

// TestPythonScoreVersionMirror keeps python/nimbus/risk_weights.json pointing at the Go version.
func TestPythonScoreVersionMirror(t *testing.T) {
	data, err := os.ReadFile("../../python/nimbus/risk_weights.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ScoreVersion string `json:"score_version"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.ScoreVersion != ScoreVersion {
		t.Errorf("python/nimbus/risk_weights.json score_version %q, Go %q (%v)", doc.ScoreVersion, ScoreVersion, err)
	}
}
