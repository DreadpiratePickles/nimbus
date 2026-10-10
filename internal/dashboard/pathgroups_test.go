package dashboard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// payloadOf decodes the page's embedded JSON payload.
func payloadOf(t *testing.T, html []byte) map[string]json.RawMessage {
	t.Helper()
	const open = `<script id="data" type="application/json">`
	s := string(html)
	i := strings.Index(s, open)
	if i < 0 {
		t.Fatal("no data block")
	}
	s = s[i+len(open):]
	s = s[:strings.Index(s, "</script>")]
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return m
}

func groupedPaths() []model.AttackPath {
	steps := func(ids ...string) []model.Step {
		var out []model.Step
		for i, id := range ids {
			out = append(out, model.Step{Stage: i + 1, Resource: id})
		}
		return out
	}
	return []model.AttackPath{
		{ID: "pii-a", Name: "pii via sg", Score: 10, Severity: model.Critical, Steps: steps("sg-1", "i-1", "s3-pii")},
		{ID: "pii-b", Name: "pii via ec2", Score: 7, Severity: model.High, Steps: steps("i-1", "s3-pii")},
		{ID: "db", Name: "db", Score: 5.2, Severity: model.Medium, Steps: steps("i-2", "rds-1")},
	}
}

// Shortfall #11 / r2 #7: the dashboard reads Analysis.Grouped() — one path Issue row per
// group with its variants, the same score and band as `paths`.
func TestRenderEmbedsPathGroups(t *testing.T) {
	ps := groupedPaths()
	html, err := Render(Data{Paths: ps, Analysis: &attackpath.Analysis{Paths: ps}})
	if err != nil {
		t.Fatal(err)
	}
	var groups []PathGroupRow
	if err := json.Unmarshal(payloadOf(t, html)["path_groups"], &groups); err != nil {
		t.Fatalf("path_groups: %v", err)
	}
	want := attackpath.GroupPaths(ps)
	if len(groups) != len(want) || len(groups) != 2 {
		t.Fatalf("path_groups = %d rows, want %d", len(groups), len(want))
	}
	g := groups[0]
	if g.IssueID != want[0].IssueID || g.BestID != "pii-a" || g.Variants != 1 || g.Score != 10 || g.Band != "Critical" ||
		g.Severity != model.Critical || strings.Join(g.PathIDs, ",") != "pii-a,pii-b" {
		t.Errorf("group 0 = %+v", g)
	}
	if groups[1].Variants != 0 || groups[1].Band != "Medium" {
		t.Errorf("group 1 = %+v", groups[1])
	}
}

// Without an analysis (convert, older callers) the groups come from Data.Paths; with no paths
// the field is an empty array, never null.
func TestRenderPathGroupsFallbackAndEmpty(t *testing.T) {
	html, err := Render(Data{Paths: groupedPaths()})
	if err != nil {
		t.Fatal(err)
	}
	var groups []PathGroupRow
	json.Unmarshal(payloadOf(t, html)["path_groups"], &groups)
	if len(groups) != 2 {
		t.Errorf("fallback path_groups = %d, want 2", len(groups))
	}
	if got := string(payloadOf(t, renderEmptyBytes(t))["path_groups"]); got != "[]" {
		t.Errorf("empty path_groups = %s, want []", got)
	}
}

func renderEmptyBytes(t *testing.T) []byte {
	t.Helper()
	b, err := Render(Data{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The paths view lists path_groups (one row per Issue, "+N" variants), draws the selected
// Issue's path only, and keeps the full fan behind an explicit toggle.
func TestPathsViewReadsGroups(t *testing.T) {
	for _, want := range []string{"D.path_groups", "data-variants", "data-toggle", "'fan'", "show all paths", "attack path Issue"} {
		if !strings.Contains(clientsJS, want) {
			t.Errorf("clients.js lacks %s", want)
		}
	}
}
