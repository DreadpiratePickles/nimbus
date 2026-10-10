package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// GET /api/attack-paths/issues: one row per path Issue (attackpath.GroupPaths over the stored
// paths), the same grouping the `paths` CLI and the dashboard list.
func TestAPIAttackPathIssues(t *testing.T) {
	s := newTestServer(t)
	st := func(ids ...string) []model.Step {
		var out []model.Step
		for _, id := range ids {
			out = append(out, model.Step{Resource: id})
		}
		return out
	}
	paths := []model.AttackPath{
		{ID: "a", Score: 10, Severity: model.Critical, Steps: st("sg", "i", "pii")},
		{ID: "b", Score: 7, Severity: model.High, Steps: st("i", "pii")},
		{ID: "c", Score: 4, Severity: model.Low, Steps: st("j", "db")},
	}
	if err := s.st.ReplaceAttackPaths("s", paths); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/attack-paths/issues")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got []attackpath.PathGroup
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Variants != 1 || got[0].Best.ID != "a" || got[0].Band != "Critical" || got[1].Variants != 0 {
		t.Errorf("groups = %+v", got)
	}
	// empty store: [] not null
	s2 := newTestServer(t)
	ts2 := httptest.NewServer(s2.Handler())
	defer ts2.Close()
	r2, _ := http.Get(ts2.URL + "/api/attack-paths/issues")
	var raw json.RawMessage
	json.NewDecoder(r2.Body).Decode(&raw)
	r2.Body.Close()
	if string(raw) != "[]" {
		t.Errorf("empty = %s, want []", raw)
	}
}
