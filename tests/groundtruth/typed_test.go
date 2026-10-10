package groundtruth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Track B3 item 1: the committed lab output (what `make lab-local` writes and what TestGroundTruth
// ingests) carries every estate relationship in the typed native form
// {"id", "kind", "attr": {"via"}} (docs/benchmark.md "Native relationship contract"), and no
// longer smuggles the typed list through attributes.lab_relationships.
func TestLabEmitsTypedRelationships(t *testing.T) {
	e := loadEstate(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "lab", "local", "out", "estate.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []struct {
		Resource struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
			Related    []any          `json:"related"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatal(err)
	}
	byRes := map[string][][]any{}
	for _, r := range recs {
		if _, ok := r.Resource.Attributes["lab_relationships"]; ok {
			t.Errorf("%s: attributes.lab_relationships is still emitted", r.Resource.ID)
		}
		byRes[r.Resource.ID] = append(byRes[r.Resource.ID], r.Resource.Related)
	}
	typed := 0
	for _, res := range e.Resources {
		for _, related := range byRes[res.ID] {
			if len(related) != len(res.Relationships) {
				t.Errorf("%s: %d related entries, estate declares %d", res.ID, len(related), len(res.Relationships))
				continue
			}
			for i, rel := range res.Relationships {
				m, ok := related[i].(map[string]any)
				if !ok {
					t.Errorf("%s related[%d] = %v: want a typed object {id, kind, attr}", res.ID, i, related[i])
					continue
				}
				typed++
				if m["id"] != rel.To || m["kind"] != rel.Kind {
					t.Errorf("%s related[%d] = %v, want id %q kind %q", res.ID, i, m, rel.To, rel.Kind)
				}
				attr, hasAttr := m["attr"].(map[string]any)
				switch {
				case rel.Via == "" && hasAttr:
					t.Errorf("%s related[%d]: attr %v emitted although the estate has no via", res.ID, i, attr)
				case rel.Via != "" && (!hasAttr || attr["via"] != rel.Via):
					t.Errorf("%s related[%d]: attr.via = %v, want %q", res.ID, i, attr["via"], rel.Via)
				}
			}
		}
	}
	if typed == 0 {
		t.Error("no typed relationship found in the lab output")
	}
}
