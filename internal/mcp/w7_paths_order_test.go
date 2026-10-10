package mcp

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Verification 7 defect 12: MCP `paths` broke score ties by Issue id; every other surface lists
// path Issues in the store's order (score, then the store's tie order). MCP now uses it too.
func TestPathsToolUsesTheStoreOrder(t *testing.T) {
	fx := newFixture(t)
	stored, _ := fx.st.Issues(store.IssueFilter{Kind: model.IssuePath})
	pos := map[string]int{}
	for i, is := range stored {
		pos[is.ID] = i
	}
	c := startServer(t, fx.st, Options{Traversal: labTraversal, NoRedact: true})
	c.initialize()
	out := c.toolOK("paths", map[string]any{"limit": 200})
	rows, _ := out["issues"].([]any)
	last := -1
	ties := 0
	var prevScore float64 = 11
	for _, r := range rows {
		m := r.(map[string]any)
		id, _ := m["issue_id"].(string)
		p, ok := pos[id]
		if !ok {
			continue
		}
		if sc := m["score"].(float64); sc == prevScore {
			ties++
		} else {
			prevScore = sc
		}
		if p < last {
			t.Errorf("Issue %s (store position %d) listed after position %d", id, p, last)
		}
		last = p
	}
	if ties == 0 {
		t.Log("fixture has no score tie; order still checked against the store")
	}
}
