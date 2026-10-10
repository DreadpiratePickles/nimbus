package cli

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W7-POLISH item 13 (r5 #10 hand-off from W7-ENGINE): inferred path-rule matches
// (attackpath.PotentialEscalations) are shown as "potential escalation" annotations on the
// principal's finding Issue page (`issues show`), never as path Issues.
func TestIssueShowListsPotentialEscalationsOnLab(t *testing.T) {
	cfg := w6IngestLab(t)
	st := openTestStore(t)
	g, err := loadGraph(st)
	if err != nil {
		t.Fatal(err)
	}
	pot := attackpath.PotentialEscalations(g, nil)
	all, _ := st.Issues(store.IssueFilter{OpenOnly: true})
	var target model.Issue
	var ms []attackpath.PathRuleMatch
	for _, is := range all {
		if is.Kind != model.IssuePath && len(pot[is.ResourceID]) > 0 {
			target, ms = is, pot[is.ResourceID]
			break
		}
	}
	if target.ID == "" {
		t.Fatalf("lab: no finding Issue on a principal with an inferred match (anchors %d)", len(pot))
	}
	out := run(t, "-c", cfg, "issues", "show", target.ID)
	if !strings.Contains(out, "Potential escalation") {
		t.Fatalf("issues show %s lacks the potential escalation block:\n%s", target.ID, out)
	}
	for _, m := range ms {
		if !strings.Contains(out, m.RuleID) {
			t.Errorf("potential escalation %s (→ %s) not listed:\n%s", m.RuleID, m.Target, out)
		}
	}
	if !strings.Contains(out, "inferred") || !strings.Contains(out, "not a path Issue") {
		t.Errorf("the block must say the match is inferred and not a path Issue:\n%s", out)
	}
	// A finding Issue with no inferred match prints no block.
	for _, is := range all {
		if is.Kind != model.IssuePath && len(pot[is.ResourceID]) == 0 {
			if o := run(t, "-c", cfg, "issues", "show", is.ID); strings.Contains(o, "Potential escalation") {
				t.Errorf("Issue %s has no inferred match but shows the block", is.ID)
			}
			break
		}
	}
}
