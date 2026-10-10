package cli

import (
	"context"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Coordinator item 13 (r5 #10, ui-smoke check 28): the Issue page the API / dashboard serve
// carries potential_escalations for finding Issues — the inferred path-rule matches anchored on
// the Issue's principal, the same list `issues show` prints — and none for path Issues.
func TestIssuePageCarriesPotentialEscalations(t *testing.T) {
	labDB(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	st := openTestStore(t)
	o, err := issuePageOptions(context.Background(), cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := server.BuildIssuePages(st, o)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := loadGraph(st)
	with := 0
	all, _ := st.Issues(store.IssueFilter{})
	for _, is := range all {
		pg := pages[is.ID]
		want := potentialEscalationsFor(cfg, g, is)
		if is.Kind == model.IssuePath {
			if len(pg.PotentialEscalations) != 0 {
				t.Errorf("path Issue %s carries potential escalations", is.ID)
			}
			continue
		}
		if len(pg.PotentialEscalations) != len(want) {
			t.Errorf("Issue %s: page has %d potential escalations, issues show has %d", is.ID, len(pg.PotentialEscalations), len(want))
		}
		if len(want) > 0 {
			with++
			if pg.PotentialEscalations[0].Confidence != string(model.ConfidenceInferred) {
				t.Errorf("a potential escalation must be inferred: %+v", pg.PotentialEscalations[0])
			}
		}
	}
	if with == 0 {
		t.Fatal("the lab has inferred matches (SSM, Instance Connect, PutRolePolicy); no finding Issue page carries one")
	}
}
