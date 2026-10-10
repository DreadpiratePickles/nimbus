package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W5-ISSUES item C6 (Verification 5): a rule chain folded into a traversal path must not lower the
// Issue's score. The engine (attackpath.FoldRuleChains, W5-ENGINE) now reports the highest member
// score; the store independently takes the max score / band over every path of an Issue it
// receives, whatever their order.

func foldPair() (trav, chain model.AttackPath) {
	trav = syntheticPath("sg-1", 4.0)
	trav.ID, trav.Severity = "p-trav", model.Medium
	chain = syntheticPath("sg-1", 9.5)
	chain.ID, chain.RuleID, chain.Severity = "p-chain", "PUBLIC_ADMIN_CHAIN", model.Critical
	return trav, chain
}

func TestFoldedRuleChainKeepsHigherScoreThroughStore(t *testing.T) {
	trav, chain := foldPair()
	folded := attackpath.FoldRuleChains([]model.AttackPath{trav, chain})
	if len(folded) != 1 || folded[0].Score != 9.5 {
		t.Fatalf("engine fold: %d paths, score %v, want 1 at 9.5", len(folded), folded)
	}
	st := openTemp(t)
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: folded}, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if is := onlyPathIssue(t, st); is.Score != 9.5 || is.Band != "Critical" || is.Severity != model.Critical {
		t.Fatalf("folded Issue %.1f %s %s, want 9.5 Critical", is.Score, is.Band, is.Severity)
	}
}

func TestPathIssueTakesMaxScoreOverMembersInAnyOrder(t *testing.T) {
	lo := syntheticPath("sg-1", 4.0)
	lo.ID, lo.Severity = "p-lo", model.Medium
	hi := syntheticPath("i-direct", 9.5)
	hi.ID = "p-hi"
	for _, order := range [][]model.AttackPath{{lo, hi}, {hi, lo}} {
		st := openTemp(t)
		if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: order}, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		is := onlyPathIssue(t, st)
		if is.Score != 9.5 || is.Band != "Critical" || is.SecondaryKey != st.PathSecondaryKeyOf(hi) || len(is.SecondaryKeys) != 2 {
			t.Fatalf("order %s first: %.1f %s best %s, want 9.5 Critical best p-hi", order[0].ID, is.Score, is.Band, is.SecondaryKey)
		}
	}
}
