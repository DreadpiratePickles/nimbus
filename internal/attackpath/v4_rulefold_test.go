package attackpath_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Delta r2 #2: a rule chain that shares entry + anchor with a traversal path (the same path
// Issue modulo rule) is folded into the traversal Issue as an also_matches_rule tag instead of
// a second Issue at another score. vendor-access 8.0 (traversal) vs 5.0 (CROSS_ACCOUNT_PIVOT)
// becomes one Issue; rule chains with no traversal counterpart stay.
func TestV4RuleChainsFoldIntoTraversalIssues(t *testing.T) {
	r := v4Lab(t)
	const vendor = "arn:aws:iam::111111111111:role/nimbus-lab-vendor-access"
	var rule, trav []model.AttackPath
	ruleMatch := map[string]bool{} // W6-ENGINE: rule-match path Issues are separate by design
	for _, p := range r.an.Paths {
		if attackpath.IsRuleMatch(p) {
			ruleMatch[p.RuleID] = true
			continue
		}
		if p.RuleID == "GRAPH_TRAVERSAL" {
			trav = append(trav, p)
		} else {
			rule = append(rule, p)
		}
	}
	for _, p := range rule {
		e, a, _ := model.PathIssueKey(p)
		if a == vendor || e == vendor {
			t.Errorf("vendor-access rule chain %s (%.2f) still a separate path", p.RuleID, p.Score)
		}
	}
	var tagged []string
	for _, p := range trav {
		if rs := attackpath.AlsoMatchesRules(p); len(rs) > 0 {
			tagged = append(tagged, p.Name+" ← "+strings.Join(rs, ","))
		}
	}
	vendorTagged := false
	for _, p := range trav {
		if p.Steps[len(p.Steps)-1].Resource == vendor {
			for _, x := range attackpath.AlsoMatchesRules(p) {
				if x == "CROSS_ACCOUNT_PIVOT" {
					vendorTagged = true
				}
			}
		}
	}
	if !vendorTagged {
		t.Errorf("vendor-access traversal path does not carry also_matches_rule CROSS_ACCOUNT_PIVOT; tagged: %v", tagged)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "f.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.RebuildPathIssues("s", r.an, time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	iss, _ := st.Issues(store.IssueFilter{Kind: model.IssuePath})
	nRule := 0
	for _, is := range iss {
		if ruleMatch[is.RuleID] {
			continue
		}
		if is.RuleID != model.PathRuleTraversal {
			nRule++
			t.Logf("remaining rule-chain Issue %s %s %.2f", is.RuleID, is.AnchorID, is.Score)
		}
		if is.AnchorID == vendor && is.RuleID != model.PathRuleTraversal {
			t.Errorf("vendor-access rule-chain Issue %s %.2f still stored", is.RuleID, is.Score)
		}
	}
	t.Logf("path Issues %d (rule-chain %d); rule chains %d; folded tags: %v", len(iss), nRule, len(rule), tagged)
	if nRule > 1 {
		t.Errorf("%d rule-chain Issues remain (want only chains with no traversal counterpart)", nRule)
	}
}
