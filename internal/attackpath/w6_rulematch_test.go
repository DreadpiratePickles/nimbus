package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-ENGINE item 1 (competitive delta r4 #7): path rules reach the product. A verified rule
// match on an entry-reachable impact target is a path Issue whose rule component is the rule id,
// tagged rule_match; inferred matches stay dry-run only. Bar: Prowler's AWS attack-path queries
// feed its findings; Sysdig risk definitions produce Issues.

const ec2RuleID = "aws-ec2-privesc-passrole-iam"

func TestRiskTestAcceptsLibraryID(t *testing.T) {
	r, err := LoadPathRuleFile(ec2RuleID)
	if err != nil {
		t.Fatalf("LoadPathRuleFile(%q): %v", ec2RuleID, err)
	}
	if r.ID != ec2RuleID || !strings.HasPrefix(r.Source, "builtin:") {
		t.Fatalf("got id %q source %q, want the embedded rule with a builtin: source", r.ID, r.Source)
	}
	if _, err := LoadPathRuleFile("no-such-rule-id"); err == nil || !strings.Contains(err.Error(), "no such file or library rule") {
		t.Fatalf("unknown id: want a 'no such file or library rule' error, got %v", err)
	}
}

func TestLibraryHasAtLeast36Rules(t *testing.T) {
	rules, err := LibraryPathRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 36 {
		t.Fatalf("library has %d rules, want >= 36", len(rules))
	}
}

func ruleMatchPaths(paths []model.AttackPath) []model.AttackPath {
	var out []model.AttackPath
	for _, p := range paths {
		if IsRuleMatch(p) {
			out = append(out, p)
		}
	}
	return out
}

// W7-ENGINE (r5 #3): the verified dev-sam PassRole match has the same hops as the traversal
// path "credential compromise of nimbus-lab-dev-sam → nimbus-lab-ec2-admin-role": it folds into
// that path Issue as an also_matches_rule tag (rule id, confidence, because, credit) and is never
// a second Issue. W6 made it a separate rule-match Issue (lab headline 20 path Issues / 23 hop
// variants, `plan` step 1 "resolves 2", groundtruth matched P13 twice).
func TestVerifiedRuleMatchFoldsIntoTraversalIssueOnTheLab(t *testing.T) {
	gt := groundTruth(t)
	g, _ := labGraph(t, false)
	an := Traverse(g, labOptions())
	if rps := ruleMatchPaths(an.Paths); len(rps) != 0 {
		for _, p := range rps {
			t.Logf("rule path %s %.2f %s", p.RuleID, p.Score, stepKey(pathEntry(p), p.Steps))
		}
		t.Fatalf("%d separate rule-match paths, want 0 (the P13 match folds into its traversal twin)", len(rps))
	}
	var carrier *model.AttackPath
	for i, p := range an.Paths {
		for _, r := range AlsoMatchesRules(p) {
			if r == ec2RuleID {
				if carrier != nil {
					t.Fatalf("two paths carry %s: %s and %s", ec2RuleID, carrier.ID, p.ID)
				}
				carrier = &an.Paths[i]
			}
		}
	}
	if carrier == nil {
		t.Fatalf("no traversal path carries also_matches_rule %s", ec2RuleID)
	}
	if !isTraversal(*carrier) || !gtMatch(gt["P13"], *carrier) || carrier.Score < 7 {
		t.Errorf("carrier is not the P13 traversal path at >= 7: %s %.2f %s", carrier.RuleID, carrier.Score, stepKey(pathEntry(*carrier), carrier.Steps))
	}
	last := carrier.Steps[len(carrier.Steps)-1]
	pm := PathRuleMatchesOf(*carrier)
	if len(pm) != 1 || pm[0].RuleID != ec2RuleID || pm[0].Confidence != "verified" || pm[0].Credit == nil || pm[0].Credit.Source != "Prowler" {
		t.Errorf("carrier path_rule_matches = %+v, want the verified %s match with its Prowler credit", pm, ec2RuleID)
	}
	if !strings.Contains(last.Because, "Prowler") || !strings.Contains(last.Because, ec2RuleID) {
		t.Errorf("because should name the rule and credit its source: %q", last.Because)
	}
	if _, ok := last.Evidence[AttrRuleMatch]; ok {
		t.Errorf("a folded match must not mark the carrier as a rule-match path: %v", last.Evidence)
	}
	if len(an.RuleMatches) != 1 || an.RuleMatches[0].PathID != carrier.ID || !an.RuleMatches[0].Folded {
		t.Errorf("Analysis.RuleMatches = %+v, want the one verified match folded into %s", an.RuleMatches, carrier.ID)
	}
	// One Issue: no other path shares the carrier's hop list.
	for _, p := range an.Paths {
		if p.ID != carrier.ID && stepKey(pathEntry(p), p.Steps) == stepKey(pathEntry(*carrier), carrier.Steps) {
			t.Errorf("path %s (%s) duplicates the carrier's hops", p.ID, p.RuleID)
		}
	}
	// Merge (rule chains + traversal) keeps the tag.
	kept := false
	for _, p := range Merge(an.Paths, nil) {
		for _, r := range AlsoMatchesRules(p) {
			kept = kept || r == ec2RuleID
		}
	}
	if !kept {
		t.Errorf("Merge dropped the also_matches_rule tag")
	}
	// Exactly one fix lists the carrier as broken by the PassRole fix, and it breaks one path
	// (not the two of W6).
	for _, fx := range an.BreakFixes {
		if fx.Edge != nil && fx.Edge.To == carrier.Steps[len(carrier.Steps)-1].Resource && strings.Contains(fx.Edge.From, "dev-sam") {
			if len(fx.Breaks) != 1 || fx.Breaks[0] != carrier.ID {
				t.Errorf("PassRole fix breaks %v, want only %s", fx.Breaks, carrier.ID)
			}
		}
	}
}

func TestPathRuleMatchCounts(t *testing.T) {
	g, _ := labGraph(t, false)
	rules, err := LibraryPathRules()
	if err != nil {
		t.Fatal(err)
	}
	counts := PathRuleMatchCounts(g, rules)
	if c := counts[ec2RuleID]; c.Total != 1 || c.Verified != 1 {
		t.Errorf("%s counts %+v, want 1 total / 1 verified", ec2RuleID, c)
	}
	if c := counts["aws-iam-privesc-put-role-policy"]; c.Total != 1 || c.Verified != 0 {
		t.Errorf("put-role-policy counts %+v, want 1 total / 0 verified", c)
	}
	if len(counts) != len(rules) {
		t.Errorf("counts cover %d rules, want all %d (zeros included)", len(counts), len(rules))
	}
}
