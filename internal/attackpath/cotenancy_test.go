package attackpath

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Item 2: rule chains need a real link (same resource, or a related/typed edge) between
// consecutive steps. A same_account join is allowed only when the stage declares
// allow_same_account with a justification; such paths are weak_link and score x0.5.
func TestRuleChainsRequireARealLink(t *testing.T) {
	rules, err := LoadRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := labFindings(t, false)
	paths := Evaluate(fs, rules)
	for _, p := range paths {
		for i, s := range p.Steps {
			if i == 0 {
				continue
			}
			if (s.Relation == "same_account" || s.Relation == "any") && !p.WeakLink {
				t.Errorf("%s joined by %s without weak_link: %s", p.RuleID, s.Relation, chainOf(p))
			}
		}
		// The lab's noise: public RDS / EKS / Lambda chained to an unrelated instance or admin.
		if p.RuleID == "INTERNET_TO_ACCOUNT_ADMIN" || p.RuleID == "PUBLIC_K8S_API_TAKEOVER" || p.RuleID == "STALE_KEY_ABUSE" {
			first, last := p.Steps[0].Resource, p.Steps[len(p.Steps)-1].Resource
			bad := strings.Contains(first, "db:nimbus-lab-orders") || strings.Contains(first, "function:nimbus-lab-export") ||
				strings.HasSuffix(last, "user/nimbus-lab-ops-jane") && p.RuleID != "STALE_KEY_ABUSE" || strings.HasSuffix(last, "role/nimbus-lab-vendor-access") ||
				p.RuleID == "STALE_KEY_ABUSE" && !strings.HasSuffix(last, "user/nimbus-lab-ops-jane")
			if bad {
				t.Errorf("co-tenancy chain still reported: %s %s", p.RuleID, chainOf(p))
			}
		}
	}
	// The seeded false positive (corp-tools instance) is no longer chained to other admins.
	n := 0
	for _, p := range paths {
		for _, s := range p.Steps {
			if strings.Contains(s.Resource, "i-0a1b2c3d4e5f60002") {
				n++
				break
			}
		}
	}
	if n > 1 {
		t.Errorf("F01 instance appears in %d rule chains, want at most its own one", n)
	}
	if len(paths) > 10 {
		for _, p := range paths {
			t.Logf("%.2f %s %s", p.Score, p.RuleID, chainOf(p))
		}
		t.Errorf("%d rule chains on the lab, want only linked ones (≤ 10)", len(paths))
	}
}

func chainOf(p model.AttackPath) string {
	var parts []string
	for _, s := range p.Steps {
		parts = append(parts, s.Resource+"("+s.Relation+")")
	}
	return strings.Join(parts, " > ")
}

func TestSameAccountNeedsJustification(t *testing.T) {
	bad := []string{
		"rules:\n  - id: X\n    stages:\n      - weakness: A\n      - weakness: B\n        relation: same_account\n",
		"rules:\n  - id: X\n    stages:\n      - weakness: A\n      - weakness: B\n        relation: related\n        fallback: any\n",
		"rules:\n  - id: X\n    stages:\n      - weakness: A\n      - weakness: B\n        relation: same_account\n        allow_same_account: true\n",
	}
	for _, y := range bad {
		if _, err := LoadRules([]byte(y)); err == nil {
			t.Errorf("want an error for:\n%s", y)
		}
	}
	ok := "rules:\n  - id: X\n    stages:\n      - weakness: A\n      - weakness: B\n        relation: related\n        fallback: same_account\n        allow_same_account: true\n        justification: account-wide control\n"
	rules, err := LoadRules([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	a := f("a", "A", "r1", "A")
	b := f("b", "B", "r2", "B")
	var custom Rule
	for _, r := range rules {
		if r.ID == "X" {
			custom = r
		}
	}
	paths := Evaluate([]model.Finding{a, b}, []Rule{custom})
	if len(paths) != 1 || !paths[0].WeakLink {
		t.Fatalf("justified same_account join should yield one weak_link path: %+v", paths)
	}
	// Same chain joined by a real edge scores twice as much.
	a2 := a
	a2.Resource.Related = []string{"r2"}
	linked := Evaluate([]model.Finding{a2, b}, []Rule{custom})
	if len(linked) != 1 || linked[0].WeakLink || linked[0].Score < 2*paths[0].Score-0.02 {
		t.Errorf("linked=%+v weak=%+v", linked, paths)
	}
	if !strings.Contains(paths[0].Steps[1].Because, "account-wide control") {
		t.Errorf("weak step should carry the rule's justification: %q", paths[0].Steps[1].Because)
	}
}
