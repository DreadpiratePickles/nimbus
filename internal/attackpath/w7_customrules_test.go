package attackpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W7-ENGINE item 2 (r5 #4; bar: Sysdig custom risk definitions become Issues with New badges).
// Customer rules load from directories, are validated with `risk test` semantics (schema + their
// own fixture tests) and a duplicate of a library id is refused; each refusal names its reason.

const customRuleFile = "testdata/custom_rules/acme-self-grant-billing-read.yaml"

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCustomPathRulesValidatesAndRejects(t *testing.T) {
	good, err := os.ReadFile(customRuleFile)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeRule(t, dir, "good.yaml", string(good))
	// Own tests fail: the near-miss expects no match on a target the rule does match.
	writeRule(t, dir, "failing.yaml", strings.NewReplacer("acme-self-grant-billing-read", "acme-failing", `id_like: ["arn:aws:s3:::*billing*"]`, `id_like: ["arn:aws:s3:::*"]`).Replace(string(good)))
	writeRule(t, dir, "typo.yaml", strings.Replace(string(good), "severity: HIGH", "severty: HIGH", 1))
	writeRule(t, dir, "dup.yaml", strings.Replace(string(good), "acme-self-grant-billing-read", ec2RuleID, 1))
	writeRule(t, dir, "notes.txt", "not a rule")

	rules, rejected := LoadCustomPathRules([]string{dir}, productRules())
	if len(rules) != 1 || rules[0].ID != "acme-self-grant-billing-read" || !IsCustomRule(rules[0]) {
		t.Fatalf("accepted %v, want only acme-self-grant-billing-read (custom)", ruleIDs(rules))
	}
	want := map[string]string{"failing.yaml": "own tests", "typo.yaml": "severty", "dup.yaml": "duplicate"}
	if len(rejected) != len(want) {
		t.Fatalf("rejected %+v, want %d", rejected, len(want))
	}
	for _, r := range rejected {
		w, ok := want[filepath.Base(r.File)]
		if !ok || !strings.Contains(r.Reason, w) {
			t.Errorf("rejection %s: %q, want a reason containing %q", r.File, r.Reason, w)
		}
	}
	if _, rej := LoadCustomPathRules([]string{filepath.Join(dir, "missing")}, nil); len(rej) != 1 {
		t.Errorf("a missing directory must be one rejection with its reason, got %+v", rej)
	}
}

func ruleIDs(rs []PathRule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// On the lab, the customer rule finds a chain traversal does not model: the internet-invocable
// Bedrock agent's role (P18) may put a policy on itself, so it can read the billing export bucket.
// It is one rule-match path Issue tagged rule_match + custom; the library's P13 match still folds.
func TestCustomRuleChainIsAPathIssueOnTheLab(t *testing.T) {
	dir := t.TempDir()
	good, _ := os.ReadFile(customRuleFile)
	writeRule(t, dir, "r.yaml", string(good))
	custom, rej := LoadCustomPathRules([]string{dir}, productRules())
	if len(rej) != 0 || len(custom) != 1 {
		t.Fatalf("custom %v rejected %+v", ruleIDs(custom), rej)
	}
	g, _ := labGraph(t, false)
	o := labOptions()
	o.PathRules = append(append([]PathRule(nil), productRules()...), custom...)
	an := Traverse(g, o)
	rps := ruleMatchPaths(an.Paths)
	if len(rps) != 1 {
		t.Fatalf("%d rule-match paths, want 1 (the custom chain)", len(rps))
	}
	p := rps[0]
	last := p.Steps[len(p.Steps)-1]
	tags, _ := last.Evidence["tags"].([]string)
	if p.RuleID != "acme-self-grant-billing-read" || last.Resource != "arn:aws:s3:::nimbus-lab-billing-exports" || strings.Join(tags, ",") != "rule_match,custom" {
		t.Errorf("rule path %s → %s tags %v", p.RuleID, last.Resource, tags)
	}
	if pathEntry(p) != "internet" || len(p.Steps) < 3 || p.Steps[len(p.Steps)-2].Resource != "arn:aws:iam::111111111111:role/nimbus-lab-support-agent-role" {
		t.Errorf("chain %s: want internet → support agent → its role → billing exports", stepKey(pathEntry(p), p.Steps))
	}
	if p.Score < 5 {
		t.Errorf("custom chain scored %.2f", p.Score)
	}
	folded := false
	for _, x := range an.Paths {
		for _, r := range AlsoMatchesRules(x) {
			folded = folded || r == ec2RuleID
		}
	}
	if !folded {
		t.Errorf("the library P13 match no longer folds when custom rules are present")
	}
}
