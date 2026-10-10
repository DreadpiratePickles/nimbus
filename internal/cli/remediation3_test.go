package cli

// Integration pass 3, item 3 (#8): remediation content that was never shown. `fix` prints the
// sidecar as AWS-remediation-plan phases; `plan` covers rule-chain paths and names what it
// cannot break.

import (
	"encoding/json"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func TestFixPrintsRemediationPhases(t *testing.T) {
	dir := labDB(t)
	out := run(t, "fix", "--finding", "S3_PUBLIC_BUCKET", "--out-dir", filepath.Join(dir, "rem"))
	for _, want := range []string{
		"1. prerequisite", "s3:PutBucketPublicAccessBlock", "breaks function: yes",
		"2. snapshot", "terraform state pull",
		"3. fix", "terraform plan",
		"4. verify", "expect no rows", "canonical_id = 'S3_PUBLIC_BUCKET'",
		"5. rollback", "delete-public-access-block",
		"mitigation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fix output lacks %q:\n%s", want, out)
		}
	}
}

func TestPlanCoversRuleChainsAndNamesResidualPaths(t *testing.T) {
	labDB(t)
	st, _ := store.Open(flagDB)
	stored, _ := st.AttackPaths()
	st.Close()
	rules := 0
	for _, p := range stored {
		// Path-rule matches are traversal paths (and path Issues), not rule chains (W6-ENGINE).
		if _, _, r := model.PathIssueKey(p); r != model.PathRuleTraversal && !attackpath.IsRuleMatch(p) {
			rules++
		}
	}
	if rules == 0 {
		t.Skip("lab has no rule-chain paths")
	}
	var doc struct {
		TotalPaths     int `json:"total_paths"`
		RuleChainPaths int `json:"rule_chain_paths"`
		Steps          []struct {
			Phases []struct{ Name string } `json:"phases"`
		} `json:"steps"`
		RuleChainSteps []struct {
			Resolves int `json:"resolves"`
		} `json:"rule_chain_steps"`
		Remaining []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"remaining"`
	}
	if err := json.Unmarshal([]byte(run(t, "plan", "--json", "--top", "3")), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RuleChainPaths != rules || doc.TotalPaths != len(stored) {
		t.Errorf("plan counts %d paths / %d rule chains; store has %d / %d", doc.TotalPaths, doc.RuleChainPaths, len(stored), rules)
	}
	if len(doc.Steps) == 0 || len(doc.Steps[0].Phases) != 5 {
		t.Fatalf("plan steps lack the 5 remediation phases: %+v", doc.Steps)
	}
	if len(doc.Remaining) == 0 {
		t.Errorf("--top 3 over a %d-path estate leaves paths; plan must name them", len(stored))
	}
	for _, r := range doc.Remaining {
		if r.Name == "" || r.Reason == "" {
			t.Errorf("remaining path without name/reason: %+v", r)
		}
	}
	out := run(t, "plan", "--top", "3")
	for _, want := range []string{"rule-chain", "remaining:", "paths, e.g.", "1. prerequisite", "5. rollback", "reduces"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan text lacks %q:\n%s", want, out)
		}
	}
}
