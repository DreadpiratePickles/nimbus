package cli

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/server"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W5 (competitive delta r3 #10, walkthrough E8/E13): `plan` groups its fixes per target resource
// with "resolves N / reduces M" (the AWS Security Hub remediation-plan view), its verify phase
// names `cloud-posture verify <issue-id>` with the real Issue id, and the LAMBDA_PUBLIC fix on
// the lab's top path is a typed template.

func planJSON(t *testing.T) planDoc {
	t.Helper()
	out := run(t, "plan", "--top", "100", "--json")
	var d planDoc
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &d); err != nil {
		t.Fatalf("plan --json: %v", err)
	}
	return d
}

// labIssues returns the stored Issues: finding id → single/combination Issue id, and the set of
// path Issue ids.
func labIssues(t *testing.T) (byFinding map[string]string, paths map[string]bool) {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	all, err := st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byFinding, paths = map[string]string{}, map[string]bool{}
	for _, is := range all {
		if is.Kind == model.IssuePath {
			paths[is.ID] = true
			continue
		}
		for _, f := range is.FindingIDs {
			if _, ok := byFinding[f]; !ok || is.Kind == model.IssueSingle {
				byFinding[f] = is.ID
			}
		}
	}
	return byFinding, paths
}

func phase(ps []server.Phase, name string) []string {
	for _, p := range ps {
		if p.Name == name {
			return p.Steps
		}
	}
	return nil
}

func TestPlanGroupsFixesPerTarget(t *testing.T) {
	labDB(t)
	d := planJSON(t)
	if len(d.Targets) == 0 {
		t.Fatalf("plan --json has no per-target groups (%d steps)", len(d.Steps))
	}
	steps, reducesSomewhere := 0, false
	for _, tg := range d.Targets {
		if tg.Resource == "" || len(tg.Steps) == 0 || len(tg.Fixes) != len(tg.Steps) {
			t.Errorf("malformed target %+v", tg)
		}
		steps += len(tg.Steps)
		if tg.Reduces > 0 {
			reducesSomewhere = true
		}
		// A target with one traversal step resolves exactly what that step resolves.
		if len(tg.Steps) == 1 && !strings.HasPrefix(tg.Steps[0], "R") {
			var i int
			for i = range d.Steps {
				if stepLabel(i) == tg.Steps[0] {
					break
				}
			}
			s := d.Steps[i]
			if tg.Resolves != s.Resolves+s.RuleChains || tg.Reduces > s.Reduces {
				t.Errorf("target %s: resolves %d / reduces %d, its step %s resolves %d (+%d rule-chain) reduces %d", tg.Name, tg.Resolves, tg.Reduces, tg.Steps[0], s.Resolves, s.RuleChains, s.Reduces)
			}
		}
	}
	if want := len(d.Steps) + len(d.RuleChainSteps); steps != want {
		t.Errorf("targets cover %d steps, plan has %d", steps, want)
	}
	if !reducesSomewhere {
		t.Errorf("no target reports a path it only reduces (the lab's customer-pii fix reduces one)")
	}
	txt := run(t, "plan", "--top", "100")
	for _, re := range []string{
		// W6-POLISH (r4 #4 / E6): the headline counts path Issues, then their hop variants.
		`(?m)^Plan: \d+ attack path Issues \(\d+ hop variants: \d+ traversal( incl\. \d+ path-rule match)?, \d+ rule-chain\), total score \d+\.\d$`,
		`(?m)^Minimum fix set: \d+ fix\(es\) — min_fix_exact=`,
		`(?m)^By target resource \(\d+ target\(s\)\):$`,
		`(?m)^  \S.* — resolves \d+ / reduces \d+ · steps \d`,
	} {
		if !regexp.MustCompile(re).MatchString(txt) {
			t.Errorf("plan text lacks %s\n%s", re, txt[:min(len(txt), 1500)])
		}
	}
}

func TestPlanVerifyNamesIssueVerify(t *testing.T) {
	labDB(t)
	d := planJSON(t)
	byFinding, pathIssues := labIssues(t)
	lambda, sawPath := false, false
	for i, s := range d.Steps {
		v := strings.Join(phase(s.Phases, "verify"), "\n")
		if !strings.Contains(v, "cloud-posture verify ") {
			t.Errorf("step %d (%s): verify phase does not name cloud-posture verify:\n%s", i+1, s.Fix.Name, v)
		}
		if strings.Contains(v, "Until finding lifecycle") || strings.Contains(v, "Track G") {
			t.Errorf("step %d: stale Track G caveat in verify:\n%s", i+1, v)
		}
		for pid := range pathIssues {
			if strings.Contains(v, "cloud-posture verify "+pid) {
				sawPath = true
			}
		}
		if slices.Contains(s.Fix.FindingIDs, "lab-W12") {
			lambda = true
			if s.Template != "lambda_function_url_auth.tf" {
				t.Errorf("LAMBDA_PUBLIC step template %q, want lambda_function_url_auth.tf", s.Template)
			}
			id := byFinding["lab-W12"]
			if id == "" || !strings.Contains(v, "cloud-posture verify "+id) {
				t.Errorf("LAMBDA_PUBLIC step verify must name its Issue %q:\n%s", id, v)
			}
		}
	}
	if !lambda {
		t.Errorf("no step fixes lab-W12 (LAMBDA_PUBLIC on nimbus-lab-export)")
	}
	if !sawPath {
		t.Errorf("no verify phase names a path Issue it resolves")
	}
	for _, s := range d.RuleChainSteps {
		if v := strings.Join(phase(s.Phases, "verify"), "\n"); !strings.Contains(v, "cloud-posture verify ") {
			t.Errorf("rule-chain step %s: verify lacks cloud-posture verify:\n%s", s.CanonicalID, v)
		}
	}
}

// `fix --id` prints the same verify step with the finding's Issue id.
func TestFixVerifyNamesIssueID(t *testing.T) {
	labDB(t)
	byFinding, _ := labIssues(t)
	out := run(t, "fix", "--id", "lab-W12", "--format", "terraform", "--out-dir", filepath.Join(t.TempDir(), "rem"))
	if strings.Contains(out, "generic stub") {
		t.Errorf("LAMBDA_PUBLIC fix is still a generic stub:\n%s", out)
	}
	if id := byFinding["lab-W12"]; id == "" || !strings.Contains(out, "cloud-posture verify "+id) {
		t.Errorf("fix verify phase must name Issue %q:\n%s", id, out)
	}
}
