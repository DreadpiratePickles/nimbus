package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W7-ENGINE item 2 (r5 #4; bar: Sysdig custom risk definitions become Issues with New badges):
// a customer rule directory reaches the product. `ingest --rules-dir` validates every rule with
// `risk test` semantics (a failing rule is rejected with its reason, the rest load); the accepted
// rule's lab chain (the internet-invocable Bedrock agent's role may put a policy on itself and
// read the billing exports) is a new path Issue, counted "new" by the scan trend; config
// path_rules.dirs gives `paths` the same Issue.
func TestCustomPathRulesReachTheProductOnLab(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join("..", "attackpath", "testdata", "custom_rules", "acme-self-grant-billing-read.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(rules, "billing.yaml"), good, 0o600)
	bad := strings.NewReplacer("acme-self-grant-billing-read", "acme-broken", `id_like: ["arn:aws:s3:::*billing*"]`, `id_like: ["arn:aws:s3:::*"]`).Replace(string(good))
	os.WriteFile(filepath.Join(rules, "broken.yaml"), []byte(bad), 0o600)

	cfg := labConfig(t)
	run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	st := openTestStore(t)
	h0, err := st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	out := run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary", "--diff", "--rules-dir", rules)
	if !strings.Contains(out, "acme-broken") || !strings.Contains(out, "own tests fail") {
		t.Errorf("the failing rule must be rejected with its reason:\n%s", out)
	}
	if !strings.Contains(out, "Issues this scan: 1 new") {
		t.Errorf("the custom rule's chain must be one new Issue in the scan trend:\n%s", out)
	}
	st = openTestStore(t)
	h1, err := st.Headline()
	if err != nil {
		t.Fatal(err)
	}
	if h1.PathIssues != h0.PathIssues+1 {
		t.Errorf("path Issues %d → %d, want +1 from the customer rule", h0.PathIssues, h1.PathIssues)
	}
	iss, err := st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range iss {
		if is.RuleID == "acme-self-grant-billing-read" {
			found = true
			if is.AnchorID != "arn:aws:s3:::nimbus-lab-billing-exports" || is.State != "open" {
				t.Errorf("custom Issue %+v", is)
			}
		}
		if is.RuleID == "acme-broken" {
			t.Errorf("a rejected rule produced Issue %s", is.ID)
		}
	}
	if !found {
		t.Errorf("no path Issue carries rule acme-self-grant-billing-read")
	}
	st.Close()

	// The config key: `paths` (no flag) shows the same Issue count.
	cfgBody, _ := os.ReadFile(cfg)
	cfg2 := filepath.Join(dir, "cloud-posture.yaml")
	os.WriteFile(cfg2, append(cfgBody, []byte("\npath_rules:\n  dirs: [rules]\n")...), 0o600)
	pathsOut := run(t, "-c", cfg2, "paths", "--no-dead-ends")
	if !strings.Contains(pathsOut, "Role rewrites its own policy to read billing exports") && !strings.Contains(pathsOut, "nimbus-lab-billing-exports") {
		t.Errorf("paths with path_rules.dirs lacks the custom chain:\n%s", firstLines(pathsOut, 30))
	}
	if !strings.Contains(pathsOut, "21 attack path Issue(s)") {
		t.Errorf("paths header should count 21 path Issues (lab 20 + the customer rule):\n%s", firstLines(pathsOut, 3))
	}
}

// W7-ENGINE item 1 (r5 #3): no plan step resolves the same chain twice; the dev-sam PassRole fix
// resolves one path.
func TestPlanCountsTheDevSamChainOnceOnLab(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := labConfig(t)
	run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	out := run(t, "-c", cfg, "plan", "--top", "20")
	if !strings.Contains(out, "Plan: 20 attack path Issues (23 hop variants: 22 traversal, 1 rule-chain)") {
		t.Errorf("plan headline:\n%s", firstLines(out, 2))
	}
	for _, block := range strings.Split(out, "\n\n") {
		if strings.Contains(block, "privesc passrole on nimbus-lab-dev-sam") && !strings.Contains(block, "resolves 1 path(s) alone") {
			t.Errorf("dev-sam PassRole step should resolve 1 path:\n%s", firstLines(block, 3))
		}
	}
}

// W7-ENGINE item 5 (r5 #7): every plan step's headline command renders the step's own template
// format (the K8s LoadBalancer step said --generate-terraform and printed a generic stub), and the
// typed Kubernetes fix for lab W49 patches the Service that selects report-worker-0, never the pod.
func TestPlanHeadlineFormatAndK8sServiceTargetOnLab(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := labConfig(t)
	run(t, "-c", cfg, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	var doc struct {
		Steps []struct {
			Fix struct {
				Command    string   `json:"command"`
				FindingIDs []string `json:"finding_ids"`
			} `json:"fix"`
			Template string `json:"template"`
		} `json:"steps"`
	}
	if err := json.Unmarshal([]byte(run(t, "-c", cfg, "plan", "--top", "20", "--json")), &doc); err != nil {
		t.Fatal(err)
	}
	ext := map[string]string{".k8s.yaml": "kubernetes", ".tf": "terraform", ".cfn.yaml": "cloudformation", ".bicep": "bicep"}
	sawK8s := false
	for i, s := range doc.Steps {
		for suffix, format := range ext {
			own := strings.Contains(s.Fix.Command, "--format "+format) || strings.Contains(s.Fix.Command, "--generate-"+format)
			if strings.HasSuffix(s.Template, suffix) && strings.HasPrefix(s.Fix.Command, "cloud-posture fix --id ") && !own {
				t.Errorf("step %d: template %s but headline %q", i+1, s.Template, s.Fix.Command)
			}
		}
		if strings.Contains(s.Fix.Command, "lab-W49") {
			sawK8s = true
			if s.Fix.Command != "cloud-posture fix --id lab-W49 --format kubernetes" {
				t.Errorf("W49 headline %q", s.Fix.Command)
			}
		}
	}
	if !sawK8s {
		t.Fatalf("plan --top 20 has no W49 step")
	}
	planOut := run(t, "-c", cfg, "plan", "--top", "20")
	if strings.Contains(planOut, "-- pod report-worker-0") || !strings.Contains(planOut, "-- service report-worker") {
		t.Errorf("plan W49 fix must patch service report-worker, not the pod")
	}
	out := run(t, "-c", cfg, "fix", "--id", "lab-W49", "--format", "kubernetes", "--out-dir", filepath.Join(dir, "fixes"))
	if strings.Contains(out, "-- pod ") || !strings.Contains(out, "-- service report-worker") || strings.Contains(out, "generic stub") {
		t.Errorf("fix --id lab-W49 --format kubernetes:\n%s", out)
	}
}
