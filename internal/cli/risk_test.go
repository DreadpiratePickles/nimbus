package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// risk test dry-runs a path rule against the stored snapshot without writing to the store.
// The lab's no-MFA developer sam can iam:PassRole the EC2 admin role and ec2:RunInstances
// (ground truth P13), so the ported Prowler EC2-001 rule must match sam -> ec2-admin-role.
func TestRiskTestOnLabSnapshot(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")

	rule, _ := filepath.Abs(filepath.Join("..", "attackpath", "rules", "aws", "privesc", "aws-ec2-privesc-passrole-iam.yaml"))
	out := run(t, "risk", "test", rule, "--format", "json")
	var doc struct {
		Rule      string `json:"rule"`
		TestsPass bool   `json:"tests_pass"`
		Matches   []struct {
			Anchor     string   `json:"anchor"`
			Target     string   `json:"target"`
			Confidence string   `json:"confidence"`
			Because    []string `json:"because"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not risk JSON: %v\n%.300s", err, out)
	}
	if doc.Rule != "aws-ec2-privesc-passrole-iam" || !doc.TestsPass {
		t.Fatalf("rule %q tests_pass=%v", doc.Rule, doc.TestsPass)
	}
	found := false
	for _, m := range doc.Matches {
		if strings.HasSuffix(m.Anchor, "user/nimbus-lab-dev-sam") && strings.HasSuffix(m.Target, "role/nimbus-lab-ec2-admin-role") {
			found = true
			if m.Confidence != "verified" {
				t.Errorf("P13 match confidence = %q, want verified (the can_assume technique edge proves it)", m.Confidence)
			}
			if len(m.Because) == 0 {
				t.Errorf("match has no per-hop because")
			}
		}
	}
	if !found {
		t.Fatalf("P13 match (dev-sam -> ec2-admin-role) missing; matches=%+v", doc.Matches)
	}
}

func TestRiskListShowsLibraryWithCredits(t *testing.T) {
	out := run(t, "risk", "list", "--format", "json")
	var rules []struct {
		ID         string `json:"id"`
		Confidence string `json:"confidence"`
		Credit     *struct {
			Source     string `json:"source"`
			UpstreamID string `json:"upstream_id"`
		} `json:"credit"`
	}
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("not a rule list: %v\n%.200s", err, out)
	}
	if len(rules) < 15 {
		t.Fatalf("risk list has %d rules, want >= 15", len(rules))
	}
	for _, r := range rules {
		if r.Credit == nil || r.Credit.Source != "Prowler" || r.Credit.UpstreamID == "" {
			t.Errorf("%s: missing Prowler credit", r.ID)
		}
	}
}
