package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Delta review 2 #9: ownership out of the box. `governance init` reads the resource tags in
// the posture database and the CODEOWNERS of the repository and prints a starter
// `governance:` block (rules first-match: owner tags, then CODEOWNERS for IaC files), with the
// share of open Issues it would assign.
func TestGovernanceInitStarterRulesFromLab(t *testing.T) {
	dir := labDB(t)
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(filepath.Join(repo, ".github"), 0o755)
	os.WriteFile(filepath.Join(repo, ".github", "CODEOWNERS"), []byte("*.tf @acme/platform\nmodules/ @acme/infra\n"), 0o644)
	out := run(t, "governance", "init", "--repo", repo)
	for _, want := range []string{"governance:", "owner: tag:owner", "owner: codeowners", "iac_path_glob:", "would assign"} {
		if !strings.Contains(out, want) {
			t.Errorf("governance init output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tag:environment") || strings.Contains(out, "tag:data_classification") {
		t.Errorf("non-ownership tags must not become owner rules:\n%s", out)
	}
	// The printed block is a valid config.
	block := out[strings.Index(out, "governance:"):]
	cfgPath := filepath.Join(dir, "gov.yaml")
	os.WriteFile(cfgPath, []byte(block), 0o644)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("starter block does not load: %v\n%s", err, block)
	}
	if len(cfg.Governance.Rules) < 2 {
		t.Fatalf("want tag + codeowners rules, got %+v", cfg.Governance.Rules)
	}
}

// --write appends the block to the config file (keeping what is there) and refuses to
// replace an existing governance block without --force.
func TestGovernanceInitWrite(t *testing.T) {
	dir := labDB(t)
	cfgPath := filepath.Join(dir, "cloud-posture.yaml")
	orig := "# my config\naccounts:\n  prod:\n    provider: aws\n    profile: prod\n"
	os.WriteFile(cfgPath, []byte(orig), 0o644)
	run(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write")
	b, _ := os.ReadFile(cfgPath)
	if !strings.HasPrefix(string(b), orig) || !strings.Contains(string(b), "governance:") {
		t.Fatalf("--write must append the block and keep the file:\n%s", b)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil || !cfg.Governance.Enabled() || cfg.Accounts["prod"] == nil {
		t.Fatalf("written config: %v %+v", err, cfg)
	}
	if out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write"); err == nil || !strings.Contains(out+err.Error(), "--force") {
		t.Fatalf("second --write must refuse without --force: %v\n%s", err, out)
	}
}

// Ownership-like tag keys are found case-insensitively in resource and finding tags;
// unrelated keys are not.
func TestDiscoverOwnerTagKeys(t *testing.T) {
	mk := func(id string, tags map[string]any) model.Finding {
		return model.Finding{ID: id, Status: model.Fail, Resource: model.Resource{ID: id, Attributes: map[string]any{"tags": tags}}}
	}
	fs := []model.Finding{
		mk("a", map[string]any{"Team": "payments", "env": "prod"}),
		mk("b", map[string]any{"Team": "payments", "owner_email": "x@example.com"}),
		mk("c", map[string]any{"CostCenter": "42", "Name": "c"}),
		mk("c", map[string]any{"CostCenter": "42"}), // same resource counts once
	}
	stats, total := discoverOwnerTags(fs, nil)
	if total != 3 {
		t.Fatalf("resources = %d, want 3", total)
	}
	got := map[string]int{}
	for _, s := range stats {
		got[s.Key] = s.Resources
	}
	if got["Team"] != 2 || got["owner_email"] != 1 || got["CostCenter"] != 1 {
		t.Fatalf("stats %+v", stats)
	}
	if _, ok := got["env"]; ok {
		t.Fatalf("env is not an ownership key: %+v", stats)
	}
	if stats[len(stats)-1].Key != "CostCenter" {
		t.Errorf("weak keys (cost center) rank after owner/team keys: %+v", stats)
	}
}

// onboard adds the starter block when the config has none, and leaves an existing one alone.
func TestOnboardGovernanceStarter(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @acme/sec\n"), 0o644)
	cfg := &config.Config{Accounts: map[string]*config.Account{}}
	if !onboardGovernance(cfg, dir, nil) {
		t.Fatal("onboard must add a starter governance block")
	}
	var co, tag bool
	for _, r := range cfg.Governance.Rules {
		co = co || r.Owner == "codeowners"
		tag = tag || strings.HasPrefix(r.Owner, "tag:")
	}
	if !co || !tag {
		t.Fatalf("starter rules %+v", cfg.Governance.Rules)
	}
	cfg.Governance = config.Governance{Defaults: config.GovernanceDefaults{Owner: "me@example.com"}}
	if onboardGovernance(cfg, dir, nil) || cfg.Governance.Defaults.Owner != "me@example.com" || len(cfg.Governance.Rules) != 0 {
		t.Fatalf("an existing governance block must be kept: %+v", cfg.Governance)
	}
}

// doctor warns when more than 30% of open Issues have no owner (the lab: most are unassigned).
func TestDoctorWarnsUnassignedIssues(t *testing.T) {
	labDB(t)
	flagConfig = filepath.Join(t.TempDir(), "none.yaml")
	t.Cleanup(func() { flagConfig = "" })
	var buf bytes.Buffer
	runDoctor(context.Background(), fakeDoctorEnv(nil, nil, nil), &buf)
	out := buf.String()
	if !strings.Contains(out, "ownership") || !strings.Contains(out, "unassigned") || !strings.Contains(out, "governance init") {
		t.Fatalf("doctor must warn about unassigned Issues:\n%s", out)
	}
	if strings.Contains(out, "risk model") {
		t.Errorf("stale python-layer message (risk scoring is Go-native):\n%s", out)
	}
	if !strings.Contains(out, "intel snapshot") {
		t.Errorf("doctor must state the embedded KEV/EPSS snapshot date:\n%s", out)
	}
}
