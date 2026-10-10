package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// Verification 6 (routed item 7, G1/G2): `governance init --write` merges into an existing empty
// `governance:` block instead of appending a duplicate key, writes atomically and only a file
// that re-loads, keeps comments and user-authored rules under --force, never writes through a
// symlink, and keeps the file's mode.
func TestGovernanceInitWriteMergesAnEmptyBlock(t *testing.T) {
	for name, body := range map[string]string{
		"empty-map":    "# lab\npython:\n  enabled: false\ngovernance: {}\n",
		"null-comment": "# lab\npython:\n  enabled: false\ngovernance:  # owners go here\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := labDB(t)
			cfgPath := filepath.Join(dir, "c.yaml")
			os.WriteFile(cfgPath, []byte(body), 0o600)
			if out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write"); err != nil {
				t.Fatalf("--write on %q: %v\n%s", body, err, out)
			}
			b, _ := os.ReadFile(cfgPath)
			if n := strings.Count("\n"+string(b), "\ngovernance:"); n != 1 {
				t.Fatalf("%d governance: keys:\n%s", n, b)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil || !cfg.Governance.Enabled() {
				t.Fatalf("written config does not load: %v\n%s", err, b)
			}
			if !strings.Contains(string(b), "# lab") {
				t.Errorf("comments dropped:\n%s", b)
			}
			if fi, _ := os.Stat(cfgPath); fi.Mode().Perm() != 0o600 {
				t.Errorf("mode %v, want the file's own 0600", fi.Mode().Perm())
			}
		})
	}
}

func TestGovernanceInitForceKeepsCommentsAndUserRules(t *testing.T) {
	dir := labDB(t)
	cfgPath := filepath.Join(dir, "c.yaml")
	orig := `# team config
python:
  enabled: false
governance:
  # payments owns its account, whatever the tags say
  rules:
    - id: payments
      match:
        account: "999999999999"
      owner: payments-oncall # pager rotation
  digest:
    sink: stdout
`
	os.WriteFile(cfgPath, []byte(orig), 0o644)
	if out, err := runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write", "--force"); err != nil {
		t.Fatalf("--force: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(cfgPath)
	s := string(b)
	for _, want := range []string{"# team config", "# payments owns its account", "# pager rotation", "id: payments", "payments-oncall", "sink: stdout", "owner-tag-owner"} {
		if !strings.Contains(s, want) {
			t.Errorf("--force lost %q:\n%s", want, s)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("does not load: %v\n%s", err, s)
	}
	if cfg.Governance.Rules[0].ID != "payments" {
		t.Errorf("user rule must stay first (first match wins): %+v", cfg.Governance.Rules)
	}
	// A rerun with --force is idempotent: no duplicated generated rules.
	runErr(t, "-c", cfgPath, "governance", "init", "--repo", dir, "--write", "--force")
	b2, _ := os.ReadFile(cfgPath)
	if strings.Count(string(b2), "id: owner-tag-owner") != 1 || strings.Count(string(b2), "starter block written by") != 1 {
		t.Errorf("rerun duplicated generated rules:\n%s", b2)
	}
}

func TestGovernanceInitWriteRefusesSymlinkAndKeepsFileOnInvalidResult(t *testing.T) {
	dir := labDB(t)
	target := filepath.Join(dir, "real.yaml")
	os.WriteFile(target, []byte("python:\n  enabled: false\n"), 0o644)
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, err := runErr(t, "-c", link, "governance", "init", "--repo", dir, "--write"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("--write through a symlink must be refused: %v", err)
	}
	if b, _ := os.ReadFile(target); strings.Contains(string(b), "governance") {
		t.Errorf("the symlink target was written:\n%s", b)
	}
	// The atomic writer never replaces the file with something that does not load.
	p := filepath.Join(dir, "keep.yaml")
	os.WriteFile(p, []byte("python:\n  enabled: false\n"), 0o640)
	if err := writeConfigValidated(p, []byte("governance:\n  rules: [ {id: x, match: {}, owner: \"\"} ]\n"), 0o640); err == nil {
		t.Error("an invalid result must be refused")
	}
	if b, _ := os.ReadFile(p); string(b) != "python:\n  enabled: false\n" {
		t.Errorf("file changed on a refused write:\n%s", b)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".cloud-posture-*.yaml")); len(m) != 0 {
		t.Errorf("temp files left behind: %v", m)
	}
}
