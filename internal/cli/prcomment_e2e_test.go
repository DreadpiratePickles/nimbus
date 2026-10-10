package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionFixtureE2E is the Action e2e scenario (P1-PLANDIFF D4) run locally: the fixture
// module under testdata/action-fixture is planned with OpenTofu (or Terraform) against its
// committed state with `plan -refresh=false` (mock credentials, no AWS call), once with the "bad"
// PR (-var ssh_cidr=0.0.0.0/0 → opens 1 path) and once as the revert (state = bad, default var →
// closes 1). It skips, saying why, when no binary is installed or the provider cannot be
// installed offline. .github/workflows/action-e2e.yml runs the same two steps in CI.
func TestActionFixtureE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: -short")
	}
	tf := ""
	for _, b := range []string{"tofu", "terraform"} {
		if p, err := exec.LookPath(b); err == nil {
			tf = p
			break
		}
	}
	if tf == "" {
		t.Skip("e2e: neither tofu nor terraform is on PATH (brew install opentofu); the committed plans in testdata/action-fixture/plans cover the diff")
	}
	// This package's TestMain sets CLOUD_POSTURE_NO_NETWORK, so `init` (which may download
	// hashicorp/aws 5.100.0) needs an explicit opt-in.
	if os.Getenv("TF_PLUGIN_CACHE_DIR") == "" && os.Getenv("NIMBUS_E2E_NETWORK") != "1" {
		t.Skip("e2e: set TF_PLUGIN_CACHE_DIR (a provider cache, filled on first use) or NIMBUS_E2E_NETWORK=1 to let `" + filepath.Base(tf) + " init` install hashicorp/aws 5.100.0")
	}
	src := filepath.Join("..", "..", "testdata", "action-fixture")
	work := t.TempDir()
	for _, f := range []string{"main.tf", ".terraform.lock.hcl", filepath.Join("modules", "web", "main.tf")} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(filepath.Join(work, f)), 0o755)
		os.WriteFile(filepath.Join(work, f), b, 0o644)
	}
	state, err := os.ReadFile(filepath.Join(src, "fixture.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	tfRun := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(tf, args...)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			if args[0] == "init" {
				t.Skipf("e2e: %s init failed (provider not installable here): %v\n%s", filepath.Base(tf), err, errb.String())
			}
			t.Fatalf("%s %v: %v\n%s", tf, args, err, errb.String())
		}
		return out.Bytes()
	}
	tfRun("init", "-input=false", "-no-color")
	planJSON := func(name string, stateBody []byte, vars ...string) string {
		os.WriteFile(filepath.Join(work, "terraform.tfstate"), stateBody, 0o600)
		tfRun(append([]string{"plan", "-refresh=false", "-lock=false", "-input=false", "-no-color", "-out=" + name + ".bin"}, vars...)...)
		p := filepath.Join(work, name+".json")
		os.WriteFile(p, tfRun("show", "-json", name+".bin"), 0o600)
		return p
	}
	bad := planComment(t, "--plan-json", planJSON("bad", state, "-var", "ssh_cidr=0.0.0.0/0"), "--redact", "on")
	if !strings.Contains(bad, "opens 1 / closes 0") || !strings.Contains(bad, "nimbus-opens-paths: 1") {
		t.Fatalf("bad PR state:\n%s", bad)
	}
	badState := bytes.ReplaceAll(state, []byte(`"203.0.113.0/24"`), []byte(`"0.0.0.0/0"`))
	rev := planComment(t, "--plan-json", planJSON("revert", badState), "--redact", "on")
	if !strings.Contains(rev, "opens 0 / closes 1") || !strings.Contains(rev, "nimbus-closes-paths: 1") {
		t.Fatalf("revert:\n%s", rev)
	}
	t.Logf("e2e ran with %s: bad → opens 1, revert → closes 1", tf)
}
