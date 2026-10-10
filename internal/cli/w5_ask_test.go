package cli

import (
	"os"
	"strings"
	"testing"
)

// Delta r3 #11: `cloud-posture ask` hands the Python copilot its own executable as
// CLOUD_POSTURE_BIN (who-can and the verdict overlay then never fail on discovery), never
// overrides an explicit CLOUD_POSTURE_BIN, passes --show-sql through, and prints an error once.
func TestAskEnvCarriesOwnBinary(t *testing.T) {
	t.Setenv("CLOUD_POSTURE_BIN", "")
	env := askEnv("/tmp/p.db")
	self, _ := os.Executable()
	if !containsEnv(env, "CLOUD_POSTURE_BIN="+self) || !containsEnv(env, "CLOUD_POSTURE_DB=/tmp/p.db") {
		t.Fatalf("ask env %v lacks CLOUD_POSTURE_BIN=%s / CLOUD_POSTURE_DB", env, self)
	}
	t.Setenv("CLOUD_POSTURE_BIN", "/opt/explicit/cloud-posture")
	if env := askEnv("/tmp/p.db"); containsEnvPrefix(env, "CLOUD_POSTURE_BIN=") {
		t.Fatalf("explicit CLOUD_POSTURE_BIN overridden: %v", env)
	}
}

func TestAskArgsAndSingleError(t *testing.T) {
	if got := strings.Join(askArgs("ask", "public buckets", false), " "); got != "-m nimbus ask -- public buckets" {
		t.Errorf("args %q", got)
	}
	if got := strings.Join(askArgs("ask", "public buckets", true), " "); got != "-m nimbus ask --show-sql -- public buckets" {
		t.Errorf("args with --show-sql %q", got)
	}
	if got := strings.Join(askArgs("policy", "write an opa policy", true), " "); strings.Contains(got, "--show-sql") {
		t.Errorf("--show-sql passed to policy: %q", got)
	}
	if !askCmd.SilenceErrors {
		t.Error("ask errors are printed twice (cobra and main)")
	}
	if askCmd.Flags().Lookup("show-sql") == nil {
		t.Error("ask has no --show-sql flag")
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func containsEnvPrefix(env []string, p string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, p) {
			return true
		}
	}
	return false
}
