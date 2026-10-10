package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// delta r3 #13: with no accounts configured, doctor looks at the AWS SDK default chain (fake
// STS here, no `aws` CLI on PATH) and names what onboard would add, instead of only saying
// "no accounts configured".
func TestDoctorNoAccountsReportsSDKCredentials(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	cfgPath := filepath.Join(dir, "cloud-posture.yaml")
	if err := os.WriteFile(cfgPath, []byte("accounts: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	flagConfig, flagDB = cfgPath, filepath.Join(dir, "p.db")
	t.Cleanup(func() { flagConfig, flagDB = "", "" })
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	env := fakeDoctorEnv(nil, map[string]string{"prowler": "5", "checkov": "3", "trivy": "0.55", "steampipe": "1"}, nil)
	env.discoverAWS = func(context.Context) []awscol.DiscoveredIdentity {
		return []awscol.DiscoveredIdentity{{Source: "environment", Account: "111111111111", Arn: "arn:aws:iam::111111111111:user/ci"}}
	}
	var buf bytes.Buffer
	_ = runDoctor(context.Background(), env, &buf)
	out := buf.String()
	for _, want := range []string{"AWS credentials found via environment", "account 111111111111", "cloud-posture onboard --aws"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}

	env.discoverAWS = func(context.Context) []awscol.DiscoveredIdentity {
		return []awscol.DiscoveredIdentity{{Err: "no AWS credentials found (searched: environment, shared config/credentials files, SSO cache)"}}
	}
	buf.Reset()
	_ = runDoctor(context.Background(), env, &buf)
	if !strings.Contains(buf.String(), "no AWS credentials found") {
		t.Fatalf("nothing-found case:\n%s", buf.String())
	}
}
