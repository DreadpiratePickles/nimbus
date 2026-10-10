package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awscol "github.com/DreadpiratePickles/nimbus/internal/collector/aws"
)

// delta r3 #13 / walkthrough E19: onboard detects AWS through the SDK credential chain, not
// the `aws` CLI. With SDK credentials and no CLI on PATH it must add the account.
func TestOnboardDetectsAWSWithoutCLI(t *testing.T) {
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "") // the discovery is a fake; W6 gates real detection on no-network
	dir := t.TempDir()
	t.Setenv("PATH", t.TempDir()) // no aws / az / gcloud
	old := discoverAWS
	t.Cleanup(func() { discoverAWS = old })
	discoverAWS = func(ctx context.Context) []awscol.DiscoveredIdentity {
		return []awscol.DiscoveredIdentity{
			{Source: "environment", Account: "111111111111", Arn: "arn:aws:iam::111111111111:user/ci"},
			{Profile: "prod", Source: "SSO cache", Account: "222222222222", Arn: "arn:aws:sts::222222222222:assumed-role/Admin/me"},
		}
	}
	flagDB = filepath.Join(dir, "p.db")
	out := filepath.Join(dir, "cp.yaml")
	got := run(t, "onboard", "--aws", "--yes", "--out", out)
	for _, want := range []string{"✓ aws", "account 111111111111", "via environment", "account 222222222222", "via SSO cache (profile prod)", "wrote"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "aws not installed") || strings.Contains(got, "Nothing detected") {
		t.Fatalf("CLI-based detection leaked:\n%s", got)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"aws-111111111111", "aws-prod", "profile: prod"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("config missing %q:\n%s", want, data)
		}
	}
}

func TestOnboardAWSNothingFoundSaysWhatWasSearched(t *testing.T) {
	t.Setenv("CLOUD_POSTURE_NO_NETWORK", "") // the discovery is a fake; W6 gates real detection on no-network
	dir := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	old := discoverAWS
	t.Cleanup(func() { discoverAWS = old })
	discoverAWS = func(ctx context.Context) []awscol.DiscoveredIdentity {
		return []awscol.DiscoveredIdentity{{Err: "no AWS credentials found (searched: environment, shared config/credentials files, SSO cache, web identity, container and instance metadata)"}}
	}
	flagDB = filepath.Join(dir, "p.db")
	got := run(t, "onboard", "--aws", "--yes", "--out", filepath.Join(dir, "cp.yaml"))
	if !strings.Contains(got, "✗ aws") || !strings.Contains(got, "SSO cache") || strings.Contains(got, "not installed") {
		t.Fatalf("%s", got)
	}
}
