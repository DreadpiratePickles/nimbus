package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// fakeSTS answers GetCallerIdentity from the access key id the request was signed with.
type fakeSTS struct {
	cfg   awssdk.Config
	calls *int
	ids   map[string][2]string // access key id → account, arn
}

func (f fakeSTS) GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	*f.calls++
	c, err := f.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	id, ok := f.ids[c.AccessKeyID]
	if !ok {
		return nil, errors.New("InvalidClientTokenId")
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(id[0]), Arn: awssdk.String(id[1])}, nil
}

// isolate points every SDK credential source at an empty temp home so the developer's real
// credentials never leak into the test, and disables IMDS (no network).
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("HOME", dir)
	return dir
}

func discoverer(calls *int, ids map[string][2]string) CredentialDiscovery {
	return CredentialDiscovery{NewSTS: func(cfg awssdk.Config) CallerIdentityAPI { return fakeSTS{cfg: cfg, calls: calls, ids: ids} }}
}

func TestDiscoverEnvCredentialsWithoutCLI(t *testing.T) {
	isolate(t)
	t.Setenv("PATH", t.TempDir()) // no `aws` CLI anywhere
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENVEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	calls := 0
	got := discoverer(&calls, map[string][2]string{"AKIAENVEXAMPLE": {"111111111111", "arn:aws:iam::111111111111:user/ci"}}).Discover(context.Background())
	if len(got) != 1 || got[0].Err != "" || got[0].Account != "111111111111" || got[0].Source != "environment" || got[0].Profile != "" {
		t.Fatalf("%+v", got)
	}
	if calls != 1 {
		t.Fatalf("STS calls %d, want 1 (read-only GetCallerIdentity only)", calls)
	}
}

func TestDiscoverSharedProfiles(t *testing.T) {
	dir := isolate(t)
	os.WriteFile(filepath.Join(dir, "credentials"), []byte("[default]\naws_access_key_id = AKIADEF\naws_secret_access_key = s\n\n[dev]\naws_access_key_id = AKIADEV\naws_secret_access_key = s\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "config"), []byte("[default]\nregion = us-east-1\n\n[profile prod]\nregion = eu-west-1\naws_access_key_id = AKIAPROD\naws_secret_access_key = s\n\n[sso-session corp]\nsso_region = us-east-1\n"), 0o600)
	calls := 0
	got := discoverer(&calls, map[string][2]string{
		"AKIADEF":  {"222222222222", "arn:aws:iam::222222222222:user/me"},
		"AKIADEV":  {"333333333333", "arn:aws:iam::333333333333:user/me"},
		"AKIAPROD": {"444444444444", "arn:aws:iam::444444444444:user/me"},
	}).Discover(context.Background())
	byProfile := map[string]DiscoveredIdentity{}
	for _, d := range got {
		byProfile[d.Profile] = d
	}
	if d := byProfile[""]; d.Account != "222222222222" || !strings.Contains(d.Source, "shared") {
		t.Fatalf("default chain: %+v (all %+v)", d, got)
	}
	if d := byProfile["dev"]; d.Account != "333333333333" {
		t.Fatalf("dev: %+v", d)
	}
	if d := byProfile["prod"]; d.Account != "444444444444" {
		t.Fatalf("prod: %+v", d)
	}
	if _, dup := byProfile["default"]; dup {
		t.Fatalf("[default] repeats the default chain: %+v", got)
	}
	if _, bogus := byProfile["corp"]; bogus {
		t.Fatal("an sso-session section is not a profile")
	}
}

func TestDiscoverNothingSaysWhy(t *testing.T) {
	isolate(t)
	calls := 0
	got := discoverer(&calls, nil).Discover(context.Background())
	if len(got) != 1 || got[0].Err == "" || calls != 0 {
		t.Fatalf("no credentials: %+v (sts calls %d)", got, calls)
	}
	if !strings.Contains(got[0].Err, "no AWS credentials") {
		t.Fatalf("error should say what was searched: %q", got[0].Err)
	}
}

func TestDiscoverSTSFailureIsReported(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXPIRED")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	calls := 0
	got := discoverer(&calls, map[string][2]string{}).Discover(context.Background())
	if len(got) != 1 || !strings.Contains(got[0].Err, "InvalidClientTokenId") || got[0].Source != "environment" {
		t.Fatalf("%+v", got)
	}
}

func TestCredentialSourceNames(t *testing.T) {
	for raw, want := range map[string]string{
		credentials.StaticCredentialsName: "static",
		"EnvConfigCredentials":            "environment",
		"SharedConfigCredentials: /x":     "shared config/credentials file",
		"SSOProvider":                     "SSO cache",
		"WebIdentityCredentials":          "web identity (IRSA / OIDC)",
		"EC2RoleProvider":                 "instance metadata (IMDS)",
		"CredentialsEndpointProvider":     "container credentials endpoint",
		"AssumeRoleProvider":              "assumed role (profile role_arn)",
		"ProcessProvider":                 "credential_process",
	} {
		if got := credentialSourceName(raw); got != want {
			t.Errorf("%q → %q, want %q", raw, got, want)
		}
	}
}
