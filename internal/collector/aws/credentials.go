package aws

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// Credential discovery for `onboard` (delta r3 #13): find AWS credentials through the SDK's
// default chain — environment, shared config/credentials files (every profile), the SSO token
// cache, web identity (IRSA / OIDC), container and instance metadata — and confirm each with
// one read-only STS GetCallerIdentity call. No `aws` CLI is needed: the collectors use the
// same SDK chain (core.AWSConfig).

// CallerIdentityAPI is the one STS call discovery makes.
type CallerIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// DiscoveredIdentity is one credential source and who it is. Profile "" is the default chain.
type DiscoveredIdentity struct {
	Profile string `json:"profile"`
	Source  string `json:"source"`
	Account string `json:"account,omitempty"`
	Arn     string `json:"arn,omitempty"`
	Err     string `json:"error,omitempty"`
}

// CredentialDiscovery holds the seams tests replace. Zero values use the real SDK.
type CredentialDiscovery struct {
	// LoadConfig loads the SDK config for a profile ("" = default chain).
	LoadConfig func(ctx context.Context, profile string) (awssdk.Config, error)
	// NewSTS returns the STS client for a config.
	NewSTS func(cfg awssdk.Config) CallerIdentityAPI
	// Timeout bounds each profile's credential retrieval + STS call (IMDS can be slow).
	Timeout time.Duration
}

// Discover returns the default chain first, then every other named profile in the shared
// config and credentials files. Identities already found under another profile are dropped.
// With nothing usable it returns one entry whose Err says what was searched.
func (d CredentialDiscovery) Discover(ctx context.Context) []DiscoveredIdentity {
	if d.LoadConfig == nil {
		d.LoadConfig = func(ctx context.Context, profile string) (awssdk.Config, error) {
			return core.AWSConfig(ctx, core.AccountSpec{Provider: "aws", Profile: profile}, core.DefaultAWSRegion)
		}
	}
	if d.NewSTS == nil {
		d.NewSTS = func(cfg awssdk.Config) CallerIdentityAPI { return sts.NewFromConfig(cfg) }
	}
	if d.Timeout == 0 {
		d.Timeout = 15 * time.Second
	}
	var out []DiscoveredIdentity
	seen := map[string]bool{}
	var firstErr string
	active := firstNonEmptyStr(os.Getenv("AWS_PROFILE"), os.Getenv("AWS_DEFAULT_PROFILE"), "default")
	for _, p := range append([]string{""}, SharedProfiles()...) {
		if p != "" && p == active {
			continue // the default chain already resolved this profile
		}
		id := d.one(ctx, p)
		if id.Err != "" {
			if p == "" && id.Source == "" {
				firstErr = id.Err // no credentials in the default chain: only report it if nothing else is found
				continue
			}
			out = append(out, id)
			continue
		}
		key := id.Account + "|" + id.Arn
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		msg := "no AWS credentials found (searched: environment, shared config/credentials files, SSO cache, web identity, container and instance metadata)"
		if firstErr != "" && !strings.Contains(firstErr, "no EC2 IMDS") && !strings.Contains(firstErr, "failed to refresh cached credentials") {
			msg += ": " + firstErr
		}
		out = append(out, DiscoveredIdentity{Err: msg})
	}
	return out
}

func (d CredentialDiscovery) one(ctx context.Context, profile string) DiscoveredIdentity {
	ctx, cancel := context.WithTimeout(ctx, d.Timeout)
	defer cancel()
	id := DiscoveredIdentity{Profile: profile}
	cfg, err := d.LoadConfig(ctx, profile)
	if err != nil {
		id.Err = err.Error()
		return id
	}
	if cfg.Credentials == nil {
		id.Err = "no credential provider"
		return id
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		id.Err = firstLineStr(err.Error())
		return id
	}
	id.Source = credentialSourceName(creds.Source)
	outp, err := d.NewSTS(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		id.Err = "sts:GetCallerIdentity: " + firstLineStr(err.Error())
		return id
	}
	id.Account, id.Arn = awssdk.ToString(outp.Account), awssdk.ToString(outp.Arn)
	return id
}

// credentialSourceName turns the SDK provider's Source into words a user recognises.
func credentialSourceName(src string) string {
	switch {
	case src == "EnvConfigCredentials":
		return "environment"
	case strings.HasPrefix(src, "SharedConfigCredentials"):
		return "shared config/credentials file"
	case strings.HasPrefix(src, "SSOProvider"):
		return "SSO cache"
	case strings.HasPrefix(src, "WebIdentityCredentials"):
		return "web identity (IRSA / OIDC)"
	case strings.HasPrefix(src, "EC2RoleProvider"):
		return "instance metadata (IMDS)"
	case strings.HasPrefix(src, "CredentialsEndpoint"):
		return "container credentials endpoint"
	case strings.HasPrefix(src, "AssumeRoleProvider"):
		return "assumed role (profile role_arn)"
	case strings.HasPrefix(src, "ProcessProvider"):
		return "credential_process"
	case strings.HasPrefix(src, "StaticCredentials"):
		return "static"
	case src == "":
		return "unknown"
	}
	return src
}

// SharedProfiles lists the profile names in the shared config and credentials files
// (AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE or the SDK defaults), sorted. Section types
// that are not profiles (sso-session, services) are skipped.
func SharedProfiles() []string {
	set := map[string]bool{}
	cfgFile := firstNonEmptyStr(os.Getenv("AWS_CONFIG_FILE"), awsconfig.DefaultSharedConfigFilename())
	credFile := firstNonEmptyStr(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), awsconfig.DefaultSharedCredentialsFilename())
	for _, f := range []struct {
		path   string
		config bool
	}{{cfgFile, true}, {credFile, false}} {
		fh, err := os.Open(filepath.Clean(f.path))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
				continue
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if f.config {
				switch {
				case name == "default":
				case strings.HasPrefix(name, "profile "):
					name = strings.TrimSpace(strings.TrimPrefix(name, "profile "))
				default:
					continue // sso-session, services, …
				}
			}
			if name != "" {
				set[name] = true
			}
		}
		fh.Close()
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func firstLineStr(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return fmt.Sprint(s)
}
