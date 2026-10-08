package core

import (
	"context"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"google.golang.org/api/option"
)

// DefaultAWSRegion is used for global services and region discovery.
const DefaultAWSRegion = "us-east-1"

// AWSConfig loads SDK config for the spec: shared profile, optional role assumption
// (cross-account audit role), adaptive retries with 8 attempts.
func AWSConfig(ctx context.Context, spec AccountSpec, region string) (aws.Config, error) {
	if region == "" {
		region = DefaultAWSRegion
	}
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
		awsconfig.WithRetryMode(aws.RetryModeAdaptive),
		awsconfig.WithRetryMaxAttempts(8),
	}
	if spec.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(spec.Profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	if spec.RoleARN != "" {
		prov := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), spec.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "nimbus-cloud-posture"
		})
		cfg.Credentials = aws.NewCredentialsCache(prov)
	}
	return cfg, nil
}

// AzureCredential returns DefaultAzureCredential (env, workload identity, managed identity, az CLI).
func AzureCredential(spec AccountSpec) (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: spec.TenantID})
}

// GCPOptions returns client options: a service-account key file named by the
// env var in spec.TokenEnv when set, otherwise Application Default Credentials.
func GCPOptions(spec AccountSpec) []option.ClientOption {
	opts := []option.ClientOption{option.WithUserAgent("cloud-posture/0.1")}
	if spec.TokenEnv != "" {
		if path := os.Getenv(spec.TokenEnv); path != "" {
			opts = append(opts, option.WithAuthCredentialsFile(option.ServiceAccount, path))
		}
	}
	return opts
}

// Token reads a secret from spec.TokenEnv, falling back to the default env var name.
func Token(spec AccountSpec, defaultEnv string) string {
	if spec.TokenEnv != "" {
		if v := os.Getenv(spec.TokenEnv); v != "" {
			return v
		}
	}
	return os.Getenv(defaultEnv)
}
