package aws

import (
	"context"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// Narrow per-service interfaces. The SDK clients satisfy them, and they embed the
// SDK paginator interfaces so the official paginators drive the fakes in tests too.

type EC2API interface {
	ec2.DescribeInstancesAPIClient
	ec2.DescribeSecurityGroupsAPIClient
	ec2.DescribeVolumesAPIClient
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

type S3API interface {
	s3.ListBucketsAPIClient
	GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error)
	GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketTagging(context.Context, *s3.GetBucketTaggingInput, ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
}

type IAMAPI interface {
	iam.GetAccountAuthorizationDetailsAPIClient
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type RDSAPI interface {
	rds.DescribeDBInstancesAPIClient
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type LambdaAPI interface {
	lambda.ListFunctionsAPIClient
	lambda.ListFunctionUrlConfigsAPIClient
}

type EKSAPI interface {
	eks.ListClustersAPIClient
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

type SecretsAPI interface {
	secretsmanager.ListSecretsAPIClient
}

type CloudWatchAPI interface {
	GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

type CostExplorerAPI interface {
	GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

type CloudTrailAPI interface {
	DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

type KMSAPI interface {
	kms.ListKeysAPIClient
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// Clients is the set of service clients for one region. Global services
// (IAM, S3 listing, STS, Cost Explorer) are taken from the home-region set.
type Clients struct {
	EC2          EC2API
	S3           S3API
	IAM          IAMAPI
	RDS          RDSAPI
	STS          STSAPI
	Lambda       LambdaAPI
	EKS          EKSAPI
	Secrets      SecretsAPI
	CloudWatch   CloudWatchAPI
	CostExplorer CostExplorerAPI
	CloudTrail   CloudTrailAPI
	KMS          KMSAPI
}

// ClientFactory builds the clients for a region.
type ClientFactory func(ctx context.Context, spec core.AccountSpec, region string) (*Clients, error)

// SDKClientFactory loads credentials once per spec (profile + optional AssumeRole,
// adaptive retryer) and returns real SDK clients per region.
func SDKClientFactory() ClientFactory {
	var (
		mu   sync.Mutex
		base = map[string]awssdk.Config{}
	)
	return func(ctx context.Context, spec core.AccountSpec, region string) (*Clients, error) {
		key := spec.Profile + "|" + spec.RoleARN
		mu.Lock()
		cfg, ok := base[key]
		mu.Unlock()
		if !ok {
			var err error
			cfg, err = core.AWSConfig(ctx, spec, core.DefaultAWSRegion)
			if err != nil {
				return nil, err
			}
			mu.Lock()
			base[key] = cfg
			mu.Unlock()
		}
		c := cfg.Copy()
		c.Region = region
		return &Clients{
			EC2:          ec2.NewFromConfig(c),
			S3:           s3.NewFromConfig(c),
			IAM:          iam.NewFromConfig(c),
			RDS:          rds.NewFromConfig(c),
			STS:          sts.NewFromConfig(c),
			Lambda:       lambda.NewFromConfig(c),
			EKS:          eks.NewFromConfig(c),
			Secrets:      secretsmanager.NewFromConfig(c),
			CloudWatch:   cloudwatch.NewFromConfig(c),
			CostExplorer: costexplorer.NewFromConfig(c),
			CloudTrail:   cloudtrail.NewFromConfig(c),
			KMS:          kms.NewFromConfig(c),
		}, nil
	}
}
