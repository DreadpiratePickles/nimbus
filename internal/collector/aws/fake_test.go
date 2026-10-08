package aws

import (
	"context"
	"errors"
	"net/url"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// fakeAWS implements every narrow interface with canned single-region data.
type fakeAWS struct {
	account   string
	fail      map[string]error // operation name -> error
	instPages [][]ec2types.Instance
	sgs       []ec2types.SecurityGroup
	volumes   []ec2types.Volume
	addresses []ec2types.Address
	buckets   []fakeBucket
	dbs       []rdstypes.DBInstance
	functions []lambdatypes.FunctionConfiguration
	urls      map[string]lambdatypes.FunctionUrlConfig
	clusters  []ekstypes.Cluster
	secrets   []smtypes.SecretListEntry
	keys      []kmstypes.KeyMetadata
	rotation  map[string]bool
	trails    []fakeTrail
	auth      iam.GetAccountAuthorizationDetailsOutput
	awsPols   map[string]string // AWS managed policy ARN -> document
	rootMFA   bool
	credCSV   string
	cpu       map[string]float64
	netOutGB  map[string]float64
}

type fakeBucket struct {
	name         string
	pab          *s3types.PublicAccessBlockConfiguration
	policyPublic bool
	aclAllUsers  bool
	encrypted    bool
	tags         map[string]string
}

type fakeTrail struct {
	arn         string
	multiRegion bool
	logging     bool
}

func (f *fakeAWS) err(op string) error {
	if f.fail == nil {
		return nil
	}
	return f.fail[op]
}

func apiErr(code string) error { return &smithy.GenericAPIError{Code: code, Message: code} }

// EC2
func (f *fakeAWS) DescribeInstances(_ context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if err := f.err("DescribeInstances"); err != nil {
		return nil, err
	}
	page := 0
	if in.NextToken != nil {
		page = int((*in.NextToken)[0] - '0')
	}
	if page >= len(f.instPages) {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	out := &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: f.instPages[page]}}}
	if page+1 < len(f.instPages) {
		out.NextToken = awssdk.String(string(rune('0' + page + 1)))
	}
	return out, nil
}
func (f *fakeAWS) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.sgs}, f.err("DescribeSecurityGroups")
}
func (f *fakeAWS) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, f.err("DescribeVolumes")
}
func (f *fakeAWS) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: f.addresses}, f.err("DescribeAddresses")
}
func (f *fakeAWS) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{{RegionName: awssdk.String("us-east-1")}}}, f.err("DescribeRegions")
}

// S3
func (f *fakeAWS) bucket(name *string) *fakeBucket {
	for i := range f.buckets {
		if f.buckets[i].name == awssdk.ToString(name) {
			return &f.buckets[i]
		}
	}
	return nil
}
func (f *fakeAWS) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if err := f.err("ListBuckets"); err != nil {
		return nil, err
	}
	out := &s3.ListBucketsOutput{}
	for _, b := range f.buckets {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: awssdk.String(b.name), BucketRegion: awssdk.String("us-east-1"), CreationDate: awssdk.Time(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))})
	}
	return out, nil
}
func (f *fakeAWS) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	b := f.bucket(in.Bucket)
	if b.pab == nil {
		return nil, apiErr("NoSuchPublicAccessBlockConfiguration")
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: b.pab}, nil
}
func (f *fakeAWS) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	b := f.bucket(in.Bucket)
	if !b.policyPublic {
		return nil, apiErr("NoSuchBucketPolicy")
	}
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(true)}}, nil
}
func (f *fakeAWS) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, _ ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	out := &s3.GetBucketAclOutput{}
	if f.bucket(in.Bucket).aclAllUsers {
		out.Grants = []s3types.Grant{{Grantee: &s3types.Grantee{Type: s3types.TypeGroup, URI: awssdk.String("http://acs.amazonaws.com/groups/global/AllUsers")}, Permission: s3types.PermissionRead}}
	}
	return out, nil
}
func (f *fakeAWS) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if !f.bucket(in.Bucket).encrypted {
		return nil, apiErr("ServerSideEncryptionConfigurationNotFoundError")
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{Rules: []s3types.ServerSideEncryptionRule{{}}}}, nil
}
func (f *fakeAWS) GetBucketTagging(_ context.Context, in *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	b := f.bucket(in.Bucket)
	if len(b.tags) == 0 {
		return nil, apiErr("NoSuchTagSet")
	}
	out := &s3.GetBucketTaggingOutput{}
	for k, v := range b.tags {
		out.TagSet = append(out.TagSet, s3types.Tag{Key: awssdk.String(k), Value: awssdk.String(v)})
	}
	return out, nil
}

// IAM
func (f *fakeAWS) GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if err := f.err("GetAccountAuthorizationDetails"); err != nil {
		return nil, err
	}
	out := f.auth
	return &out, nil
}
func (f *fakeAWS) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	v := int32(0)
	if f.rootMFA {
		v = 1
	}
	return &iam.GetAccountSummaryOutput{SummaryMap: map[string]int32{"AccountMFAEnabled": v}}, nil
}
func (f *fakeAWS) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeComplete}, nil
}
func (f *fakeAWS) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{Content: []byte(f.credCSV)}, nil
}
func (f *fakeAWS) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if _, ok := f.awsPols[awssdk.ToString(in.PolicyArn)]; !ok {
		return nil, apiErr("NoSuchEntity")
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{Arn: in.PolicyArn, DefaultVersionId: awssdk.String("v1")}}, nil
}
func (f *fakeAWS) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(url.QueryEscape(f.awsPols[awssdk.ToString(in.PolicyArn)]))}}, nil
}

// RDS / STS / Lambda / EKS / Secrets
func (f *fakeAWS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.dbs}, f.err("DescribeDBInstances")
}
func (f *fakeAWS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if err := f.err("GetCallerIdentity"); err != nil {
		return nil, err
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(f.account)}, nil
}
func (f *fakeAWS) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: f.functions}, f.err("ListFunctions")
}
func (f *fakeAWS) ListFunctionUrlConfigs(_ context.Context, in *lambda.ListFunctionUrlConfigsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error) {
	out := &lambda.ListFunctionUrlConfigsOutput{}
	if u, ok := f.urls[awssdk.ToString(in.FunctionName)]; ok {
		out.FunctionUrlConfigs = []lambdatypes.FunctionUrlConfig{u}
	}
	return out, nil
}
func (f *fakeAWS) ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	out := &eks.ListClustersOutput{}
	for _, c := range f.clusters {
		out.Clusters = append(out.Clusters, awssdk.ToString(c.Name))
	}
	return out, f.err("ListClusters")
}
func (f *fakeAWS) DescribeCluster(_ context.Context, in *eks.DescribeClusterInput, _ ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	for _, c := range f.clusters {
		if awssdk.ToString(c.Name) == awssdk.ToString(in.Name) {
			c := c
			return &eks.DescribeClusterOutput{Cluster: &c}, nil
		}
	}
	return nil, apiErr("ResourceNotFoundException")
}
func (f *fakeAWS) ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return &secretsmanager.ListSecretsOutput{SecretList: f.secrets}, f.err("ListSecrets")
}

// CloudWatch / Cost Explorer / CloudTrail / KMS
func (f *fakeAWS) GetMetricStatistics(_ context.Context, in *cloudwatch.GetMetricStatisticsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	id := awssdk.ToString(in.Dimensions[0].Value)
	if awssdk.ToString(in.MetricName) == "NetworkOut" {
		gb, ok := f.netOutGB[id]
		if !ok {
			return &cloudwatch.GetMetricStatisticsOutput{}, nil
		}
		return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: awssdk.Float64(gb * (1 << 30))}}}, nil
	}
	v, ok := f.cpu[id]
	if !ok {
		return &cloudwatch.GetMetricStatisticsOutput{}, nil
	}
	return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: awssdk.Float64(v)}, {Average: awssdk.Float64(v)}}}, nil
}
func (f *fakeAWS) GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	if err := f.err("GetCostAndUsage"); err != nil {
		return nil, err
	}
	return &costexplorer.GetCostAndUsageOutput{}, nil
}
func (f *fakeAWS) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	out := &cloudtrail.DescribeTrailsOutput{}
	for _, t := range f.trails {
		out.TrailList = append(out.TrailList, cttypesTrail(t))
	}
	return out, f.err("DescribeTrails")
}
func (f *fakeAWS) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	for _, t := range f.trails {
		if t.arn == awssdk.ToString(in.Name) {
			return &cloudtrail.GetTrailStatusOutput{IsLogging: awssdk.Bool(t.logging)}, nil
		}
	}
	return nil, errors.New("no trail")
}
func (f *fakeAWS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	out := &kms.ListKeysOutput{}
	for _, k := range f.keys {
		out.Keys = append(out.Keys, kmstypes.KeyListEntry{KeyId: k.KeyId, KeyArn: k.Arn})
	}
	return out, f.err("ListKeys")
}
func (f *fakeAWS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	for _, k := range f.keys {
		if awssdk.ToString(k.KeyId) == awssdk.ToString(in.KeyId) {
			k := k
			return &kms.DescribeKeyOutput{KeyMetadata: &k}, nil
		}
	}
	return nil, apiErr("NotFoundException")
}
func (f *fakeAWS) GetKeyRotationStatus(_ context.Context, in *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation[awssdk.ToString(in.KeyId)]}, nil
}

func (f *fakeAWS) clients() *Clients {
	return &Clients{EC2: f, S3: f, IAM: f, RDS: f, STS: f, Lambda: f, EKS: f, Secrets: f, CloudWatch: f, CostExplorer: f, CloudTrail: f, KMS: f}
}

func (f *fakeAWS) factory() ClientFactory {
	return func(context.Context, core.AccountSpec, string) (*Clients, error) { return f.clients(), nil }
}

func cttypesTrail(t fakeTrail) cttypes.Trail {
	return cttypes.Trail{TrailARN: awssdk.String(t.arn), Name: awssdk.String(lastSeg(t.arn)), IsMultiRegionTrail: awssdk.Bool(t.multiRegion), HomeRegion: awssdk.String("us-east-1")}
}
