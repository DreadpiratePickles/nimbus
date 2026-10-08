package aws

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
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
	"github.com/aws/smithy-go"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// inventory is the raw state gathered from all services before analysis.
type inventory struct {
	mu sync.Mutex

	account string

	instances []regional[ec2types.Instance]
	sgs       []regional[ec2types.SecurityGroup]
	volumes   []regional[ec2types.Volume]
	addresses []regional[ec2types.Address]
	dbs       []regional[rdstypes.DBInstance]
	functions []lambdaFn
	clusters  []regional[ekstypes.Cluster]
	secrets   []regional[smtypes.SecretListEntry]
	keys      []kmsKey
	buckets   []bucket

	trails       []cttypes.Trail
	trailLogging map[string]bool
	trailsKnown  bool

	users    []iamtypes.UserDetail
	roles    []iamtypes.RoleDetail
	groups   []iamtypes.GroupDetail
	policies map[string]policyInfo // ARN -> default version document
	iamKnown bool

	credReport []credRow
	rootMFA    *bool

	cpu    map[string]float64 // instance ID -> avg CPU over lookback
	egress map[string]float64 // instance ID -> GB out over 30 days
	spend  map[string]float64 // service -> USD last 30 days
}

type regional[T any] struct {
	Region string
	Item   T
}

type lambdaFn struct {
	Region  string
	Fn      lambdatypes.FunctionConfiguration
	URL     string
	URLAuth string
}

type kmsKey struct {
	Region   string
	ARN      string
	ID       string
	Rotation bool
}

type bucket struct {
	Name        string
	Region      string
	Created     time.Time
	Tags        map[string]string
	PABAll      bool // all four public access block settings on
	PolicyPublic bool
	ACLPublic   bool
	Encrypted   bool
	EncKnown    bool
}

type policyInfo struct {
	ARN, Name string
	AWSManaged bool
	Document   string
}

type credRow map[string]string

func (inv *inventory) lock(f func()) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	f()
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// isAccessDenied matches the many spellings of AWS permission failures.
func isAccessDenied(err error) bool {
	c := strings.ToLower(apiCode(err))
	return strings.Contains(c, "accessdenied") || strings.Contains(c, "unauthorized") || c == "authfailure" || c == "optinrequired"
}

func tagsEC2(ts []ec2types.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		out[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return out
}

func tagsIAM(ts []iamtypes.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range ts {
		out[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return out
}

// ---------------------------------------------------------------- regional fetchers

func fetchEC2(ctx context.Context, c EC2API, region string, inv *inventory) error {
	var errs []error
	ip := ec2.NewDescribeInstancesPaginator(c, &ec2.DescribeInstancesInput{MaxResults: awssdk.Int32(1000)})
	for ip.HasMorePages() {
		out, err := ip.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeInstances: %w", err))
			break
		}
		inv.lock(func() {
			for _, r := range out.Reservations {
				for _, i := range r.Instances {
					if i.State != nil && i.State.Name == ec2types.InstanceStateNameTerminated {
						continue
					}
					inv.instances = append(inv.instances, regional[ec2types.Instance]{region, i})
				}
			}
		})
	}
	sp := ec2.NewDescribeSecurityGroupsPaginator(c, &ec2.DescribeSecurityGroupsInput{MaxResults: awssdk.Int32(1000)})
	for sp.HasMorePages() {
		out, err := sp.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeSecurityGroups: %w", err))
			break
		}
		inv.lock(func() {
			for _, s := range out.SecurityGroups {
				inv.sgs = append(inv.sgs, regional[ec2types.SecurityGroup]{region, s})
			}
		})
	}
	vp := ec2.NewDescribeVolumesPaginator(c, &ec2.DescribeVolumesInput{MaxResults: awssdk.Int32(1000)})
	for vp.HasMorePages() {
		out, err := vp.NextPage(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeVolumes: %w", err))
			break
		}
		inv.lock(func() {
			for _, v := range out.Volumes {
				inv.volumes = append(inv.volumes, regional[ec2types.Volume]{region, v})
			}
		})
	}
	addrs, err := c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		errs = append(errs, fmt.Errorf("DescribeAddresses: %w", err))
	} else {
		inv.lock(func() {
			for _, a := range addrs.Addresses {
				inv.addresses = append(inv.addresses, regional[ec2types.Address]{region, a})
			}
		})
	}
	return errors.Join(errs...)
}

func fetchRDS(ctx context.Context, c RDSAPI, region string, inv *inventory) error {
	p := rds.NewDescribeDBInstancesPaginator(c, &rds.DescribeDBInstancesInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("DescribeDBInstances: %w", err)
		}
		inv.lock(func() {
			for _, d := range out.DBInstances {
				inv.dbs = append(inv.dbs, regional[rdstypes.DBInstance]{region, d})
			}
		})
	}
	return nil
}

func fetchLambda(ctx context.Context, c LambdaAPI, region string, inv *inventory) error {
	var fns []lambdatypes.FunctionConfiguration
	p := lambda.NewListFunctionsPaginator(c, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListFunctions: %w", err)
		}
		fns = append(fns, out.Functions...)
	}
	var errs []error
	for _, fn := range fns {
		rec := lambdaFn{Region: region, Fn: fn}
		up := lambda.NewListFunctionUrlConfigsPaginator(c, &lambda.ListFunctionUrlConfigsInput{FunctionName: fn.FunctionName})
		for up.HasMorePages() {
			out, err := up.NextPage(ctx)
			if err != nil {
				errs = append(errs, fmt.Errorf("ListFunctionUrlConfigs %s: %w", awssdk.ToString(fn.FunctionName), err))
				break
			}
			for _, u := range out.FunctionUrlConfigs {
				rec.URL = awssdk.ToString(u.FunctionUrl)
				rec.URLAuth = string(u.AuthType)
			}
		}
		inv.lock(func() { inv.functions = append(inv.functions, rec) })
	}
	return errors.Join(errs...)
}

func fetchEKS(ctx context.Context, c EKSAPI, region string, inv *inventory) error {
	var names []string
	p := eks.NewListClustersPaginator(c, &eks.ListClustersInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListClusters: %w", err)
		}
		names = append(names, out.Clusters...)
	}
	var errs []error
	for _, n := range names {
		out, err := c.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: awssdk.String(n)})
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeCluster %s: %w", n, err))
			continue
		}
		if out.Cluster != nil {
			inv.lock(func() { inv.clusters = append(inv.clusters, regional[ekstypes.Cluster]{region, *out.Cluster}) })
		}
	}
	return errors.Join(errs...)
}

func fetchSecrets(ctx context.Context, c SecretsAPI, region string, inv *inventory) error {
	p := secretsmanager.NewListSecretsPaginator(c, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListSecrets: %w", err)
		}
		inv.lock(func() {
			for _, s := range out.SecretList {
				inv.secrets = append(inv.secrets, regional[smtypes.SecretListEntry]{region, s})
			}
		})
	}
	return nil
}

func fetchKMS(ctx context.Context, c KMSAPI, region string, inv *inventory) error {
	var errs []error
	p := kms.NewListKeysPaginator(c, &kms.ListKeysInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListKeys: %w", err)
		}
		for _, k := range out.Keys {
			d, err := c.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil {
				errs = append(errs, fmt.Errorf("DescribeKey %s: %w", awssdk.ToString(k.KeyId), err))
				continue
			}
			md := d.KeyMetadata
			if md == nil || md.KeyManager != kmstypes.KeyManagerTypeCustomer || md.KeyState != kmstypes.KeyStateEnabled || md.KeySpec != kmstypes.KeySpecSymmetricDefault {
				continue
			}
			rs, err := c.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			if err != nil {
				errs = append(errs, fmt.Errorf("GetKeyRotationStatus %s: %w", awssdk.ToString(k.KeyId), err))
				continue
			}
			inv.lock(func() {
				inv.keys = append(inv.keys, kmsKey{Region: region, ARN: awssdk.ToString(md.Arn), ID: awssdk.ToString(md.KeyId), Rotation: rs.KeyRotationEnabled})
			})
		}
	}
	return errors.Join(errs...)
}

// fetchMetrics pulls CPU averages for running instances and 30-day NetworkOut for public ones.
func fetchMetrics(ctx context.Context, c CloudWatchAPI, region string, inv *inventory, lookback time.Duration, now time.Time) error {
	inv.mu.Lock()
	var running, public []string
	for _, i := range inv.instances {
		if i.Region != region || i.Item.State == nil || i.Item.State.Name != ec2types.InstanceStateNameRunning {
			continue
		}
		running = append(running, awssdk.ToString(i.Item.InstanceId))
		if i.Item.PublicIpAddress != nil {
			public = append(public, awssdk.ToString(i.Item.InstanceId))
		}
	}
	inv.mu.Unlock()
	var errs []error
	for _, id := range running {
		out, err := c.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
			Namespace: awssdk.String("AWS/EC2"), MetricName: awssdk.String("CPUUtilization"),
			Dimensions: []cwtypes.Dimension{{Name: awssdk.String("InstanceId"), Value: awssdk.String(id)}},
			StartTime:  awssdk.Time(now.Add(-lookback)), EndTime: awssdk.Time(now),
			Period: awssdk.Int32(86400), Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("GetMetricStatistics %s: %w", id, err))
			if isAccessDenied(err) {
				break
			}
			continue
		}
		if len(out.Datapoints) == 0 {
			continue
		}
		var sum float64
		for _, d := range out.Datapoints {
			sum += awssdk.ToFloat64(d.Average)
		}
		avg := sum / float64(len(out.Datapoints))
		inv.lock(func() { inv.cpu[id] = avg })
	}
	for _, id := range public {
		out, err := c.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
			Namespace: awssdk.String("AWS/EC2"), MetricName: awssdk.String("NetworkOut"),
			Dimensions: []cwtypes.Dimension{{Name: awssdk.String("InstanceId"), Value: awssdk.String(id)}},
			StartTime:  awssdk.Time(now.Add(-30 * 24 * time.Hour)), EndTime: awssdk.Time(now),
			Period: awssdk.Int32(86400 * 30), Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("GetMetricStatistics NetworkOut %s: %w", id, err))
			break
		}
		var bytes float64
		for _, d := range out.Datapoints {
			bytes += awssdk.ToFloat64(d.Sum)
		}
		inv.lock(func() { inv.egress[id] = bytes / (1 << 30) })
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------- global fetchers

func fetchIAM(ctx context.Context, c IAMAPI, inv *inventory) error {
	p := iam.NewGetAccountAuthorizationDetailsPaginator(c, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []iamtypes.EntityType{iamtypes.EntityTypeUser, iamtypes.EntityTypeRole, iamtypes.EntityTypeGroup, iamtypes.EntityTypeLocalManagedPolicy},
	})
	policies := map[string]policyInfo{}
	var users []iamtypes.UserDetail
	var roles []iamtypes.RoleDetail
	var groups []iamtypes.GroupDetail
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("GetAccountAuthorizationDetails: %w", err)
		}
		users = append(users, out.UserDetailList...)
		roles = append(roles, out.RoleDetailList...)
		groups = append(groups, out.GroupDetailList...)
		for _, pd := range out.Policies {
			pi := policyInfo{ARN: awssdk.ToString(pd.Arn), Name: awssdk.ToString(pd.PolicyName)}
			for _, v := range pd.PolicyVersionList {
				if v.IsDefaultVersion {
					pi.Document = awssdk.ToString(v.Document)
				}
			}
			policies[pi.ARN] = pi
		}
	}
	// AWS-managed policies are not returned for the local filter: resolve the attached ones.
	attached := map[string]string{}
	add := func(aps []iamtypes.AttachedPolicy) {
		for _, ap := range aps {
			arn := awssdk.ToString(ap.PolicyArn)
			if _, ok := policies[arn]; !ok && strings.Contains(arn, ":aws:policy/") {
				attached[arn] = awssdk.ToString(ap.PolicyName)
			}
		}
	}
	for _, u := range users {
		add(u.AttachedManagedPolicies)
	}
	for _, r := range roles {
		add(r.AttachedManagedPolicies)
	}
	for _, g := range groups {
		add(g.AttachedManagedPolicies)
	}
	var errs []error
	var pmu sync.Mutex
	var tasks []core.Task
	for _, arn := range core.SortedKeys(attached) {
		tasks = append(tasks, core.Task{Name: "iam:GetPolicy " + arn, Fn: func(ctx context.Context) error {
			gp, err := c.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awssdk.String(arn)})
			if err != nil {
				return err
			}
			pv, err := c.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: awssdk.String(arn), VersionId: gp.Policy.DefaultVersionId})
			if err != nil {
				return err
			}
			pmu.Lock()
			policies[arn] = policyInfo{ARN: arn, Name: attached[arn], AWSManaged: true, Document: awssdk.ToString(pv.PolicyVersion.Document)}
			pmu.Unlock()
			return nil
		}})
	}
	var acc core.Acc
	core.RunTasks(ctx, 8, &acc, tasks)
	errs = append(errs, acc.Result().Errors...)
	for arn, name := range attached {
		if _, ok := policies[arn]; !ok {
			policies[arn] = policyInfo{ARN: arn, Name: name, AWSManaged: true}
		}
	}
	inv.lock(func() {
		inv.users, inv.roles, inv.groups, inv.policies, inv.iamKnown = users, roles, groups, policies, true
	})
	return errors.Join(errs...)
}

func fetchAccountSummary(ctx context.Context, c IAMAPI, inv *inventory) error {
	out, err := c.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return fmt.Errorf("GetAccountSummary: %w", err)
	}
	v := out.SummaryMap["AccountMFAEnabled"] == 1
	inv.lock(func() { inv.rootMFA = &v })
	return nil
}

func fetchCredentialReport(ctx context.Context, c IAMAPI, inv *inventory, poll time.Duration) error {
	for i := 0; i < 15; i++ {
		g, err := c.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return fmt.Errorf("GenerateCredentialReport: %w", err)
		}
		if g.State == iamtypes.ReportStateTypeComplete {
			break
		}
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	out, err := c.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return fmt.Errorf("GetCredentialReport: %w", err)
	}
	rows, err := ParseCredentialReport(out.Content)
	if err != nil {
		return err
	}
	inv.lock(func() { inv.credReport = rows })
	return nil
}

// ParseCredentialReport decodes the IAM credential report CSV into header-keyed rows.
func ParseCredentialReport(content []byte) ([]credRow, error) {
	r := csv.NewReader(strings.NewReader(string(content)))
	recs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("credential report: %w", err)
	}
	if len(recs) == 0 {
		return nil, nil
	}
	hdr := recs[0]
	var out []credRow
	for _, rec := range recs[1:] {
		row := credRow{}
		for i, h := range hdr {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func fetchS3(ctx context.Context, c S3API, inv *inventory, concurrency int) error {
	var list []s3types.Bucket
	p := s3.NewListBucketsPaginator(c, &s3.ListBucketsInput{MaxBuckets: awssdk.Int32(1000)})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("ListBuckets: %w", err)
		}
		list = append(list, out.Buckets...)
	}
	var acc core.Acc
	var tasks []core.Task
	for _, b := range list {
		tasks = append(tasks, core.Task{Name: "s3:" + awssdk.ToString(b.Name), Fn: func(ctx context.Context) error {
			bk, err := describeBucket(ctx, c, b)
			inv.lock(func() { inv.buckets = append(inv.buckets, bk) })
			return err
		}})
	}
	core.RunTasks(ctx, concurrency, &acc, tasks)
	return acc.Result().Err()
}

func describeBucket(ctx context.Context, c S3API, b s3types.Bucket) (bucket, error) {
	name := awssdk.ToString(b.Name)
	region := awssdk.ToString(b.BucketRegion)
	if region == "" {
		region = core.DefaultAWSRegion
	}
	bk := bucket{Name: name, Region: region, Tags: map[string]string{}}
	if b.CreationDate != nil {
		bk.Created = *b.CreationDate
	}
	inRegion := func(o *s3.Options) { o.Region = region }
	var errs []error
	if pab, err := c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: b.Name}, inRegion); err == nil && pab.PublicAccessBlockConfiguration != nil {
		cfg := pab.PublicAccessBlockConfiguration
		bk.PABAll = awssdk.ToBool(cfg.BlockPublicAcls) && awssdk.ToBool(cfg.IgnorePublicAcls) && awssdk.ToBool(cfg.BlockPublicPolicy) && awssdk.ToBool(cfg.RestrictPublicBuckets)
	} else if err != nil && apiCode(err) != "NoSuchPublicAccessBlockConfiguration" {
		errs = append(errs, fmt.Errorf("GetPublicAccessBlock: %w", err))
	}
	if ps, err := c.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: b.Name}, inRegion); err == nil && ps.PolicyStatus != nil {
		bk.PolicyPublic = awssdk.ToBool(ps.PolicyStatus.IsPublic)
	} else if err != nil && apiCode(err) != "NoSuchBucketPolicy" {
		errs = append(errs, fmt.Errorf("GetBucketPolicyStatus: %w", err))
	}
	if acl, err := c.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: b.Name}, inRegion); err == nil {
		for _, g := range acl.Grants {
			if g.Grantee != nil && g.Grantee.Type == s3types.TypeGroup {
				uri := awssdk.ToString(g.Grantee.URI)
				if strings.HasSuffix(uri, "/global/AllUsers") || strings.HasSuffix(uri, "/global/AuthenticatedUsers") {
					bk.ACLPublic = true
				}
			}
		}
	} else {
		errs = append(errs, fmt.Errorf("GetBucketAcl: %w", err))
	}
	if enc, err := c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name}, inRegion); err == nil {
		bk.EncKnown = true
		bk.Encrypted = enc.ServerSideEncryptionConfiguration != nil && len(enc.ServerSideEncryptionConfiguration.Rules) > 0
	} else if apiCode(err) == "ServerSideEncryptionConfigurationNotFoundError" {
		bk.EncKnown = true
	} else {
		errs = append(errs, fmt.Errorf("GetBucketEncryption: %w", err))
	}
	if tg, err := c.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: b.Name}, inRegion); err == nil {
		for _, t := range tg.TagSet {
			bk.Tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
		}
	} else if apiCode(err) != "NoSuchTagSet" {
		errs = append(errs, fmt.Errorf("GetBucketTagging: %w", err))
	}
	return bk, errors.Join(errs...)
}

func fetchCloudTrail(ctx context.Context, c CloudTrailAPI, inv *inventory) error {
	out, err := c.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: awssdk.Bool(true)})
	if err != nil {
		return fmt.Errorf("DescribeTrails: %w", err)
	}
	logging := map[string]bool{}
	var errs []error
	for _, t := range out.TrailList {
		arn := awssdk.ToString(t.TrailARN)
		st, err := c.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			errs = append(errs, fmt.Errorf("GetTrailStatus %s: %w", arn, err))
			continue
		}
		logging[arn] = awssdk.ToBool(st.IsLogging)
	}
	inv.lock(func() { inv.trails, inv.trailLogging, inv.trailsKnown = out.TrailList, logging, true })
	return errors.Join(errs...)
}

// fetchSpend records last-30-day unblended cost per service. Missing ce:GetCostAndUsage
// permission is expected in many audit roles, so the caller turns it into a warning.
func fetchSpend(ctx context.Context, c CostExplorerAPI, inv *inventory, now time.Time) error {
	start := now.AddDate(0, 0, -30).Format("2006-01-02")
	end := now.Format("2006-01-02")
	in := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  &cetypes.DateInterval{Start: awssdk.String(start), End: awssdk.String(end)},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy:     []cetypes.GroupDefinition{{Type: cetypes.GroupDefinitionTypeDimension, Key: awssdk.String("SERVICE")}},
	}
	spend := map[string]float64{}
	for page := 0; page < 50; page++ {
		out, err := c.GetCostAndUsage(ctx, in)
		if err != nil {
			return err
		}
		for _, r := range out.ResultsByTime {
			for _, g := range r.Groups {
				if len(g.Keys) == 0 {
					continue
				}
				if m, ok := g.Metrics["UnblendedCost"]; ok {
					var v float64
					fmt.Sscanf(awssdk.ToString(m.Amount), "%g", &v)
					spend[g.Keys[0]] += v
				}
			}
		}
		if out.NextPageToken == nil {
			break
		}
		in.NextPageToken = out.NextPageToken
	}
	inv.lock(func() { inv.spend = spend })
	return nil
}
