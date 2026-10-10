package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const acct = "111111111111"

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func tcp(from, to int32, cidrs ...string) ec2types.IpPermission {
	p := ec2types.IpPermission{IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(from), ToPort: awssdk.Int32(to)}
	for _, c := range cidrs {
		p.IpRanges = append(p.IpRanges, ec2types.IpRange{CidrIp: awssdk.String(c)})
	}
	return p
}

func fixture() *fakeAWS {
	running := &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}
	pol := func(doc string) *string { return awssdk.String(doc) }
	return &fakeAWS{
		account: acct,
		instPages: [][]ec2types.Instance{
			{{
				InstanceId: awssdk.String("i-web"), InstanceType: ec2types.InstanceTypeT3Large, State: running, PublicIpAddress: awssdk.String("54.1.1.1"),
				VpcId: awssdk.String("vpc-1"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-open")}},
				IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String("arn:aws:iam::" + acct + ":instance-profile/web")},
				MetadataOptions:    &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateOptional},
				Tags:               []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("web")}, {Key: awssdk.String("env"), Value: awssdk.String("prod")}, {Key: awssdk.String("owner"), Value: awssdk.String("team-a")}},
				LaunchTime:         awssdk.Time(time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC)),
			}},
			{
				{InstanceId: awssdk.String("i-big"), InstanceType: ec2types.InstanceTypeM54xlarge, State: running, SecurityGroups: []ec2types.GroupIdentifier{{GroupId: awssdk.String("sg-private")}},
					MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateRequired}},
				{InstanceId: awssdk.String("i-stop"), InstanceType: ec2types.InstanceTypeT3Micro, State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}},
			},
		},
		sgs: []ec2types.SecurityGroup{
			{GroupId: awssdk.String("sg-open"), GroupName: awssdk.String("open"), VpcId: awssdk.String("vpc-1"), IpPermissions: []ec2types.IpPermission{tcp(22, 22, "0.0.0.0/0"), tcp(443, 443, "10.0.0.0/8")}},
			{GroupId: awssdk.String("sg-private"), GroupName: awssdk.String("private"), VpcId: awssdk.String("vpc-1"), IpPermissions: []ec2types.IpPermission{
				{IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(5432), ToPort: awssdk.Int32(5432), UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: awssdk.String("sg-open")}}}}},
		},
		volumes: []ec2types.Volume{
			{VolumeId: awssdk.String("vol-1"), Size: awssdk.Int32(8), Encrypted: awssdk.Bool(true), State: ec2types.VolumeStateInUse, VolumeType: ec2types.VolumeTypeGp3,
				Attachments: []ec2types.VolumeAttachment{{InstanceId: awssdk.String("i-web"), Device: awssdk.String("/dev/xvda")}}},
			{VolumeId: awssdk.String("vol-2"), Size: awssdk.Int32(100), Encrypted: awssdk.Bool(false), State: ec2types.VolumeStateAvailable, VolumeType: ec2types.VolumeTypeGp2},
		},
		addresses: []ec2types.Address{
			{AllocationId: awssdk.String("eipalloc-1"), PublicIp: awssdk.String("3.3.3.3")},
			{AllocationId: awssdk.String("eipalloc-2"), PublicIp: awssdk.String("4.4.4.4"), AssociationId: awssdk.String("assoc-1")},
		},
		buckets: []fakeBucket{
			{name: "prod-customer-data", aclAllUsers: true, tags: map[string]string{"classification": "pii"}},
			{name: "logs", encrypted: true, pab: &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true), BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true)}, policyPublic: true},
		},
		dbs: []rdstypes.DBInstance{{
			DBInstanceArn: awssdk.String("arn:aws:rds:us-east-1:" + acct + ":db:orders"), DBInstanceIdentifier: awssdk.String("orders"), PubliclyAccessible: awssdk.Bool(true),
			StorageEncrypted: awssdk.Bool(false), VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awssdk.String("sg-open")}},
		}},
		functions: []lambdatypes.FunctionConfiguration{
			{FunctionArn: awssdk.String("arn:aws:lambda:us-east-1:" + acct + ":function:hook"), FunctionName: awssdk.String("hook"), Role: awssdk.String("arn:aws:iam::" + acct + ":role/web-role")},
			{FunctionArn: awssdk.String("arn:aws:lambda:us-east-1:" + acct + ":function:internal"), FunctionName: awssdk.String("internal")},
		},
		urls: map[string]lambdatypes.FunctionUrlConfig{"hook": {FunctionUrl: awssdk.String("https://x.lambda-url.us-east-1.on.aws/"), AuthType: lambdatypes.FunctionUrlAuthTypeNone}},
		clusters: []ekstypes.Cluster{{Name: awssdk.String("c1"), Arn: awssdk.String("arn:aws:eks:us-east-1:" + acct + ":cluster/c1"),
			ResourcesVpcConfig: &ekstypes.VpcConfigResponse{EndpointPublicAccess: true, PublicAccessCidrs: []string{"0.0.0.0/0"}}}},
		secrets: []smtypes.SecretListEntry{{ARN: awssdk.String("arn:aws:secretsmanager:us-east-1:" + acct + ":secret:db-pass"), Name: awssdk.String("db-pass")}},
		keys: []kmstypes.KeyMetadata{
			{KeyId: awssdk.String("k1"), Arn: awssdk.String("arn:aws:kms:us-east-1:" + acct + ":key/k1"), KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled, KeySpec: kmstypes.KeySpecSymmetricDefault},
			{KeyId: awssdk.String("k2"), Arn: awssdk.String("arn:aws:kms:us-east-1:" + acct + ":key/k2"), KeyManager: kmstypes.KeyManagerTypeAws, KeyState: kmstypes.KeyStateEnabled, KeySpec: kmstypes.KeySpecSymmetricDefault},
		},
		rotation: map[string]bool{"k1": false},
		auth: iam.GetAccountAuthorizationDetailsOutput{
			RoleDetailList: []iamtypes.RoleDetail{
				{Arn: awssdk.String("arn:aws:iam::" + acct + ":role/web-role"), RoleName: awssdk.String("web-role"), Path: awssdk.String("/"),
					AssumeRolePolicyDocument: pol(`%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22ec2.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`),
					InstanceProfileList:      []iamtypes.InstanceProfile{{Arn: awssdk.String("arn:aws:iam::" + acct + ":instance-profile/web")}},
					AttachedManagedPolicies:  []iamtypes.AttachedPolicy{{PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AmazonS3FullAccess"), PolicyName: awssdk.String("AmazonS3FullAccess")}},
					RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: awssdk.String("secrets"), PolicyDocument: pol(`{"Statement":{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:` + acct + `:secret:db-*"}}`)}},
				},
				{Arn: awssdk.String("arn:aws:iam::" + acct + ":role/vendor"), RoleName: awssdk.String("vendor"), Path: awssdk.String("/"),
					AssumeRolePolicyDocument: pol(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Action":"sts:AssumeRole"}]}`)},
				{Arn: awssdk.String("arn:aws:iam::" + acct + ":role/aws-service-role/x"), RoleName: awssdk.String("slr"), Path: awssdk.String("/aws-service-role/"),
					AssumeRolePolicyDocument: pol(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::333333333333:root"},"Action":"sts:AssumeRole"}]}`)},
			},
			UserDetailList: []iamtypes.UserDetail{{Arn: awssdk.String("arn:aws:iam::" + acct + ":user/alice"), UserName: awssdk.String("alice"), GroupList: []string{"admins"}}},
			GroupDetailList: []iamtypes.GroupDetail{{Arn: awssdk.String("arn:aws:iam::" + acct + ":group/admins"), GroupName: awssdk.String("admins"),
				AttachedManagedPolicies: []iamtypes.AttachedPolicy{{PolicyArn: awssdk.String("arn:aws:iam::" + acct + ":policy/full"), PolicyName: awssdk.String("full")}}}},
			Policies: []iamtypes.ManagedPolicyDetail{{Arn: awssdk.String("arn:aws:iam::" + acct + ":policy/full"), PolicyName: awssdk.String("full"),
				PolicyVersionList: []iamtypes.PolicyVersion{{IsDefaultVersion: true, Document: pol(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)}}}},
		},
		awsPols: map[string]string{"arn:aws:iam::aws:policy/AmazonS3FullAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","s3-object-lambda:*"],"Resource":"*"}]}`},
		credCSV: "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n" +
			"<root_account>,arn:aws:iam::" + acct + ":root,not_supported,false,false,N/A,N/A,false,N/A,N/A\n" +
			"alice,arn:aws:iam::" + acct + ":user/alice,true,false,true,2025-01-01T00:00:00+00:00,2025-02-01T00:00:00+00:00,true,2026-09-01T00:00:00+00:00,2026-09-30T00:00:00+00:00\n",
		cpu:      map[string]float64{"i-web": 2, "i-big": 10},
		netOutGB: map[string]float64{"i-web": 500},
		fail:     map[string]error{"GetCostAndUsage": apiErr("AccessDeniedException")},
	}
}

func collect(t *testing.T, f *fakeAWS) (core.Result, *graph.Graph) {
	t.Helper()
	g := graph.New()
	c := &Collector{NewClients: f.factory(), Now: func() time.Time { return now }, CredentialReportPoll: time.Millisecond}
	res, err := c.Collect(context.Background(), core.AccountSpec{Name: "prod-main", Provider: "aws", Regions: []string{"us-east-1"}}, g)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return res, g
}

func findStatus(fs []model.Finding, check, resSuffix string) (model.Status, bool) {
	for _, f := range fs {
		if f.CheckID == check && strings.HasSuffix(f.Resource.ID, resSuffix) {
			return f.Status, true
		}
	}
	return "", false
}

func TestCollectFindings(t *testing.T) {
	res, _ := collect(t, fixture())
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	cases := []struct {
		check, res string
		want       model.Status
	}{
		{"s3_bucket_public_access", ":::prod-customer-data", model.Fail},
		{"s3_bucket_public_access", ":::logs", model.Pass},
		{"s3_bucket_default_encryption", ":::prod-customer-data", model.Fail},
		{"s3_bucket_default_encryption", ":::logs", model.Pass},
		{"ec2_instance_imdsv2_enabled", "instance/i-web", model.Fail},
		{"ec2_instance_imdsv2_enabled", "instance/i-big", model.Pass},
		{"ec2_instance_public_ip", "instance/i-web", model.Fail},
		{"ec2_instance_public_ip", "instance/i-big", model.Pass},
		{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "security-group/sg-open", model.Fail},
		{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "security-group/sg-private", model.Pass},
		{"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", "security-group/sg-open", model.Pass},
		{"ec2_securitygroup_allow_ingress_from_internet_to_any_port", "security-group/sg-open", model.Pass},
		{"ec2_ebs_volume_encryption", "volume/vol-1", model.Pass},
		{"ec2_ebs_volume_encryption", "volume/vol-2", model.Fail},
		{"rds_instance_no_public_access", "db:orders", model.Fail},
		{"rds_instance_storage_encrypted", "db:orders", model.Fail},
		{"awslambda_function_url_public", "function:hook", model.Fail},
		{"awslambda_function_url_public", "function:internal", model.Pass},
		{"eks_control_plane_endpoint_access_publicly_accessible", "cluster/c1", model.Fail},
		{"kms_cmk_rotation_enabled", "key/k1", model.Fail},
		{"cloudtrail_multi_region_enabled", "trail/none", model.Fail},
		{"iam_root_mfa_enabled", ":root", model.Fail},
		{"iam_user_mfa_enabled_console_access", "user/alice", model.Fail},
		{"iam_customer_attached_policy_no_administrative_privileges", "policy/full", model.Fail},
		{"iam_aws_attached_policy_no_administrative_privileges", "policy/AmazonS3FullAccess", model.Pass},
		{"iam_inline_policy_no_administrative_privileges", "inline-policy/secrets", model.Pass},
		{"iam_role_cross_account_readonlyaccess_policy", "role/vendor", model.Fail},
		{"iam_role_cross_account_readonlyaccess_policy", "role/web-role", model.Pass},
	}
	for _, tc := range cases {
		t.Run(tc.check+"/"+tc.res, func(t *testing.T) {
			got, ok := findStatus(res.Findings, tc.check, tc.res)
			if !ok {
				t.Fatalf("no finding %s on %s", tc.check, tc.res)
			}
			if got != tc.want {
				t.Fatalf("status = %s, want %s", got, tc.want)
			}
		})
	}
	// Service-linked roles are never evaluated; the AWS-managed KMS key is skipped.
	if _, ok := findStatus(res.Findings, "iam_role_cross_account_readonlyaccess_policy", "role/aws-service-role/x"); ok {
		t.Error("service-linked role should be skipped")
	}
	if _, ok := findStatus(res.Findings, "kms_cmk_rotation_enabled", "key/k2"); ok {
		t.Error("AWS-managed key should be skipped")
	}
	// Key 1 unused since Feb 2025 -> FAIL, key 2 used recently -> PASS.
	var stale, fresh int
	for _, f := range res.Findings {
		if f.CheckID == "iam_user_accesskey_unused" {
			if f.Status == model.Fail {
				stale++
			} else {
				fresh++
			}
		}
	}
	if stale != 1 || fresh != 1 {
		t.Errorf("access key findings stale=%d fresh=%d, want 1/1", stale, fresh)
	}
	for _, f := range res.Findings {
		if f.Source != "nimbus" || f.CanonicalID == "" || f.ID == "" {
			t.Fatalf("finding not enriched/finalized: %+v", f)
		}
		if f.Tags["account_label"] != "prod-main" {
			t.Fatalf("missing account label on %s", f.CheckID)
		}
	}
	if got, _ := findStatus(res.Findings, "s3_bucket_public_access", ":::prod-customer-data"); got == model.Fail {
		for _, f := range res.Findings {
			if f.CheckID == "s3_bucket_public_access" && f.Status == model.Fail && f.CanonicalID != "S3_PUBLIC_BUCKET" {
				t.Errorf("canonical = %s", f.CanonicalID)
			}
		}
	}
	if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, "\n"), "cost explorer") {
		t.Errorf("expected cost explorer warning, got %v", res.Warnings)
	}
}

func hasEdge(g *graph.Graph, from, to, kind string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func TestCollectGraph(t *testing.T) {
	_, g := collect(t, fixture())
	arn := func(kind, id string) string { return "arn:aws:ec2:us-east-1:" + acct + ":" + kind + "/" + id }
	role := "arn:aws:iam::" + acct + ":role/web-role"
	bucket := "arn:aws:s3:::prod-customer-data"
	db := "arn:aws:rds:us-east-1:" + acct + ":db:orders"
	secret := "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:db-pass"
	acctN := core.AccountNodeID("aws", acct)
	edges := []struct{ from, to, kind string }{
		{acctN, arn("instance", "i-web"), graph.EdgeContains},
		{arn("instance", "i-web"), arn("security-group", "sg-open"), graph.EdgeAttachedTo},
		{arn("security-group", "sg-open"), arn("instance", "i-web"), graph.EdgeAllowsTrafficTo},
		{arn("instance", "i-web"), role, graph.EdgeRunsAs},
		{graph.InternetNodeID, arn("instance", "i-web"), graph.EdgeExposes},
		{graph.InternetNodeID, bucket, graph.EdgeExposes},
		{graph.InternetNodeID, db, graph.EdgeExposes},
		{graph.InternetNodeID, "arn:aws:lambda:us-east-1:" + acct + ":function:hook", graph.EdgeExposes},
		{graph.InternetNodeID, "arn:aws:eks:us-east-1:" + acct + ":cluster/c1", graph.EdgeExposes},
		{arn("security-group", "sg-open"), db, graph.EdgeAllowsTrafficTo},
		{arn("security-group", "sg-open"), arn("security-group", "sg-private"), graph.EdgeAllowsTrafficTo},
		{role, "arn:aws:iam::aws:policy/AmazonS3FullAccess", graph.EdgeHasPolicy},
		// P1-IAM: data-store grants run principal -> store (evaluated; permissions_test.go).
		{role, bucket, graph.EdgeGrantsAccessTo},
		{role, "arn:aws:s3:::logs", graph.EdgeGrantsAccessTo},
		{role, secret, graph.EdgeGrantsAccessTo},
		{"arn:aws:iam::" + acct + ":user/alice", db, graph.EdgeGrantsAccessTo},
		{"arn:aws:iam::" + acct + ":user/alice", "arn:aws:iam::" + acct + ":group/admins", graph.EdgeMemberOf},
		{"arn:aws:iam::" + acct + ":group/admins", "arn:aws:iam::" + acct + ":policy/full", graph.EdgeHasPolicy},
		{core.AccountNodeID("aws", "222222222222"), "arn:aws:iam::" + acct + ":role/vendor", graph.EdgeCanAssume},
		{"arn:aws:iam::" + acct + ":role/vendor", core.AccountNodeID("aws", "222222222222"), graph.EdgeTrusts},
		{arn("instance", "i-web"), arn("volume", "vol-1"), graph.EdgeAttachedTo},
		{"arn:aws:lambda:us-east-1:" + acct + ":function:hook", role, graph.EdgeRunsAs},
	}
	for _, e := range edges {
		if !hasEdge(g, e.from, e.to, e.kind) {
			t.Errorf("missing edge %s -[%s]-> %s", e.from, e.kind, e.to)
		}
	}
	negative := []struct{ from, to, kind string }{
		{graph.InternetNodeID, arn("instance", "i-big"), graph.EdgeExposes},
		{graph.InternetNodeID, "arn:aws:s3:::logs", graph.EdgeExposes},
		{"arn:aws:iam::aws:policy/AmazonS3FullAccess", bucket, graph.EdgeGrantsAccessTo},
		{role, db, graph.EdgeGrantsAccessTo},
	}
	for _, e := range negative {
		if hasEdge(g, e.from, e.to, e.kind) {
			t.Errorf("unexpected edge %s -[%s]-> %s", e.from, e.kind, e.to)
		}
	}
	web, _ := g.Node(arn("instance", "i-web"))
	if web.Criticality != "production" || web.Owner != "team-a" || web.ModifiedAt == "" {
		t.Errorf("instance context = %q %q %q", web.Criticality, web.Owner, web.ModifiedAt)
	}
	if !web.HasWeakness("IMDSV1_ENABLED") || len(web.FindingIDs) == 0 {
		t.Errorf("FAIL findings not attached: %v %v", web.Weaknesses, web.FindingIDs)
	}
	for _, id := range []string{bucket, secret, db} {
		n, _ := g.Node(id)
		if !n.Sensitive {
			t.Errorf("%s should be sensitive", id)
		}
	}
	if n, _ := g.Node("arn:aws:s3:::logs"); n.Sensitive {
		t.Error("logs bucket should not be sensitive")
	}
	if n, _ := g.Node(acctN); n.Class != graph.ClassAccount || n.Name != "prod-main" {
		t.Errorf("account node = %+v", n)
	}
}

func TestCollectCostSignals(t *testing.T) {
	res, _ := collect(t, fixture())
	kinds := map[string][]core.CostSignal{}
	for _, c := range res.Cost {
		kinds[c.Kind] = append(kinds[c.Kind], c)
	}
	want := map[string]int{core.KindUnattachedVolume: 1, core.KindUnassociatedIP: 1, core.KindStoppedInstance: 1, core.KindIdleInstance: 1, core.KindOversizedInstance: 1, core.KindPublicEgress: 1}
	for k, n := range want {
		if len(kinds[k]) != n {
			t.Errorf("%s: got %d signals, want %d", k, len(kinds[k]), n)
		}
	}
	if v := kinds[core.KindUnattachedVolume]; len(v) == 1 && (v[0].SizeGB != 100 || v[0].Attributes["volume_type"] != "gp2") {
		t.Errorf("volume signal = %+v", v[0])
	}
	if v := kinds[core.KindIdleInstance]; len(v) == 1 && (!strings.HasSuffix(v[0].ResourceID, "i-web") || v[0].AvgCPU != 2) {
		t.Errorf("idle signal = %+v", v[0])
	}
	if v := kinds[core.KindOversizedInstance]; len(v) == 1 && v[0].InstanceType != "m5.4xlarge" {
		t.Errorf("oversized signal = %+v", v[0])
	}
	if v := kinds[core.KindPublicEgress]; len(v) == 1 && v[0].Attributes["egress_gb"] != 500.0 {
		t.Errorf("egress signal = %+v", v[0])
	}
}

func TestCollectPartialFailure(t *testing.T) {
	f := fixture()
	f.fail["DescribeDBInstances"] = apiErr("Throttling")
	f.fail["ListSecrets"] = errors.New("boom")
	res, _ := collect(t, f)
	if len(res.Errors) != 2 {
		t.Fatalf("errors = %v, want 2", res.Errors)
	}
	if _, ok := findStatus(res.Findings, "rds_instance_no_public_access", "db:orders"); ok {
		t.Error("RDS findings should be absent when RDS failed")
	}
	if _, ok := findStatus(res.Findings, "s3_bucket_public_access", ":::logs"); !ok {
		t.Error("other services must still produce findings")
	}
}

func TestCollectFatal(t *testing.T) {
	f := fixture()
	f.fail["GetCallerIdentity"] = errors.New("no credentials")
	c := &Collector{NewClients: f.factory()}
	if _, err := c.Collect(context.Background(), core.AccountSpec{Provider: "aws"}, graph.New()); err == nil {
		t.Fatal("expected fatal error")
	}
}

func TestCollectCloudTrailPass(t *testing.T) {
	f := fixture()
	f.trails = []fakeTrail{{arn: "arn:aws:cloudtrail:us-east-1:" + acct + ":trail/main", multiRegion: true, logging: true}}
	res, _ := collect(t, f)
	if st, ok := findStatus(res.Findings, "cloudtrail_multi_region_enabled", "trail/main"); !ok || st != model.Pass {
		t.Fatalf("cloudtrail = %v %v", st, ok)
	}
}

func TestSGOpenInfo(t *testing.T) {
	cases := []struct {
		name          string
		perm          ec2types.IpPermission
		ssh, rdp, all bool
	}{
		{"ssh only", tcp(22, 22, "0.0.0.0/0"), true, false, false},
		{"range covers both", tcp(0, 5000, "0.0.0.0/0"), true, true, false},
		{"private cidr", tcp(22, 22, "10.0.0.0/8"), false, false, false},
		{"all protocols", ec2types.IpPermission{IpProtocol: awssdk.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}}}, true, true, true},
		{"ipv6 rdp", ec2types.IpPermission{IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(3389), ToPort: awssdk.Int32(3389), Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}}}, false, true, false},
		{"udp 22 is not ssh", ec2types.IpPermission{IpProtocol: awssdk.String("udp"), FromPort: awssdk.Int32(22), ToPort: awssdk.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}}}, false, false, false},
		{"tcp full range", tcp(0, 65535, "0.0.0.0/0"), true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oi := sgOpenInfo(ec2types.SecurityGroup{IpPermissions: []ec2types.IpPermission{tc.perm}})
			if oi.SSH != tc.ssh || oi.RDP != tc.rdp || oi.All != tc.all {
				t.Fatalf("got ssh=%v rdp=%v all=%v", oi.SSH, oi.RDP, oi.All)
			}
		})
	}
}

func TestIsLargeType(t *testing.T) {
	for typ, want := range map[string]bool{"m5.4xlarge": true, "t3.xlarge": true, "t3.large": false, "c5.metal": true, "weird": false} {
		if got := isLargeType(typ); got != want {
			t.Errorf("isLargeType(%s) = %v", typ, got)
		}
	}
}

func TestParseCredentialReport(t *testing.T) {
	rows, err := ParseCredentialReport([]byte("user,arn,mfa_active\nbob,arn:aws:iam::1:user/bob,true\n"))
	if err != nil || len(rows) != 1 || rows[0]["user"] != "bob" || rows[0]["mfa_active"] != "true" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if _, err := ParseCredentialReport([]byte("a,b\n\"unterminated")); err == nil {
		t.Fatal("expected CSV error")
	}
}

// Defect 15(b): account-level S3 Block Public Access overrides bucket ACLs/policies.
func TestS3AccountLevelBlockPublicAccess(t *testing.T) {
	bucket := "arn:aws:s3:::prod-customer-data" // ACL grants AllUsers, no bucket-level PAB
	all := &AccountPublicAccessBlock{Configured: true, BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true}
	t.Run("all four on at account level is not public", func(t *testing.T) {
		f := fixture()
		f.accountPAB = all
		res, g := collect(t, f)
		if st, _ := findStatus(res.Findings, "s3_bucket_public_access", ":::prod-customer-data"); st != model.Pass {
			t.Fatalf("status = %q, want PASS", st)
		}
		for _, fd := range res.Findings {
			if fd.CheckID == "s3_bucket_public_access" && strings.HasSuffix(fd.Resource.ID, "prod-customer-data") && !strings.Contains(fd.Description, "account level") {
				t.Errorf("evidence must name the account-level setting: %q", fd.Description)
			}
		}
		if hasEdge(g, graph.InternetNodeID, bucket, graph.EdgeExposes) {
			t.Error("bucket blocked at account level must not be internet-exposed")
		}
		n, _ := g.Node(bucket)
		if n.Attributes["public"] != false || n.Attributes["public_access_block_source"] != "account" || n.Attributes["account_public_access_block"] != true {
			t.Errorf("attrs = %v", n.Attributes)
		}
	})
	t.Run("account BlockPublicAcls without IgnorePublicAcls stays public", func(t *testing.T) {
		f := fixture()
		f.accountPAB = &AccountPublicAccessBlock{Configured: true, BlockPublicAcls: true, BlockPublicPolicy: true}
		res, g := collect(t, f)
		if st, _ := findStatus(res.Findings, "s3_bucket_public_access", ":::prod-customer-data"); st != model.Fail {
			t.Fatalf("status = %q, want FAIL", st)
		}
		if !hasEdge(g, graph.InternetNodeID, bucket, graph.EdgeExposes) {
			t.Error("existing public ACL is still honoured without IgnorePublicAcls")
		}
	})
	t.Run("account IgnorePublicAcls neutralises an ACL-only public bucket", func(t *testing.T) {
		f := fixture()
		f.accountPAB = &AccountPublicAccessBlock{Configured: true, IgnorePublicAcls: true}
		res, _ := collect(t, f)
		if st, _ := findStatus(res.Findings, "s3_bucket_public_access", ":::prod-customer-data"); st != model.Pass {
			t.Fatalf("status = %q, want PASS", st)
		}
	})
	t.Run("account PAB unreadable is a coverage error, bucket still evaluated", func(t *testing.T) {
		f := fixture()
		f.fail["GetAccountPublicAccessBlock"] = apiErr("AccessDenied")
		res, _ := collect(t, f)
		ces := res.CollectErrors()
		if len(ces) != 1 || ces[0].Reason != core.ReasonAccessDenied || !strings.Contains(ces[0].API, "s3control") {
			t.Fatalf("collect errors = %+v", ces)
		}
		if st, _ := findStatus(res.Findings, "s3_bucket_public_access", ":::prod-customer-data"); st != model.Fail {
			t.Fatalf("status = %q, want FAIL", st)
		}
	})
}

// O10: SG exposure carries width — 0.0.0.0/0 wide, a public /16 narrow, a corp CIDR
// listed in trusted_cidrs trusted — and Lambda URLs / EKS / RDS / S3 are labelled too.
func TestExposureWidthLabels(t *testing.T) {
	running := &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}
	f := fixture()
	mk := func(id, sg string) ec2types.Instance {
		return ec2types.Instance{InstanceId: awssdk.String(id), InstanceType: ec2types.InstanceTypeT3Micro, State: running, PublicIpAddress: awssdk.String("54.9.9.9"),
			SecurityGroups: []ec2types.GroupIdentifier{{GroupId: awssdk.String(sg)}}, MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateRequired}}
	}
	f.instPages = append(f.instPages, []ec2types.Instance{mk("i-narrow", "sg-narrow"), mk("i-corp", "sg-corp"), mk("i-private", "sg-private")})
	f.sgs = append(f.sgs,
		ec2types.SecurityGroup{GroupId: awssdk.String("sg-narrow"), GroupName: awssdk.String("narrow"), IpPermissions: []ec2types.IpPermission{tcp(443, 443, "52.10.0.0/16")}},
		ec2types.SecurityGroup{GroupId: awssdk.String("sg-corp"), GroupName: awssdk.String("corp"), IpPermissions: []ec2types.IpPermission{tcp(22, 22, "203.0.113.0/24")}},
	)
	f.clusters[0].ResourcesVpcConfig.PublicAccessCidrs = []string{"198.51.100.0/24"}
	g := graph.New()
	c := &Collector{NewClients: f.factory(), Now: func() time.Time { return now }, CredentialReportPoll: time.Millisecond}
	res, err := c.Collect(context.Background(), core.AccountSpec{Name: "prod-main", Provider: "aws", Regions: []string{"us-east-1"}, TrustedCIDRs: []string{"203.0.113.0/24"}}, g)
	if err != nil {
		t.Fatal(err)
	}
	inst := func(id string) string { return "arn:aws:ec2:us-east-1:" + acct + ":instance/" + id }
	attrOf := func(to string) map[string]any {
		for _, e := range g.Out(graph.InternetNodeID) {
			if e.To == to && e.Kind == graph.EdgeExposes {
				return e.Attr
			}
		}
		return nil
	}
	cases := []struct {
		id, width, cidr string
	}{
		{inst("i-web"), core.ExposureWide, "0.0.0.0/0"},
		{inst("i-narrow"), core.ExposureNarrow, "52.10.0.0/16"},
		{inst("i-corp"), core.ExposureTrusted, "203.0.113.0/24"},
		{"arn:aws:lambda:us-east-1:" + acct + ":function:hook", core.ExposureWide, "0.0.0.0/0"},
		{"arn:aws:s3:::prod-customer-data", core.ExposureWide, "0.0.0.0/0"},
		{"arn:aws:eks:us-east-1:" + acct + ":cluster/c1", core.ExposureNarrow, "198.51.100.0/24"},
		{"arn:aws:rds:us-east-1:" + acct + ":db:orders", core.ExposureWide, "0.0.0.0/0"},
	}
	for _, tc := range cases {
		a := attrOf(tc.id)
		if a == nil {
			t.Errorf("%s: not exposed", tc.id)
			continue
		}
		cidrs, _ := a[core.AttrExposureCIDRs].([]string)
		if a[core.AttrExposure] != tc.width || len(cidrs) != 1 || cidrs[0] != tc.cidr {
			t.Errorf("%s: exposure=%v cidrs=%v, want %s %s", tc.id, a[core.AttrExposure], cidrs, tc.width, tc.cidr)
		}
		if n, _ := g.Node(tc.id); n.Attributes[core.AttrExposure] != tc.width {
			t.Errorf("%s: node exposure = %v", tc.id, n.Attributes[core.AttrExposure])
		}
	}
	if attrOf(inst("i-private")) != nil {
		t.Error("SG with only SG-references must not be internet exposed")
	}
	// The CIS "open to the world" findings stay wide-only.
	if st, _ := findStatus(res.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_any_port", "sg-narrow"); st != model.Pass {
		t.Errorf("narrow SG flagged as open to the world: %q", st)
	}
	if st, _ := findStatus(res.Findings, "eks_control_plane_endpoint_access_publicly_accessible", "cluster/c1"); st != model.Pass {
		t.Errorf("EKS restricted to a /24 flagged as public: %q", st)
	}
}
