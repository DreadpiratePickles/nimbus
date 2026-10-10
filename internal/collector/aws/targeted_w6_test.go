package aws

import (
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-VERIFY (r4 #8): targeted readers beyond S3 / EC2 / SG / IAM role — RDS, Lambda (URL auth +
// role), EKS endpoint, IAM user (MFA / keys / policies) — each re-reads only its resource and one
// hop, through the same analyze code as a full scan, and confirms a fix (Orca rescan-on-close,
// Prowler partial re-check).

const (
	tRDS    = "arn:aws:rds:us-east-1:" + acct + ":db:orders"
	tLambda = "arn:aws:lambda:us-east-1:" + acct + ":function:hook"
	tEKS    = "arn:aws:eks:us-east-1:" + acct + ":cluster/c1"
	tUser   = "arn:aws:iam::" + acct + ":user/alice"
)

// w6Fixture is targetFixture with the services one reader needs allowed again.
func w6Fixture(allow ...string) *fakeAWS {
	f := targetFixture()
	for _, op := range allow {
		delete(f.fail, op)
	}
	return f
}

func onlyNear(t *testing.T, fs []model.Finding, far ...string) {
	t.Helper()
	for _, fd := range fs {
		for _, x := range far {
			if strings.Contains(fd.Resource.ID, x) {
				t.Errorf("targeted read returned a resource more than one hop away: %s %s", fd.CheckID, fd.Resource.ID)
			}
		}
	}
}

func TestTargetRDSPublicThenPrivate(t *testing.T) {
	f := w6Fixture("DescribeDBInstances")
	r := target(t, f, tRDS)
	if r.Inconclusive() {
		t.Fatalf("RDS read inconclusive: errors %v unsupported %v", r.Errors, r.Unsupported)
	}
	if st, ok := statusOf(r.Findings, "rds_instance_no_public_access", tRDS); !ok || st != model.Fail {
		t.Fatalf("public DB: rds_instance_no_public_access = %q (%v)", st, ok)
	}
	if _, ok := r.Graph.Node(tSG); !ok {
		t.Errorf("fragment lacks the DB's security group (one hop)")
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tRDS, graph.EdgeExposes) {
		t.Errorf("public DB behind an open SG is not exposed in the fragment")
	}
	if len(r.Observed) != 1 || r.Observed[0] != tRDS {
		t.Errorf("observed = %v", r.Observed)
	}
	onlyNear(t, r.Findings, "s3:::", "function:", "cluster/", "i-big")

	f.dbs[0].PubliclyAccessible = awssdk.Bool(false)
	r = target(t, f, tRDS)
	if st, ok := statusOf(r.Findings, "rds_instance_no_public_access", tRDS); !ok || st != model.Pass {
		t.Fatalf("private DB: rds_instance_no_public_access = %q (%v)", st, ok)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tRDS, graph.EdgeExposes) {
		t.Errorf("private DB still exposed")
	}

	gone := "arn:aws:rds:us-east-1:" + acct + ":db:deleted"
	r = target(t, f, gone)
	if len(r.Missing) != 1 || r.Missing[0] != gone || r.Inconclusive() {
		t.Errorf("deleted DB: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	f.fail["DescribeDBInstances"] = apiErr("AccessDenied")
	r = target(t, f, tRDS)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied DescribeDBInstances must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestTargetLambdaURLAuthAndRole(t *testing.T) {
	f := w6Fixture("ListFunctions")
	r := target(t, f, tLambda)
	if r.Inconclusive() {
		t.Fatalf("Lambda read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := statusOf(r.Findings, "awslambda_function_url_public", tLambda); !ok || st != model.Fail {
		t.Fatalf("public URL: awslambda_function_url_public = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tLambda, graph.EdgeExposes) {
		t.Errorf("AuthType NONE URL not exposed in the fragment")
	}
	if !hasEdge(r.Graph, tLambda, tRole, graph.EdgeRunsAs) {
		t.Errorf("fragment lacks the function's execution role (one hop)")
	}
	onlyNear(t, r.Findings, "function:internal", "s3:::", "db:orders", "cluster/")

	// The owner switches the URL to AWS_IAM: PASS and no exposure.
	f.urls["hook"] = lambdatypes.FunctionUrlConfig{FunctionUrl: awssdk.String("https://x.lambda-url.us-east-1.on.aws/"), AuthType: lambdatypes.FunctionUrlAuthTypeAwsIam}
	r = target(t, f, tLambda)
	if st, _ := statusOf(r.Findings, "awslambda_function_url_public", tLambda); st != model.Pass {
		t.Fatalf("AWS_IAM URL = %q, want PASS", st)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tLambda, graph.EdgeExposes) {
		t.Errorf("AWS_IAM URL still exposed")
	}
	// The role is replaced (one hop follows the new role).
	f.functions[0].Role = awssdk.String("arn:aws:iam::" + acct + ":role/vendor")
	r = target(t, f, tLambda)
	if hasEdge(r.Graph, tLambda, tRole, graph.EdgeRunsAs) || !hasEdge(r.Graph, tLambda, "arn:aws:iam::"+acct+":role/vendor", graph.EdgeRunsAs) {
		t.Errorf("role change not reflected in the fragment")
	}

	r = target(t, f, "arn:aws:lambda:us-east-1:"+acct+":function:deleted")
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted function: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
}

func TestTargetEKSEndpoint(t *testing.T) {
	f := w6Fixture()
	r := target(t, f, tEKS)
	if r.Inconclusive() {
		t.Fatalf("EKS read inconclusive (ListClusters must not be needed): %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := statusOf(r.Findings, "eks_control_plane_endpoint_access_publicly_accessible", tEKS); !ok || st != model.Fail {
		t.Fatalf("public endpoint = %q (%v)", st, ok)
	}
	f.clusters[0].ResourcesVpcConfig = &ekstypes.VpcConfigResponse{EndpointPublicAccess: true, PublicAccessCidrs: []string{"203.0.113.0/24"}}
	r = target(t, f, tEKS)
	if st, _ := statusOf(r.Findings, "eks_control_plane_endpoint_access_publicly_accessible", tEKS); st != model.Pass {
		t.Fatalf("restricted endpoint = %q, want PASS", st)
	}
	f.clusters[0].ResourcesVpcConfig = &ekstypes.VpcConfigResponse{EndpointPublicAccess: false, EndpointPrivateAccess: true}
	r = target(t, f, tEKS)
	if hasEdge(r.Graph, graph.InternetNodeID, tEKS, graph.EdgeExposes) {
		t.Errorf("private endpoint still exposed")
	}
	r = target(t, f, "arn:aws:eks:us-east-1:"+acct+":cluster/gone")
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted cluster: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
}

func TestTargetIAMUserMFAKeysPolicies(t *testing.T) {
	f := w6Fixture()
	r := target(t, f, tUser)
	if r.Inconclusive() {
		t.Fatalf("IAM user read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := statusOf(r.Findings, "iam_user_mfa_enabled_console_access", tUser); !ok || st != model.Fail {
		t.Fatalf("console user without MFA = %q (%v)", st, ok)
	}
	stale := 0
	for _, fd := range r.Findings {
		if fd.CheckID == "iam_user_accesskey_unused" && fd.Resource.ID == tUser && fd.Status == model.Fail {
			stale++
		}
	}
	if stale != 1 {
		t.Errorf("stale access keys FAIL = %d, want 1 (key 1 unused since February)", stale)
	}
	if _, ok := r.Graph.Node("arn:aws:iam::" + acct + ":group/admins"); !ok {
		t.Errorf("fragment lacks the user's group (one hop)")
	}
	onlyNear(t, r.Findings, "s3:::", "db:orders", "instance/")

	// MFA added, key 1 deactivated, group membership (admin policy) removed.
	f.credCSV = "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n" +
		"alice," + tUser + ",true,true,false,N/A,N/A,true,2026-09-01T00:00:00+00:00,2026-09-30T00:00:00+00:00\n"
	f.auth.UserDetailList[0].GroupList = nil
	r = target(t, f, tUser)
	if st, _ := statusOf(r.Findings, "iam_user_mfa_enabled_console_access", tUser); st != model.Pass {
		t.Errorf("MFA added = %q, want PASS", st)
	}
	for _, fd := range r.Findings {
		if fd.CheckID == "iam_user_accesskey_unused" && fd.Status == model.Fail {
			t.Errorf("deactivated key still FAIL: %v", fd.Resource.Attributes)
		}
	}
	if hasEdge(r.Graph, tUser, "arn:aws:iam::"+acct+":group/admins", graph.EdgeMemberOf) {
		t.Errorf("removed group membership still in the fragment")
	}

	r = target(t, f, "arn:aws:iam::"+acct+":user/bob")
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted user: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
}

// S3 beyond Block Public Access: a public bucket policy and a public ACL are each re-read and
// each fix alone is not enough while the other is still public.
func TestTargetS3PolicyAndACL(t *testing.T) {
	f := targetFixture()
	f.buckets[0].policyPublic = true // ACL AllUsers + public policy, no BPA
	r := target(t, f, tBucket)
	if st, _ := statusOf(r.Findings, "s3_bucket_public_access", tBucket); st != model.Fail {
		t.Fatalf("ACL + policy public = %q", st)
	}
	f.buckets[0].aclAllUsers = false
	r = target(t, f, tBucket)
	if st, _ := statusOf(r.Findings, "s3_bucket_public_access", tBucket); st != model.Fail {
		t.Fatalf("ACL fixed but policy still public = %q, want FAIL", st)
	}
	f.buckets[0].policyPublic = false
	r = target(t, f, tBucket)
	if st, _ := statusOf(r.Findings, "s3_bucket_public_access", tBucket); st != model.Pass {
		t.Fatalf("ACL and policy fixed = %q, want PASS", st)
	}
	// Bucket-level BPA alone also closes it (re-read, not inferred).
	f.buckets[0].aclAllUsers, f.buckets[0].policyPublic = true, true
	all := awssdk.Bool(true)
	f.buckets[0].pab = &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: all, IgnorePublicAcls: all, BlockPublicPolicy: all, RestrictPublicBuckets: all}
	r = target(t, f, tBucket)
	if st, _ := statusOf(r.Findings, "s3_bucket_public_access", tBucket); st != model.Pass {
		t.Fatalf("BPA on = %q, want PASS", st)
	}
}

// Security group by bare id with an IPv6 open rule: still FAIL until the ::/0 rule goes too.
func TestTargetSecurityGroupIPv6(t *testing.T) {
	f := targetFixture()
	f.sgs[0].IpPermissions = []ec2types.IpPermission{{IpProtocol: awssdk.String("tcp"), FromPort: awssdk.Int32(22), ToPort: awssdk.Int32(22),
		Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awssdk.String("::/0")}}}}
	r := target(t, f, "sg-open")
	if st, _ := statusOf(r.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", tSG); st != model.Fail {
		t.Fatalf("::/0 on 22 = %q, want FAIL", st)
	}
	f.sgs[0].IpPermissions = nil
	r = target(t, f, "sg-open")
	if st, _ := statusOf(r.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", tSG); st != model.Pass {
		t.Fatalf("closed = %q, want PASS", st)
	}
}

// core.TargetReader (what read-only surfaces report) agrees with parseTarget.
func TestTargetReaderMatchesParser(t *testing.T) {
	for _, id := range []string{tBucket, tInst, tSG, tRole, tUser, tRDS, tLambda, tLambda + ":prod", tEKS, "i-0abc", "sg-0abc",
		"arn:aws:s3:::b/key", "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:x", "arn:aws:kms:us-east-1:" + acct + ":key/k",
		"arn:aws:rds:us-east-1:" + acct + ":cluster:aurora", "arn:aws:iam::" + acct + ":policy/p"} {
		_, ok := parseTarget(id, "us-east-1")
		if got := core.TargetReader("aws", id) != ""; got != ok {
			t.Errorf("%s: TargetReader says %v, parseTarget %v", id, got, ok)
		}
	}
}
