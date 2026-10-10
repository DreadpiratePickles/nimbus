package aws

import (
	"context"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var _ core.Targeted = (*Collector)(nil)

// targetFixture is fixture() with every service the targeted read must NOT touch failing:
// a call to one of them shows up as a partial error.
func targetFixture() *fakeAWS {
	f := fixture()
	f.fail = map[string]error{}
	for _, op := range []string{"DescribeDBInstances", "ListFunctions", "ListClusters", "ListSecrets", "ListKeys", "DescribeTrails", "GetCostAndUsage", "DescribeVolumes", "DescribeAddresses"} {
		f.fail[op] = apiErr("ShouldNotBeCalled")
	}
	return f
}

func target(t *testing.T, f *fakeAWS, ids ...string) *core.TargetResult {
	t.Helper()
	c := &Collector{NewClients: f.factory(), Now: func() time.Time { return now }, CredentialReportPoll: time.Millisecond}
	r, err := c.Target(context.Background(), core.AccountSpec{Name: "prod-main", Provider: "aws", Regions: []string{"us-east-1"}}, ids)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	return r
}

func statusOf(fs []model.Finding, check, resID string) (model.Status, bool) {
	for _, f := range fs {
		if f.CheckID == check && f.Resource.ID == resID {
			return f.Status, true
		}
	}
	return "", false
}

const (
	tBucket = "arn:aws:s3:::prod-customer-data"
	tInst   = "arn:aws:ec2:us-east-1:" + acct + ":instance/i-web"
	tSG     = "arn:aws:ec2:us-east-1:" + acct + ":security-group/sg-open"
	tRole   = "arn:aws:iam::" + acct + ":role/web-role"
)

func TestTargetS3BucketPublicThenFixed(t *testing.T) {
	f := targetFixture()
	r := target(t, f, tBucket)
	if len(r.Errors) != 0 || r.Inconclusive() {
		t.Fatalf("targeted read touched unrelated services or failed: %v", r.Errors)
	}
	if st, ok := statusOf(r.Findings, "s3_bucket_public_access", tBucket); !ok || st != model.Fail {
		t.Fatalf("public bucket: s3_bucket_public_access = %q (found %v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tBucket, graph.EdgeExposes) {
		t.Errorf("fragment lacks the internet exposure of the public bucket")
	}
	for _, fd := range r.Findings {
		if strings.Contains(fd.Resource.ID, ":::logs") || strings.Contains(fd.Resource.ID, "i-big") {
			t.Errorf("targeted read returned an unrelated resource: %s %s", fd.CheckID, fd.Resource.ID)
		}
	}
	if len(r.Observed) != 1 || r.Observed[0] != tBucket {
		t.Errorf("observed = %v", r.Observed)
	}

	// The owner blocks public access: the same targeted read now reports PASS.
	all := awssdk.Bool(true)
	f.buckets[0].pab = &s3types.PublicAccessBlockConfiguration{BlockPublicAcls: all, IgnorePublicAcls: all, BlockPublicPolicy: all, RestrictPublicBuckets: all}
	r = target(t, f, tBucket)
	if st, ok := statusOf(r.Findings, "s3_bucket_public_access", tBucket); !ok || st != model.Pass {
		t.Fatalf("fixed bucket: s3_bucket_public_access = %q (found %v)", st, ok)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tBucket, graph.EdgeExposes) {
		t.Errorf("fixed bucket is still exposed in the fragment")
	}
}

func TestTargetInstanceSGAndRoleOneHop(t *testing.T) {
	f := targetFixture()
	r := target(t, f, tInst)
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %v", r.Errors)
	}
	if st, ok := statusOf(r.Findings, "ec2_instance_imdsv2_enabled", tInst); !ok || st != model.Fail {
		t.Errorf("instance IMDSv1 finding = %q (%v)", st, ok)
	}
	// One-hop neighbours: the attached SG and the instance role are in the fragment.
	if st, ok := statusOf(r.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", tSG); !ok || st != model.Fail {
		t.Errorf("neighbour SG 22 finding = %q (%v)", st, ok)
	}
	if _, ok := r.Graph.Node(tRole); !ok {
		t.Errorf("fragment lacks the instance role (one hop)")
	}
	for _, fd := range r.Findings {
		if strings.Contains(fd.Resource.ID, "i-big") || strings.Contains(fd.Resource.ID, "sg-private") || strings.Contains(fd.Resource.ID, "s3:::") {
			t.Errorf("not one hop from the instance: %s %s", fd.CheckID, fd.Resource.ID)
		}
	}

	// SG narrowed: 22 only from 10/8, 3389 still open to the world.
	f.sgs[0].IpPermissions = []ec2types.IpPermission{tcp(22, 22, "10.0.0.0/8"), tcp(3389, 3389, "0.0.0.0/0")}
	r = target(t, f, tSG)
	if st, _ := statusOf(r.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", tSG); st != model.Pass {
		t.Errorf("narrowed 22 = %q, want PASS", st)
	}
	if st, _ := statusOf(r.Findings, "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", tSG); st != model.Fail {
		t.Errorf("3389 = %q, want FAIL", st)
	}
	if _, ok := r.Graph.Node(tInst); !ok {
		t.Errorf("SG target: the instance it guards (one hop) is missing from the fragment")
	}
}

func TestTargetRoleMissingUnsupportedAndErrors(t *testing.T) {
	f := targetFixture()
	gone := "arn:aws:s3:::deleted-bucket"
	rds := "arn:aws:dynamodb:us-east-1:" + acct + ":table/orders" // a type no reader targets
	r := target(t, f, tRole, gone, rds, "arn:aws:ec2:us-east-1:"+acct+":instance/i-gone")
	if len(r.Unsupported) != 1 || r.Unsupported[0] != rds {
		t.Errorf("unsupported = %v", r.Unsupported)
	}
	if !r.Inconclusive() {
		t.Errorf("a read with unsupported ids must be inconclusive")
	}
	miss := strings.Join(r.Missing, ",")
	if !strings.Contains(miss, gone) || !strings.Contains(miss, "i-gone") {
		t.Errorf("missing = %v", r.Missing)
	}
	if _, ok := r.Graph.Node(tRole); !ok {
		t.Errorf("role not in fragment")
	}

	f.fail["ListBuckets"] = apiErr("AccessDenied")
	r = target(t, f, tBucket)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied ListBuckets: inconclusive=%v missing=%v (a denied read is not a deletion)", r.Inconclusive(), r.Missing)
	}
}
