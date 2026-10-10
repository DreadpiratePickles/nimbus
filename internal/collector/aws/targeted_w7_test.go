package aws

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY (r5 #6): AWS Secrets Manager secrets and KMS keys are re-read by id through the same
// analyze code as a full scan; a denied read is inconclusive, never a deletion.

const (
	tSecret = "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:db-pass"
	tKey    = "arn:aws:kms:us-east-1:" + acct + ":key/k1"
)

const publicSecretPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`

func TestTargetSecretPolicyThenFixed(t *testing.T) {
	f := w6Fixture("ListSecrets")
	f.secretPolicy = map[string]string{tSecret: publicSecretPolicy}
	r := target(t, f, tSecret)
	if r.Inconclusive() {
		t.Fatalf("secret read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if len(r.Observed) != 1 || r.Observed[0] != tSecret {
		t.Fatalf("observed = %v", r.Observed)
	}
	n, ok := r.Graph.Node(tSecret)
	if !ok {
		t.Fatalf("fragment lacks the secret")
	}
	if n.Attributes["resource_policy_status"] != "collected" {
		t.Errorf("resource policy not read: %v", n.Attributes)
	}
	onlyNear(t, r.Findings, "s3:::", "db:orders", "function:", "cluster/", "key/k1")

	// The owner removes the public resource policy.
	f.secretPolicy = nil
	r = target(t, f, tSecret)
	if n, _ := r.Graph.Node(tSecret); n == nil || n.Attributes["resource_policy_status"] != "none" {
		t.Errorf("fixed secret policy status = %v", n)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tSecret, graph.EdgeExposes) {
		t.Errorf("secret without a policy still exposed")
	}
	gone := "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:deleted"
	r = target(t, f, gone)
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted secret: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	f.fail["GetResourcePolicy"] = apiErr("AccessDeniedException")
	r = target(t, f, tSecret)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied GetResourcePolicy must be inconclusive: missing %v", r.Missing)
	}
	delete(f.fail, "GetResourcePolicy")
	f.fail["ListSecrets"] = apiErr("AccessDeniedException")
	r = target(t, f, tSecret)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied ListSecrets must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestTargetKMSRotationThenFixed(t *testing.T) {
	f := targetFixture() // ListKeys stays failing: a targeted read describes the key by id
	r := target(t, f, tKey)
	if r.Inconclusive() {
		t.Fatalf("KMS read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := statusOf(r.Findings, "kms_cmk_rotation_enabled", tKey); !ok || st != model.Fail {
		t.Fatalf("rotation off: kms_cmk_rotation_enabled = %q (%v)", st, ok)
	}
	onlyNear(t, r.Findings, "s3:::", "secret:", "key/k2", "db:orders")
	f.rotation["k1"] = true
	r = target(t, f, tKey)
	if st, _ := statusOf(r.Findings, "kms_cmk_rotation_enabled", tKey); st != model.Pass {
		t.Fatalf("rotation on = %q, want PASS", st)
	}
	// A key scheduled for deletion leaves the estate exactly as a full scan sees it.
	f.keys[0].KeyState = kmstypes.KeyStatePendingDeletion
	r = target(t, f, tKey)
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("pending-deletion key: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	gone := "arn:aws:kms:us-east-1:" + acct + ":key/nope"
	r = target(t, f, gone)
	if len(r.Missing) != 1 || r.Missing[0] != gone {
		t.Errorf("unknown key: missing %v", r.Missing)
	}
	f.keys[0].KeyState = kmstypes.KeyStateEnabled
	f.fail["GetKeyPolicy"] = apiErr("AccessDeniedException")
	r = target(t, f, tKey)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied GetKeyPolicy must be inconclusive: missing %v", r.Missing)
	}
	delete(f.fail, "GetKeyPolicy")
	c := &Collector{NewClients: func(ctx context.Context, spec core.AccountSpec, region string) (*Clients, error) {
		cl := f.clients()
		cl.KMS = deniedKMS{f}
		return cl, nil
	}, Now: func() time.Time { return now }}
	r, err := c.Target(context.Background(), core.AccountSpec{Name: "prod-main", Provider: "aws", Regions: []string{"us-east-1"}}, []string{tKey})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied DescribeKey must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestTargetReaderNamesSecretsAndKMS(t *testing.T) {
	for id, want := range map[string]string{tSecret: "aws:secretsmanager", tKey: "aws:kms"} {
		if got := core.TargetReader("aws", id); got != want {
			t.Errorf("%s: reader %q, want %q", id, got, want)
		}
		if _, ok := parseTarget(id, "us-east-1"); !ok {
			t.Errorf("%s: parseTarget refuses it", id)
		}
	}
	for _, id := range []string{"arn:aws:kms:us-east-1:" + acct + ":alias/x", "arn:aws:secretsmanager:us-east-1:" + acct + ":nope:x"} {
		if core.TargetReader("aws", id) != "" {
			t.Errorf("%s: not a targetable id", id)
		}
	}
}

// deniedKMS answers DescribeKey with AccessDenied.
type deniedKMS struct{ *fakeAWS }

func (deniedKMS) DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return nil, apiErr("AccessDeniedException")
}
