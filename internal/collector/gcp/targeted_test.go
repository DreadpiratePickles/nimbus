package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY (r5 #6): GCP firewall rules, instances and buckets are re-read through the same
// builder as a full scan (Orca rescan-on-close, Prowler partial re-check); a denied listing is
// inconclusive, never a deletion.

var _ core.Targeted = (*Collector)(nil)

const (
	cpx     = "https://www.googleapis.com/compute/v1/projects/" + proj
	tFwSSH  = cpx + "/global/firewalls/allow-ssh"
	tWeb    = cpx + "/zones/us-central1-a/instances/web"
	tBatch  = cpx + "/zones/europe-west1-b/instances/batch"
	tBucket = "//storage.googleapis.com/projects/_/buckets/customer-exports"
)

// targetFixture is fixture() with real self links (the ids a scan stores).
func targetFixture() *Clients {
	cl := fixture()
	fc := cl.Compute.(*fakeCompute)
	for _, i := range fc.inst {
		i.SelfLink = cpx + "/" + i.Zone + "/instances/" + i.Name
	}
	for _, fw := range fc.fws {
		fw.SelfLink = cpx + "/global/firewalls/" + fw.Name
	}
	cl.SQL = &failingSQL{} // a targeted read never lists Cloud SQL
	return cl
}

type failingSQL struct{}

func (*failingSQL) Instances(context.Context, string) ([]*sqladmin.DatabaseInstance, error) {
	return nil, errors.New("ShouldNotBeCalled")
}

type deniedFirewalls struct{ *fakeCompute }

func (deniedFirewalls) Firewalls(context.Context, string) ([]*compute.Firewall, error) {
	return nil, errors.New("googleapi: Error 403: Required 'compute.firewalls.list' permission")
}

func gcpTarget(t *testing.T, cl *Clients, ids ...string) *core.TargetResult {
	t.Helper()
	c := &Collector{NewClients: func(context.Context, core.AccountSpec) (*Clients, error) { return cl, nil },
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	r, err := c.Target(context.Background(), core.AccountSpec{Name: "prod", Provider: "gcp", ProjectID: proj}, ids)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	return r
}

func findingStatus(fs []model.Finding, check, id string) (model.Status, bool) {
	for _, f := range fs {
		if f.CheckID == check && f.Resource.ID == id {
			return f.Status, true
		}
	}
	return "", false
}

func TestGCPTargetFirewallThenFixed(t *testing.T) {
	cl := targetFixture()
	r := gcpTarget(t, cl, tFwSSH)
	if r.Inconclusive() {
		t.Fatalf("firewall read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := findingStatus(r.Findings, "compute_firewall_ssh_access_from_the_internet_allowed", tFwSSH); !ok || st != model.Fail {
		t.Fatalf("open SSH = %q (%v)", st, ok)
	}
	if _, ok := r.Graph.Node(tWeb); !ok {
		t.Errorf("fragment lacks the instance the rule applies to (one hop)")
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tWeb, graph.EdgeExposes) {
		t.Errorf("instance behind the open rule not exposed in the fragment")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "buckets/") || strings.Contains(f.Resource.ID, "allow-rdp-range") {
			t.Errorf("unrelated resource in a firewall read: %s %s", f.CheckID, f.Resource.ID)
		}
	}
	if len(r.Observed) != 1 || r.Observed[0] != tFwSSH {
		t.Errorf("observed = %v", r.Observed)
	}
	// The owner narrows the rule to a corporate range.
	cl.Compute.(*fakeCompute).fws[0].SourceRanges = []string{"10.0.0.0/8"}
	r = gcpTarget(t, cl, tFwSSH)
	if st, _ := findingStatus(r.Findings, "compute_firewall_ssh_access_from_the_internet_allowed", tFwSSH); st != model.Pass {
		t.Fatalf("narrowed rule = %q, want PASS", st)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tWeb, graph.EdgeExposes) {
		t.Errorf("instance still exposed after the fix")
	}
	gone := cpx + "/global/firewalls/deleted"
	if r = gcpTarget(t, cl, gone); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted rule: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	cl.Compute = deniedFirewalls{cl.Compute.(*fakeCompute)}
	if r = gcpTarget(t, cl, tFwSSH); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied firewall listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestGCPTargetInstanceAndDenied(t *testing.T) {
	cl := targetFixture()
	r := gcpTarget(t, cl, tWeb)
	if r.Inconclusive() {
		t.Fatalf("instance read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := findingStatus(r.Findings, "compute_instance_default_service_account_in_use_with_full_api_access", tWeb); !ok || st != model.Fail {
		t.Fatalf("default SA with full scope = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tWeb, graph.EdgeExposes) {
		t.Errorf("exposed instance not exposed in the fragment")
	}
	if _, ok := r.Graph.Node(tFwSSH); !ok {
		t.Errorf("fragment lacks the instance's firewall rule (one hop)")
	}
	if _, ok := r.Graph.Node(tBatch); ok {
		t.Errorf("an unrelated instance is in the fragment")
	}
	// Public IP removed.
	cl.Compute.(*fakeCompute).inst[0].NetworkInterfaces[0].AccessConfigs = nil
	if r = gcpTarget(t, cl, tWeb); hasEdge(r.Graph, graph.InternetNodeID, tWeb, graph.EdgeExposes) {
		t.Errorf("instance without a public IP still exposed")
	}
	if r = gcpTarget(t, cl, cpx+"/zones/us-central1-a/instances/deleted"); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted instance: missing %v", r.Missing)
	}
	cl.Compute.(*fakeCompute).err = errors.New("googleapi: Error 403: forbidden")
	if r = gcpTarget(t, cl, tWeb); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied instance listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestGCPTargetBucketThenFixed(t *testing.T) {
	cl := targetFixture()
	cl.Compute = deniedFirewalls{cl.Compute.(*fakeCompute)} // a bucket read never lists compute
	r := gcpTarget(t, cl, tBucket)
	if r.Inconclusive() {
		t.Fatalf("bucket read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := findingStatus(r.Findings, "cloudstorage_bucket_public_access", tBucket); !ok || st != model.Fail {
		t.Fatalf("public bucket = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, tBucket, graph.EdgeExposes) {
		t.Errorf("public bucket not exposed in the fragment")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "buckets/private") || strings.Contains(f.Resource.ID, "buckets/locked") {
			t.Errorf("unrelated bucket in the read: %s", f.Resource.ID)
		}
	}
	st := cl.Storage.(*fakeStorage)
	st.b[0].PublicAccessPrevention = "enforced"
	r = gcpTarget(t, cl, tBucket)
	if s, _ := findingStatus(r.Findings, "cloudstorage_bucket_public_access", tBucket); s != model.Pass {
		t.Fatalf("enforced prevention = %q, want PASS", s)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, tBucket, graph.EdgeExposes) {
		t.Errorf("fixed bucket still exposed")
	}
	if r = gcpTarget(t, cl, "//storage.googleapis.com/projects/_/buckets/deleted"); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted bucket: missing %v", r.Missing)
	}
	// The bucket IAM policy cannot be read: no verdict either way.
	st.b[0].PolicyErr = errors.New("403")
	if r = gcpTarget(t, cl, tBucket); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("unreadable bucket policy must be inconclusive: missing %v", r.Missing)
	}
	st.b[0].PolicyErr, st.err = nil, errors.New("403 storage.buckets.list")
	if r = gcpTarget(t, cl, tBucket); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied bucket listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestGCPTargetUnsupportedAndReader(t *testing.T) {
	cl := targetFixture()
	sqlID := "https://sqladmin.googleapis.com/sql/v1/projects/" + proj + "/instances/orders"
	r := gcpTarget(t, cl, sqlID, tBucket)
	if len(r.Unsupported) != 1 || r.Unsupported[0] != sqlID || !r.Inconclusive() {
		t.Errorf("Cloud SQL is not targeted yet: unsupported %v", r.Unsupported)
	}
	for id, want := range map[string]string{tFwSSH: "gcp:firewall", tWeb: "gcp:instance", tBucket: "gcp:bucket", sqlID: "", "//storage.googleapis.com/projects/_/buckets/b/o/obj": ""} {
		_, ok := parseGCPTarget(id)
		if got := core.TargetReader("gcp", id); got != want || (got != "") != ok {
			t.Errorf("%s: reader %q (parser %v), want %q", id, got, ok, want)
		}
	}
}
