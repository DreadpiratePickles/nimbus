package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-VERIFY (r4 #8): Azure targeted re-collection for storage accounts and NSGs, so `verify`
// confirms an Azure fix against the cloud (Orca rescan-on-close) instead of only --from-file.

var _ core.Targeted = (*Collector)(nil)

const stCust = rgp + "Microsoft.Storage/storageAccounts/custdata"

func targetClients(cl *Clients) *Clients {
	cl.SQLServers = nil // a read of a storage account / NSG never lists SQL servers
	return cl
}

func azTarget(t *testing.T, cl *Clients, ids ...string) *core.TargetResult {
	t.Helper()
	c := newTestCollector(func(spec core.AccountSpec) (*Clients, error) {
		if spec.SubscriptionID != sub {
			return nil, errors.New("wrong subscription " + spec.SubscriptionID)
		}
		return cl, nil
	})
	r, err := c.Target(context.Background(), core.AccountSpec{Name: "azure-prod", Provider: "azure"}, ids)
	if err != nil {
		t.Fatalf("Target: %v", err)
	}
	return r
}

func azStatus(fs []model.Finding, check, id string) (model.Status, bool) {
	for _, f := range fs {
		if f.CheckID == check && strings.EqualFold(f.Resource.ID, id) {
			return f.Status, true
		}
	}
	return "", false
}

func TestAzureTargetStoragePublicThenFixed(t *testing.T) {
	cl := targetClients(fixtureClients())
	r := azTarget(t, cl, stCust)
	if r.Inconclusive() {
		t.Fatalf("storage read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := azStatus(r.Findings, "storage_blob_public_access_level_is_disabled", stCust); !ok || st != model.Fail {
		t.Fatalf("public blob access = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, stCust, graph.EdgeExposes) {
		t.Errorf("public storage account not exposed in the fragment")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "storageAccounts/logs") || strings.Contains(f.Resource.ID, "virtualMachines") {
			t.Errorf("unrelated resource in a storage read: %s %s", f.CheckID, f.Resource.ID)
		}
	}
	if len(r.Observed) != 1 {
		t.Errorf("observed = %v", r.Observed)
	}
	// The owner disables anonymous blob access.
	cl.Storage.(fakeStorage).accts[0].Properties.AllowBlobPublicAccess = to.Ptr(false)
	r = azTarget(t, cl, stCust)
	if st, _ := azStatus(r.Findings, "storage_blob_public_access_level_is_disabled", stCust); st != model.Pass {
		t.Fatalf("fixed = %q, want PASS", st)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, stCust, graph.EdgeExposes) {
		t.Errorf("fixed storage still exposed")
	}
	gone := rgp + "Microsoft.Storage/storageAccounts/deleted"
	r = azTarget(t, cl, gone)
	if len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted account: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	cl.Storage = fakeStorage{err: errors.New("AuthorizationFailed")}
	r = azTarget(t, cl, stCust)
	if !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestAzureTargetNSGOneHopAndFix(t *testing.T) {
	cl := targetClients(fixtureClients())
	r := azTarget(t, cl, nsgOpen)
	if r.Inconclusive() {
		t.Fatalf("NSG read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := azStatus(r.Findings, "network_ssh_internet_access_restricted", nsgOpen); !ok || st != model.Fail {
		t.Fatalf("SSH open = %q (%v)", st, ok)
	}
	if _, ok := r.Graph.Node(vmWeb); !ok {
		t.Errorf("the VM the NSG guards (one hop) is missing from the fragment")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "storageAccounts") || strings.Contains(f.Resource.ID, "vaults/") {
			t.Errorf("unrelated resource in an NSG read: %s %s", f.CheckID, f.Resource.ID)
		}
	}
	// SSH rule restricted to a private range.
	n := cl.NSGs.(fakeNSGs)[0]
	n.Properties.SecurityRules = []*armnetwork.SecurityRule{rule("ssh", 100, armnetwork.SecurityRuleAccessAllow, "10.0.0.0/8", "22")}
	r = azTarget(t, cl, strings.ToLower(nsgOpen)) // ARM ids are case-insensitive
	if st, _ := azStatus(r.Findings, "network_ssh_internet_access_restricted", nsgOpen); st != model.Pass {
		t.Fatalf("restricted SSH = %q, want PASS", st)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, vmWeb, graph.EdgeExposes) {
		t.Errorf("VM behind the fixed NSG still exposed")
	}
}

func TestAzureTargetUnsupportedAndSubscription(t *testing.T) {
	cl := targetClients(fixtureClients())
	r := azTarget(t, cl, aksID, stCust)
	if len(r.Unsupported) != 1 || r.Unsupported[0] != aksID || !r.Inconclusive() {
		t.Errorf("AKS cluster is not targeted yet: unsupported %v", r.Unsupported)
	}
	c := newTestCollector(func(spec core.AccountSpec) (*Clients, error) { return cl, nil })
	if _, err := c.Target(context.Background(), core.AccountSpec{Provider: "azure"}, []string{"not-an-arm-id"}); err != nil {
		t.Fatalf("an unparseable id is unsupported, not fatal: %v", err)
	}
}

func TestAzureTargetReaderMatchesParser(t *testing.T) {
	for _, id := range []string{stCust, nsgOpen, strings.ToLower(nsgOpen), sqlID, vmWeb, rgp + "Microsoft.Storage/storageAccounts/x/blobServices/default", "not-an-arm-id"} {
		_, ok := parseAzureTarget(id)
		if got := core.TargetReader("azure", id) != ""; got != ok {
			t.Errorf("%s: TargetReader says %v, parser %v", id, got, ok)
		}
	}
}
