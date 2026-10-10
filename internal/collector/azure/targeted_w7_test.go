package azure

import (
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY (r5 #6): Azure SQL servers (firewall rules), VMs (NIC / subnet NSG layers, public IP)
// and Key Vaults (soft delete / purge protection) are re-read through the same build() as a full
// scan; a denied listing is inconclusive, never a deletion.

const kvWeak = rgp + "Microsoft.KeyVault/vaults/kv-weak"

type deniedSQL struct{}

func (deniedSQL) NewListPager(*armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return pagerOf[armsql.ServersClientListResponse](errors.New("AuthorizationFailed"))
}

type deniedVaults struct{}

func (deniedVaults) NewListBySubscriptionPager(*armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse] {
	return pagerOf[armkeyvault.VaultsClientListBySubscriptionResponse](errors.New("AuthorizationFailed"))
}

type deniedVMs struct{}

func (deniedVMs) NewListAllPager(*armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse] {
	return pagerOf[armcompute.VirtualMachinesClientListAllResponse](errors.New("AuthorizationFailed"))
}

func TestAzureTargetSQLFirewallThenFixed(t *testing.T) {
	cl := fixtureClients()
	cl.Storage, cl.Vaults = fakeStorage{err: errors.New("ShouldNotBeCalled")}, deniedVaults{}
	r := azTarget(t, cl, sqlID)
	if r.Inconclusive() {
		t.Fatalf("SQL read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := azStatus(r.Findings, "sqlserver_firewall_rules_no_ingress_from_internet", sqlID); !ok || st != model.Fail {
		t.Fatalf("open SQL firewall = %q (%v)", st, ok)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, sqlID, graph.EdgeExposes) {
		t.Errorf("SQL server with a 0.0.0.0-255.255.255.255 rule not exposed in the fragment")
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "private-sql") || strings.Contains(f.Resource.ID, "storageAccounts") {
			t.Errorf("unrelated resource in a SQL read: %s %s", f.CheckID, f.Resource.ID)
		}
	}
	// The owner deletes the rule.
	cl.SQLFirewall.(fakeFW)["rg1/customers-sql"] = nil
	r = azTarget(t, cl, strings.ToLower(sqlID))
	if st, _ := azStatus(r.Findings, "sqlserver_firewall_rules_no_ingress_from_internet", sqlID); st != model.Pass {
		t.Fatalf("fixed SQL firewall = %q, want PASS", st)
	}
	if hasEdge(r.Graph, graph.InternetNodeID, sqlID, graph.EdgeExposes) {
		t.Errorf("fixed SQL server still exposed")
	}
	gone := rgp + "Microsoft.Sql/servers/deleted"
	if r = azTarget(t, cl, gone); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted server: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	// The firewall rules of the requested server cannot be read: inconclusive.
	delete(cl.SQLFirewall.(fakeFW), "rg1/customers-sql")
	if r = azTarget(t, cl, sqlID); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("unreadable firewall rules must be inconclusive: missing %v", r.Missing)
	}
	cl.SQLServers = deniedSQL{}
	if r = azTarget(t, cl, sqlID); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied server listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestAzureTargetVMExposureThenFixed(t *testing.T) {
	cl := targetClients(fixtureClients())
	r := azTarget(t, cl, vmWeb)
	if r.Inconclusive() {
		t.Fatalf("VM read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if !hasEdge(r.Graph, graph.InternetNodeID, vmWeb, graph.EdgeExposes) {
		t.Fatalf("VM behind an NSG open to the internet is not exposed in the fragment")
	}
	if _, ok := r.Graph.Node(nsgOpen); !ok {
		t.Errorf("fragment lacks the VM's NSG (one hop)")
	}
	if _, ok := r.Graph.Node(vmDB); ok {
		t.Errorf("an unrelated VM is in the fragment")
	}
	n := cl.NSGs.(fakeNSGs)[0]
	n.Properties.SecurityRules = []*armnetwork.SecurityRule{rule("ssh", 100, armnetwork.SecurityRuleAccessAllow, "10.0.0.0/8", "22")}
	r = azTarget(t, cl, vmWeb)
	if hasEdge(r.Graph, graph.InternetNodeID, vmWeb, graph.EdgeExposes) {
		t.Errorf("VM behind the fixed NSG still exposed")
	}
	gone := rgp + "Microsoft.Compute/virtualMachines/deleted"
	if r = azTarget(t, cl, gone); len(r.Missing) != 1 || r.Inconclusive() {
		t.Errorf("deleted VM: missing %v inconclusive %v", r.Missing, r.Inconclusive())
	}
	cl.VMs = deniedVMs{}
	if r = azTarget(t, cl, vmWeb); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied VM listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestAzureTargetKeyVaultThenFixed(t *testing.T) {
	cl := targetClients(fixtureClients())
	r := azTarget(t, cl, kvWeak)
	if r.Inconclusive() {
		t.Fatalf("vault read inconclusive: %v %v", r.Errors, r.Unsupported)
	}
	if st, ok := azStatus(r.Findings, "keyvault_recoverable", kvWeak); !ok || st != model.Fail {
		t.Fatalf("no purge protection = %q (%v)", st, ok)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Resource.ID, "kv-good") {
			t.Errorf("unrelated vault in the read: %s", f.Resource.ID)
		}
	}
	cl.Vaults.(fakeVaults)[0].Properties.EnablePurgeProtection = to.Ptr(true)
	if r = azTarget(t, cl, kvWeak); func() model.Status { s, _ := azStatus(r.Findings, "keyvault_recoverable", kvWeak); return s }() != model.Pass {
		t.Fatalf("purge protection on: want PASS")
	}
	cl.Vaults = deniedVaults{}
	if r = azTarget(t, cl, kvWeak); !r.Inconclusive() || len(r.Missing) != 0 {
		t.Errorf("denied vault listing must be inconclusive, never a deletion: missing %v", r.Missing)
	}
}

func TestAzureTargetReaderNamesW7(t *testing.T) {
	for id, want := range map[string]string{sqlID: "azure:sql", vmWeb: "azure:vm", kvWeak: "azure:keyvault", strings.ToLower(kvWeak): "azure:keyvault"} {
		if got := core.TargetReader("azure", id); got != want {
			t.Errorf("%s: reader %q, want %q", id, got, want)
		}
		if _, ok := parseAzureTarget(id); !ok {
			t.Errorf("%s: parser refuses it", id)
		}
	}
	for _, id := range []string{aksID, sqlID + "/databases/db1", rgp + "Microsoft.Compute/disks/web-os"} {
		_, ok := parseAzureTarget(id)
		if got := core.TargetReader("azure", id) != ""; got != ok || ok {
			t.Errorf("%s: not targetable yet (reader %v parser %v)", id, got, ok)
		}
	}
}
