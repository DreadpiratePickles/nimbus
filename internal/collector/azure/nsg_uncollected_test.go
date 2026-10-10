package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Verify-3 defect 3(c): an NSG that a NIC or subnet references but the collector did
// not list (deleted mid-scan, other subscription, list denied) is UNKNOWN, not deny:
// it must not hide exposure, and it is reported as a coverage gap.

const ghostNSG = rgp + "Microsoft.Network/networkSecurityGroups/ghost-nsg"

func exposeEdge(g *graph.Graph, to string) *graph.Edge {
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.To == to && e.Kind == graph.EdgeExposes {
			return e
		}
	}
	return nil
}

func ghostCoverage(t *testing.T, res core.Result) {
	t.Helper()
	for _, ce := range res.CollectErrors() {
		if ce.API == "network.nsgs" && strings.Contains(ce.Message, "ghost-nsg") {
			return
		}
	}
	t.Errorf("no coverage error for the uncollected NSG: %+v", res.CollectErrors())
}

func TestUncollectedNSGIsUnknownNotDeny(t *testing.T) {
	t.Run("only layer uncollected", func(t *testing.T) {
		cl := fixtureClients()
		nics := cl.NICs.(fakeNICs)
		nics[0] = nic("web-nic", ghostNSG, rgp+"Microsoft.Network/virtualNetworks/vnet/subnets/web", rgp+"Microsoft.Network/publicIPAddresses/web-ip")
		g := graph.New()
		res, err := newTestCollector(func(core.AccountSpec) (*Clients, error) { return cl, nil }).Collect(context.Background(), core.AccountSpec{SubscriptionID: sub}, g)
		if err != nil {
			t.Fatal(err)
		}
		e := exposeEdge(g, vmWeb)
		if e == nil {
			t.Fatal("VM behind an uncollected NSG treated as denied: no internet exposure edge")
		}
		if e.Attr["certainty"] != "unknown" || e.Attr["via"] != "nsg_not_collected" {
			t.Errorf("exposure through an uncollected NSG must be marked unknown: %v", e.Attr)
		}
		ghostCoverage(t, res)
	})
	t.Run("known layer denies", func(t *testing.T) {
		cl := fixtureClients()
		nics := cl.NICs.(fakeNICs)
		nics[1] = nic("db-nic", ghostNSG, subnetDB, rgp+"Microsoft.Network/publicIPAddresses/db-ip") // subnet NSG db-nsg denies the internet
		g := graph.New()
		res, err := newTestCollector(func(core.AccountSpec) (*Clients, error) { return cl, nil }).Collect(context.Background(), core.AccountSpec{SubscriptionID: sub}, g)
		if err != nil {
			t.Fatal(err)
		}
		if e := exposeEdge(g, rgp+"Microsoft.Compute/virtualMachines/db-vm"); e != nil {
			t.Errorf("a collected layer that denies the internet must still block: %v", e.Attr)
		}
		ghostCoverage(t, res)
	})
	t.Run("known layer allows, other uncollected", func(t *testing.T) {
		cl := fixtureClients()
		nics := cl.NICs.(fakeNICs)
		n := nic("web-nic", nsgOpen, rgp+"Microsoft.Network/virtualNetworks/vnet/subnets/web", rgp+"Microsoft.Network/publicIPAddresses/web-ip")
		n.Properties.IPConfigurations[0].Properties.Subnet.Properties = &armnetwork.SubnetPropertiesFormat{NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr(ghostNSG)}}
		nics[0] = n
		g := graph.New()
		res, err := newTestCollector(func(core.AccountSpec) (*Clients, error) { return cl, nil }).Collect(context.Background(), core.AccountSpec{SubscriptionID: sub}, g)
		if err != nil {
			t.Fatal(err)
		}
		e := exposeEdge(g, vmWeb)
		if e == nil {
			t.Fatal("an uncollected subnet NSG hid the NIC NSG's internet rules")
		}
		if e.Attr["ports"] != "22,443" || e.Attr["certainty"] != "unknown" {
			t.Errorf("edge attrs = %v, want ports 22,443 marked unknown", e.Attr)
		}
		ghostCoverage(t, res)
	})
}
