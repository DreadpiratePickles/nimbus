package azure

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// pagerOf builds an SDK pager over fixed pages; err (if set) is returned instead of the first page.
func pagerOf[T any](err error, pages ...T) *runtime.Pager[T] {
	i := 0
	return runtime.NewPager(runtime.PagingHandler[T]{
		More: func(T) bool { return i < len(pages) },
		Fetcher: func(context.Context, *T) (T, error) {
			var zero T
			if err != nil {
				i = len(pages)
				return zero, err
			}
			if len(pages) == 0 {
				return zero, nil
			}
			p := pages[i]
			i++
			return p, nil
		},
	})
}

type fakeVMs struct {
	vms    []*armcompute.VirtualMachine
	status []*armcompute.VirtualMachine
}

func (f fakeVMs) NewListAllPager(o *armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse] {
	v := f.vms
	if o != nil && o.StatusOnly != nil {
		v = f.status
	}
	// two pages to exercise pagination
	half := len(v) / 2
	return pagerOf[armcompute.VirtualMachinesClientListAllResponse](nil,
		armcompute.VirtualMachinesClientListAllResponse{VirtualMachineListResult: armcompute.VirtualMachineListResult{Value: v[:half]}},
		armcompute.VirtualMachinesClientListAllResponse{VirtualMachineListResult: armcompute.VirtualMachineListResult{Value: v[half:]}})
}

type fakeDisks []*armcompute.Disk

func (f fakeDisks) NewListPager(*armcompute.DisksClientListOptions) *runtime.Pager[armcompute.DisksClientListResponse] {
	return pagerOf[armcompute.DisksClientListResponse](nil, armcompute.DisksClientListResponse{DiskList: armcompute.DiskList{Value: f}})
}

type fakeNSGs []*armnetwork.SecurityGroup

func (f fakeNSGs) NewListAllPager(*armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse] {
	return pagerOf[armnetwork.SecurityGroupsClientListAllResponse](nil, armnetwork.SecurityGroupsClientListAllResponse{SecurityGroupListResult: armnetwork.SecurityGroupListResult{Value: f}})
}

type fakeNICs []*armnetwork.Interface

func (f fakeNICs) NewListAllPager(*armnetwork.InterfacesClientListAllOptions) *runtime.Pager[armnetwork.InterfacesClientListAllResponse] {
	return pagerOf[armnetwork.InterfacesClientListAllResponse](nil, armnetwork.InterfacesClientListAllResponse{InterfaceListResult: armnetwork.InterfaceListResult{Value: f}})
}

type fakePIPs []*armnetwork.PublicIPAddress

func (f fakePIPs) NewListAllPager(*armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse] {
	return pagerOf[armnetwork.PublicIPAddressesClientListAllResponse](nil, armnetwork.PublicIPAddressesClientListAllResponse{PublicIPAddressListResult: armnetwork.PublicIPAddressListResult{Value: f}})
}

type fakeStorage struct {
	accts []*armstorage.Account
	err   error
}

func (f fakeStorage) NewListPager(*armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse] {
	return pagerOf[armstorage.AccountsClientListResponse](f.err, armstorage.AccountsClientListResponse{AccountListResult: armstorage.AccountListResult{Value: f.accts}})
}

type fakeSQL []*armsql.Server

func (f fakeSQL) NewListPager(*armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse] {
	return pagerOf[armsql.ServersClientListResponse](nil, armsql.ServersClientListResponse{ServerListResult: armsql.ServerListResult{Value: f}})
}

type fakeFW map[string][]*armsql.FirewallRule // "rg/server" -> rules

func (f fakeFW) NewListByServerPager(rg, server string, _ *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse] {
	rules, ok := f[rg+"/"+server]
	if !ok {
		return pagerOf[armsql.FirewallRulesClientListByServerResponse](errors.New("server not found"))
	}
	return pagerOf[armsql.FirewallRulesClientListByServerResponse](nil, armsql.FirewallRulesClientListByServerResponse{FirewallRuleListResult: armsql.FirewallRuleListResult{Value: rules}})
}

type fakeVaults []*armkeyvault.Vault

func (f fakeVaults) NewListBySubscriptionPager(*armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse] {
	return pagerOf[armkeyvault.VaultsClientListBySubscriptionResponse](nil, armkeyvault.VaultsClientListBySubscriptionResponse{VaultListResult: armkeyvault.VaultListResult{Value: f}})
}

type fakeGraph struct{ calls int }

func (f *fakeGraph) Resources(_ context.Context, q armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	f.calls++
	var resp armresourcegraph.ClientResourcesResponse
	switch {
	case strings.Contains(*q.Query, "summarize"):
		if q.Options.SkipToken == nil {
			resp.Data = []any{map[string]any{"type": "microsoft.compute/virtualmachines", "count_": float64(2)}}
			resp.SkipToken = to.Ptr("page2")
		} else {
			resp.Data = []any{map[string]any{"type": "microsoft.storage/storageaccounts", "count_": float64(2)}}
		}
	case strings.Contains(*q.Query, "managedclusters"):
		resp.Data = []any{map[string]any{"id": aksID, "name": "aks1", "location": "eastus", "enableRBAC": false, "tags": map[string]any{"env": "prod"}}}
	}
	return resp, nil
}

type fakeSubs []string

func (f fakeSubs) NewListPager(*armsubscription.SubscriptionsClientListOptions) *runtime.Pager[armsubscription.SubscriptionsClientListResponse] {
	var subs []*armsubscription.Subscription
	for _, s := range f {
		subs = append(subs, &armsubscription.Subscription{SubscriptionID: to.Ptr(s), State: to.Ptr(armsubscription.SubscriptionStateEnabled)})
	}
	subs = append(subs, &armsubscription.Subscription{SubscriptionID: to.Ptr("disabled"), State: to.Ptr(armsubscription.SubscriptionStateDisabled)})
	return pagerOf[armsubscription.SubscriptionsClientListResponse](nil, armsubscription.SubscriptionsClientListResponse{ListResult: armsubscription.ListResult{Value: subs}})
}

// ---------------------------------------------------------------- fixtures

const (
	sub      = "00000000-0000-0000-0000-000000000001"
	rgp      = "/subscriptions/" + sub + "/resourceGroups/rg1/providers/"
	nsgOpen  = rgp + "Microsoft.Network/networkSecurityGroups/web-nsg"
	nsgShut  = rgp + "Microsoft.Network/networkSecurityGroups/db-nsg"
	subnetDB = rgp + "Microsoft.Network/virtualNetworks/vnet/subnets/db"
	vmWeb    = rgp + "Microsoft.Compute/virtualMachines/web-prod"
	vmDB     = rgp + "Microsoft.Compute/virtualMachines/db-vm"
	vmBare   = rgp + "Microsoft.Compute/virtualMachines/bare"
	aksID    = rgp + "Microsoft.ContainerService/managedClusters/aks1"
	sqlID    = rgp + "Microsoft.Sql/servers/customers-sql"
	sqlID2   = rgp + "Microsoft.Sql/servers/private-sql"
)

func rule(name string, prio int32, access armnetwork.SecurityRuleAccess, src, ports string, extraPorts ...string) *armnetwork.SecurityRule {
	p := &armnetwork.SecurityRulePropertiesFormat{
		Access: to.Ptr(access), Direction: to.Ptr(armnetwork.SecurityRuleDirectionInbound), Priority: to.Ptr(prio),
		Protocol: to.Ptr(armnetwork.SecurityRuleProtocolAsterisk), SourceAddressPrefix: to.Ptr(src),
	}
	if ports != "" {
		p.DestinationPortRange = to.Ptr(ports)
	}
	for _, e := range extraPorts {
		p.DestinationPortRanges = append(p.DestinationPortRanges, to.Ptr(e))
	}
	return &armnetwork.SecurityRule{Name: to.Ptr(name), Properties: p}
}

var defaultRules = []*armnetwork.SecurityRule{
	rule("AllowVnetInBound", 65000, armnetwork.SecurityRuleAccessAllow, "VirtualNetwork", "*"),
	rule("AllowAzureLoadBalancerInBound", 65001, armnetwork.SecurityRuleAccessAllow, "AzureLoadBalancer", "*"),
	rule("DenyAllInBound", 65500, armnetwork.SecurityRuleAccessDeny, "*", "*"),
}

func nsg(id string, rules []*armnetwork.SecurityRule, subnets ...string) *armnetwork.SecurityGroup {
	n := &armnetwork.SecurityGroup{ID: to.Ptr(id), Name: to.Ptr(id[strings.LastIndex(id, "/")+1:]), Location: to.Ptr("eastus"),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: rules, DefaultSecurityRules: defaultRules}}
	for _, s := range subnets {
		n.Properties.Subnets = append(n.Properties.Subnets, &armnetwork.Subnet{ID: to.Ptr(s)})
	}
	return n
}

func nic(name, nsgID, subnet, pip string) *armnetwork.Interface {
	ipc := &armnetwork.InterfaceIPConfiguration{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{Subnet: &armnetwork.Subnet{ID: to.Ptr(subnet)}}}
	if pip != "" {
		ipc.Properties.PublicIPAddress = &armnetwork.PublicIPAddress{ID: to.Ptr(pip)}
	}
	n := &armnetwork.Interface{ID: to.Ptr(rgp + "Microsoft.Network/networkInterfaces/" + name),
		Properties: &armnetwork.InterfacePropertiesFormat{IPConfigurations: []*armnetwork.InterfaceIPConfiguration{ipc}}}
	if nsgID != "" {
		// Reference with different casing than the NSG listing, as ARM sometimes returns.
		n.Properties.NetworkSecurityGroup = &armnetwork.SecurityGroup{ID: to.Ptr(strings.ToLower(nsgID))}
	}
	return n
}

func vm(id, nicName, size string, tags map[string]*string) *armcompute.VirtualMachine {
	return &armcompute.VirtualMachine{ID: to.Ptr(id), Name: to.Ptr(id[strings.LastIndex(id, "/")+1:]), Location: to.Ptr("eastus"), Tags: tags,
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(size))},
			NetworkProfile:  &armcompute.NetworkProfile{NetworkInterfaces: []*armcompute.NetworkInterfaceReference{{ID: to.Ptr(rgp + "Microsoft.Network/networkInterfaces/" + nicName)}}},
			TimeCreated:     to.Ptr(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)),
		}}
}

func pip(name, ip string, attached bool) *armnetwork.PublicIPAddress {
	p := &armnetwork.PublicIPAddress{ID: to.Ptr(rgp + "Microsoft.Network/publicIPAddresses/" + name), Location: to.Ptr("eastus"),
		SKU:        &armnetwork.PublicIPAddressSKU{Name: to.Ptr(armnetwork.PublicIPAddressSKUNameStandard)},
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr(ip)}}
	if attached {
		p.Properties.IPConfiguration = &armnetwork.IPConfiguration{ID: to.Ptr("ipconfig")}
	}
	return p
}

func fixtureClients() *Clients {
	return &Clients{
		SubscriptionID: sub,
		Graph:          &fakeGraph{},
		VMs: fakeVMs{
			vms: []*armcompute.VirtualMachine{
				vm(vmWeb, "web-nic", "Standard_D4s_v5", map[string]*string{"environment": to.Ptr("production"), "owner": to.Ptr("web-team")}),
				vm(vmDB, "db-nic", "Standard_E8s_v5", nil),
				vm(vmBare, "bare-nic", "Standard_B2s", nil),
			},
			status: []*armcompute.VirtualMachine{
				{ID: to.Ptr(vmDB), Properties: &armcompute.VirtualMachineProperties{InstanceView: &armcompute.VirtualMachineInstanceView{
					Statuses: []*armcompute.InstanceViewStatus{{Code: to.Ptr("ProvisioningState/succeeded")}, {Code: to.Ptr("PowerState/stopped")}}}}},
				{ID: to.Ptr(vmWeb), Properties: &armcompute.VirtualMachineProperties{InstanceView: &armcompute.VirtualMachineInstanceView{
					Statuses: []*armcompute.InstanceViewStatus{{Code: to.Ptr("PowerState/running")}}}}},
			},
		},
		Disks: fakeDisks{
			{ID: to.Ptr(rgp + "Microsoft.Compute/disks/orphan"), Name: to.Ptr("orphan"), Location: to.Ptr("eastus"),
				SKU:        &armcompute.DiskSKU{Name: to.Ptr(armcompute.DiskStorageAccountTypesPremiumLRS)},
				Properties: &armcompute.DiskProperties{DiskSizeGB: to.Ptr[int32](128), DiskState: to.Ptr(armcompute.DiskStateUnattached)}},
			{ID: to.Ptr(rgp + "Microsoft.Compute/disks/web-os"), Name: to.Ptr("web-os"), Location: to.Ptr("eastus"), ManagedBy: to.Ptr(vmWeb),
				Properties: &armcompute.DiskProperties{DiskSizeGB: to.Ptr[int32](64), DiskState: to.Ptr(armcompute.DiskStateAttached)}},
		},
		NSGs: fakeNSGs{
			nsg(nsgOpen, []*armnetwork.SecurityRule{rule("ssh", 100, armnetwork.SecurityRuleAccessAllow, "Internet", "22"), rule("https", 110, armnetwork.SecurityRuleAccessAllow, "*", "443")}),
			nsg(nsgShut, []*armnetwork.SecurityRule{rule("vnet-sql", 100, armnetwork.SecurityRuleAccessAllow, "10.0.0.0/8", "1433")}, subnetDB),
		},
		NICs: fakeNICs{
			nic("web-nic", nsgOpen, rgp+"Microsoft.Network/virtualNetworks/vnet/subnets/web", rgp+"Microsoft.Network/publicIPAddresses/web-ip"),
			nic("db-nic", "", subnetDB, rgp+"Microsoft.Network/publicIPAddresses/db-ip"),
			nic("bare-nic", "", rgp+"Microsoft.Network/virtualNetworks/vnet/subnets/none", rgp+"Microsoft.Network/publicIPAddresses/bare-ip"),
		},
		PublicIPs: fakePIPs{pip("web-ip", "20.1.1.1", true), pip("db-ip", "20.1.1.2", true), pip("bare-ip", "20.1.1.3", true), pip("spare-ip", "20.1.1.9", false)},
		Storage: fakeStorage{accts: []*armstorage.Account{
			{ID: to.Ptr(rgp + "Microsoft.Storage/storageAccounts/custdata"), Name: to.Ptr("custdata"), Location: to.Ptr("eastus"),
				Tags:       map[string]*string{"data_classification": to.Ptr("PII")},
				Properties: &armstorage.AccountProperties{AllowBlobPublicAccess: to.Ptr(true), EnableHTTPSTrafficOnly: to.Ptr(false)}},
			{ID: to.Ptr(rgp + "Microsoft.Storage/storageAccounts/logs"), Name: to.Ptr("logs"), Location: to.Ptr("eastus"),
				Properties: &armstorage.AccountProperties{AllowBlobPublicAccess: to.Ptr(false), EnableHTTPSTrafficOnly: to.Ptr(true)}},
		}},
		SQLServers: fakeSQL{
			{ID: to.Ptr(sqlID), Name: to.Ptr("customers-sql"), Location: to.Ptr("eastus"), Properties: &armsql.ServerProperties{PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagEnabled)}},
			{ID: to.Ptr(sqlID2), Name: to.Ptr("private-sql"), Location: to.Ptr("eastus"), Properties: &armsql.ServerProperties{PublicNetworkAccess: to.Ptr(armsql.ServerNetworkAccessFlagEnabled)}},
		},
		SQLFirewall: fakeFW{
			"rg1/customers-sql": {{Name: to.Ptr("everyone"), Properties: &armsql.ServerFirewallRuleProperties{StartIPAddress: to.Ptr("0.0.0.0"), EndIPAddress: to.Ptr("255.255.255.255")}}},
			"rg1/private-sql":   {{Name: to.Ptr("AllowAllWindowsAzureIps"), Properties: &armsql.ServerFirewallRuleProperties{StartIPAddress: to.Ptr("0.0.0.0"), EndIPAddress: to.Ptr("0.0.0.0")}}},
		},
		Vaults: fakeVaults{
			{ID: to.Ptr(rgp + "Microsoft.KeyVault/vaults/kv-weak"), Name: to.Ptr("kv-weak"), Location: to.Ptr("eastus"), Properties: &armkeyvault.VaultProperties{EnableSoftDelete: to.Ptr(true)}},
			{ID: to.Ptr(rgp + "Microsoft.KeyVault/vaults/kv-good"), Name: to.Ptr("kv-good"), Location: to.Ptr("eastus"), Properties: &armkeyvault.VaultProperties{EnableSoftDelete: to.Ptr(true), EnablePurgeProtection: to.Ptr(true)}},
		},
	}
}

func newTestCollector(clients func(spec core.AccountSpec) (*Clients, error)) *Collector {
	return &Collector{
		NewClients:  func(_ context.Context, spec core.AccountSpec) (*Clients, error) { return clients(spec) },
		Concurrency: 4,
		Now:         func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func statusOf(t *testing.T, fs []model.Finding, check, resourceSuffix string) model.Status {
	t.Helper()
	for _, f := range fs {
		if f.CheckID == check && strings.HasSuffix(f.Resource.ID, resourceSuffix) {
			return f.Status
		}
	}
	t.Fatalf("no %s finding for %s", check, resourceSuffix)
	return ""
}

func hasEdge(g *graph.Graph, from, to, kind string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- tests

func TestInternetAllowsPort(t *testing.T) {
	allow, deny := armnetwork.SecurityRuleAccessAllow, armnetwork.SecurityRuleAccessDeny
	tests := []struct {
		name      string
		rules     []*armnetwork.SecurityRule
		port      int
		want      bool
		wantPorts []string
	}{
		{"default rules only", nil, 22, false, nil},
		{"internet tag single port", []*armnetwork.SecurityRule{rule("a", 100, allow, "Internet", "22")}, 22, true, []string{"22"}},
		{"star source range covers", []*armnetwork.SecurityRule{rule("a", 100, allow, "*", "20-30")}, 22, true, []string{"20-30"}},
		{"range does not cover", []*armnetwork.SecurityRule{rule("a", 100, allow, "0.0.0.0/0", "1000-2000")}, 3389, false, []string{"1000-2000"}},
		{"port ranges list", []*armnetwork.SecurityRule{rule("a", 100, allow, "Any", "", "80", "3389")}, 3389, true, []string{"3389", "80"}},
		{"all ports", []*armnetwork.SecurityRule{rule("a", 100, allow, "Internet", "*")}, 3389, true, []string{"*"}},
		{"private source", []*armnetwork.SecurityRule{rule("a", 100, allow, "10.0.0.0/8", "22")}, 22, false, nil},
		{"service tag VirtualNetwork", []*armnetwork.SecurityRule{rule("a", 100, allow, "VirtualNetwork", "22")}, 22, false, nil},
		{"higher priority deny wins", []*armnetwork.SecurityRule{rule("allow", 200, allow, "Internet", "22"), rule("deny", 100, deny, "*", "22")}, 22, false, nil},
		{"allow beats lower priority deny", []*armnetwork.SecurityRule{rule("allow", 100, allow, "Internet", "22"), rule("deny", 200, deny, "*", "22")}, 22, true, []string{"22"}},
		{"source prefixes list", []*armnetwork.SecurityRule{func() *armnetwork.SecurityRule {
			r := rule("a", 100, allow, "", "22")
			r.Properties.SourceAddressPrefix = nil
			r.Properties.SourceAddressPrefixes = []*string{to.Ptr("1.2.3.4/32"), to.Ptr("0.0.0.0/0")}
			return r
		}()}, 22, true, []string{"22"}},
		{"udp only", []*armnetwork.SecurityRule{func() *armnetwork.SecurityRule {
			r := rule("a", 100, allow, "Internet", "22")
			r.Properties.Protocol = to.Ptr(armnetwork.SecurityRuleProtocolUDP)
			return r
		}()}, 22, false, []string{"22"}},
		{"outbound ignored", []*armnetwork.SecurityRule{func() *armnetwork.SecurityRule {
			r := rule("a", 100, allow, "Internet", "22")
			r.Properties.Direction = to.Ptr(armnetwork.SecurityRuleDirectionOutbound)
			return r
		}()}, 22, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := nsg(nsgOpen, tt.rules)
			if got := InternetAllowsPort(n, tt.port); got != tt.want {
				t.Fatalf("InternetAllowsPort(%d) = %v, want %v", tt.port, got, tt.want)
			}
			if got := InternetOpenPorts(n); !slices.Equal(got, tt.wantPorts) {
				t.Fatalf("InternetOpenPorts = %v, want %v", got, tt.wantPorts)
			}
		})
	}
}

func TestSpecCoversAndHelpers(t *testing.T) {
	tests := []struct {
		spec string
		port int
		want bool
	}{{"*", 1, true}, {"22", 22, true}, {"22", 23, false}, {"0-65535", 3389, true}, {" 3380 - 3390 ", 3389, true}, {"bogus", 22, false}}
	for _, tt := range tests {
		if got := specCovers(tt.spec, tt.port); got != tt.want {
			t.Errorf("specCovers(%q,%d)=%v", tt.spec, tt.port, got)
		}
	}
	rgs := map[string]string{nsgOpen: "rg1", "/subscriptions/x/RESOURCEGROUPS/Big/providers/a/b": "Big", "/subscriptions/x": ""}
	for id, want := range rgs {
		if got := ResourceGroup(id); got != want {
			t.Errorf("ResourceGroup(%q)=%q want %q", id, got, want)
		}
	}
	fw := []struct {
		start, end string
		want       bool
	}{{"0.0.0.0", "255.255.255.255", true}, {"0.0.0.0", "0.0.0.0", false}, {"10.0.0.0", "10.255.255.255", false}}
	for _, tt := range fw {
		r := &armsql.FirewallRule{Properties: &armsql.ServerFirewallRuleProperties{StartIPAddress: to.Ptr(tt.start), EndIPAddress: to.Ptr(tt.end)}}
		if internetRule(r) != tt.want {
			t.Errorf("internetRule(%s-%s) != %v", tt.start, tt.end, tt.want)
		}
	}
}

func TestCollectFindings(t *testing.T) {
	g := graph.New()
	c := newTestCollector(func(core.AccountSpec) (*Clients, error) { return fixtureClients(), nil })
	res, err := c.Collect(context.Background(), core.AccountSpec{Name: "corp-prod", Provider: "azure", SubscriptionID: sub}, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	tests := []struct {
		check, resource string
		want            model.Status
	}{
		{"network_ssh_internet_access_restricted", "web-nsg", model.Fail},
		{"network_ssh_internet_access_restricted", "db-nsg", model.Pass},
		{"network_rdp_internet_access_restricted", "web-nsg", model.Pass},
		{"storage_blob_public_access_level_is_disabled", "custdata", model.Fail},
		{"storage_blob_public_access_level_is_disabled", "logs", model.Pass},
		{"storage_secure_transfer_required_is_enabled", "custdata", model.Fail},
		{"storage_secure_transfer_required_is_enabled", "logs", model.Pass},
		{"sqlserver_firewall_rules_no_ingress_from_internet", "customers-sql", model.Fail},
		{"sqlserver_firewall_rules_no_ingress_from_internet", "private-sql", model.Pass},
		{"keyvault_recoverable", "kv-weak", model.Fail},
		{"keyvault_recoverable", "kv-good", model.Pass},
		{"aks_cluster_rbac_enabled", "aks1", model.Fail},
	}
	for _, tt := range tests {
		t.Run(tt.check+"/"+tt.resource, func(t *testing.T) {
			if got := statusOf(t, res.Findings, tt.check, tt.resource); got != tt.want {
				t.Fatalf("status = %s, want %s", got, tt.want)
			}
		})
	}
	for _, f := range res.Findings {
		if f.Source != "nimbus" || f.Provider != "azure" || f.Account != sub || f.ID == "" {
			t.Fatalf("bad finding envelope: %+v", f)
		}
		if f.CheckID == "network_ssh_internet_access_restricted" && f.CanonicalID != "AZ_NSG_OPEN_SSH" {
			t.Fatalf("canonical id not enriched: %s", f.CanonicalID)
		}
		if f.Tags["account_label"] != "corp-prod" {
			t.Fatalf("account label tag missing: %v", f.Tags)
		}
	}
	if len(res.Runs) != 1 || res.Runs[0].Status != "ok" || res.Runs[0].Findings != len(res.Findings) {
		t.Fatalf("runs = %+v", res.Runs)
	}
}

func TestCollectGraph(t *testing.T) {
	g := graph.New()
	c := newTestCollector(func(core.AccountSpec) (*Clients, error) { return fixtureClients(), nil })
	if _, err := c.Collect(context.Background(), core.AccountSpec{Name: "corp", SubscriptionID: sub}, g); err != nil {
		t.Fatal(err)
	}
	acct := core.AccountNodeID("azure", sub)
	storage := rgp + "Microsoft.Storage/storageAccounts/custdata"
	edges := []struct {
		name           string
		from, to, kind string
		want           bool
	}{
		{"account contains vm", acct, vmWeb, graph.EdgeContains, true},
		{"vm attached to nic nsg (canonical casing)", vmWeb, nsgOpen, graph.EdgeAttachedTo, true},
		{"vm attached to subnet nsg", vmDB, nsgShut, graph.EdgeAttachedTo, true},
		{"nsg allows traffic to vm", nsgOpen, vmWeb, graph.EdgeAllowsTrafficTo, true},
		{"internet exposes web vm", graph.InternetNodeID, vmWeb, graph.EdgeExposes, true},
		{"closed nsg vm not exposed", graph.InternetNodeID, vmDB, graph.EdgeExposes, false},
		{"vm without any nsg is exposed", graph.InternetNodeID, vmBare, graph.EdgeExposes, true},
		{"public blob exposed", graph.InternetNodeID, storage, graph.EdgeExposes, true},
		{"private storage not exposed", graph.InternetNodeID, rgp + "Microsoft.Storage/storageAccounts/logs", graph.EdgeExposes, false},
		{"sql internet rule exposed", graph.InternetNodeID, sqlID, graph.EdgeExposes, true},
		{"allow-azure sql not exposed", graph.InternetNodeID, sqlID2, graph.EdgeExposes, false},
		{"vm attached to disk", vmWeb, rgp + "Microsoft.Compute/disks/web-os", graph.EdgeAttachedTo, true},
	}
	for _, tt := range edges {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasEdge(g, tt.from, tt.to, tt.kind); got != tt.want {
				t.Fatalf("edge %s -%s-> %s = %v, want %v", tt.from, tt.kind, tt.to, got, tt.want)
			}
		})
	}
	if _, ok := g.Node(strings.ToLower(nsgOpen)); ok {
		t.Fatal("lower-cased duplicate NSG node created")
	}
	web, _ := g.Node(vmWeb)
	if web.Criticality != "production" || web.Owner != "web-team" || web.ModifiedAt == "" || web.Type != "azure_virtual_machine" {
		t.Fatalf("web vm context = %+v", web)
	}
	if web.Attributes["public_ip"] != "20.1.1.1" || web.Attributes["vm_size"] != "Standard_D4s_v5" {
		t.Fatalf("web vm attrs = %v", web.Attributes)
	}
	for e := range slices.Values(g.Out(nsgOpen)) {
		if e.Kind == graph.EdgeAllowsTrafficTo && e.Attr["internet_ports"] != "22,443" {
			t.Fatalf("allows_traffic_to attrs = %v", e.Attr)
		}
	}
	for _, id := range []string{storage, sqlID, rgp + "Microsoft.KeyVault/vaults/kv-weak"} {
		if n, _ := g.Node(id); !n.Sensitive {
			t.Errorf("%s should be sensitive", id)
		}
	}
	if n, _ := g.Node(rgp + "Microsoft.Network/networkSecurityGroups/web-nsg"); !n.HasWeakness("PUBLIC_NETWORK_EXPOSURE") || len(n.FindingIDs) == 0 {
		t.Fatalf("FAIL finding not attached to NSG node: %+v", n)
	}
	if n, _ := g.Node(acct); n.Type != "azure_subscription" || n.Attributes["resource_counts"] == nil {
		t.Fatalf("account node = %+v", n)
	} else if counts := n.Attributes["resource_counts"].(map[string]any); counts["microsoft.storage/storageaccounts"] != 2 {
		t.Fatalf("resource graph pagination not followed: %v", counts)
	}
}

func TestCollectCostSignals(t *testing.T) {
	c := newTestCollector(func(core.AccountSpec) (*Clients, error) { return fixtureClients(), nil })
	res, err := c.Collect(context.Background(), core.AccountSpec{SubscriptionID: sub}, graph.New())
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string][]core.CostSignal{}
	for _, s := range res.Cost {
		byKind[s.Kind] = append(byKind[s.Kind], s)
	}
	tests := []struct {
		kind, suffix string
		check        func(core.CostSignal) bool
	}{
		{core.KindUnattachedVolume, "disks/orphan", func(s core.CostSignal) bool { return s.SizeGB == 128 && s.Attributes["sku"] == "Premium_LRS" }},
		{core.KindUnassociatedIP, "publicIPAddresses/spare-ip", func(s core.CostSignal) bool { return s.ResourceType == "azure_public_ip" }},
		{core.KindStoppedInstance, "virtualMachines/db-vm", func(s core.CostSignal) bool { return s.InstanceType == "Standard_E8s_v5" }},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := byKind[tt.kind]
			if len(got) != 1 || !strings.HasSuffix(got[0].ResourceID, tt.suffix) || !tt.check(got[0]) || got[0].Provider != "azure" || got[0].Region != "eastus" {
				t.Fatalf("%s signals = %+v", tt.kind, got)
			}
		})
	}
}

func TestPartialFailure(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Clients)
		wantErrSub string
		stillCheck string
	}{
		{"storage list fails", func(c *Clients) { c.Storage = fakeStorage{err: errors.New("AuthorizationFailed")} }, "storage.accounts", "network_ssh_internet_access_restricted"},
		{"sql firewall fails for one server", func(c *Clients) { delete(c.SQLFirewall.(fakeFW), "rg1/private-sql") }, "sql.firewallrules/private-sql", "storage_secure_transfer_required_is_enabled"},
		{"missing services skipped", func(c *Clients) { c.VMs, c.NICs, c.Graph = nil, nil, nil }, "", "keyvault_recoverable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := fixtureClients()
			tt.mutate(cl)
			c := newTestCollector(func(core.AccountSpec) (*Clients, error) { return cl, nil })
			res, err := c.Collect(context.Background(), core.AccountSpec{SubscriptionID: sub}, graph.New())
			if err != nil {
				t.Fatalf("partial failure must not fail Collect: %v", err)
			}
			if tt.wantErrSub == "" && len(res.Errors) != 0 {
				t.Fatalf("errors = %v", res.Errors)
			}
			if tt.wantErrSub != "" && (len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Error(), tt.wantErrSub)) {
				t.Fatalf("errors = %v, want one containing %q", res.Errors, tt.wantErrSub)
			}
			found := false
			for _, f := range res.Findings {
				found = found || f.CheckID == tt.stillCheck
			}
			if !found {
				t.Fatalf("other services should still report %s", tt.stillCheck)
			}
		})
	}
}

func TestSubscriptionEnumeration(t *testing.T) {
	tests := []struct {
		name     string
		failSubs map[string]bool
		wantErr  bool
		wantRuns int
	}{
		{"both ok", nil, false, 2},
		{"one fails", map[string]bool{"sub-b": true}, false, 2},
		{"all fail", map[string]bool{"sub-a": true, "sub-b": true}, true, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCollector(func(spec core.AccountSpec) (*Clients, error) {
				if tt.failSubs[spec.SubscriptionID] {
					return nil, errors.New("denied")
				}
				return &Clients{SubscriptionID: spec.SubscriptionID, Vaults: fakeVaults{}}, nil
			})
			c.Subscriptions = func(ctx context.Context, _ core.AccountSpec) ([]string, error) { return listSubscriptions(ctx, fakeSubs{"sub-a", "sub-b"}) }
			g := graph.New()
			res, err := c.Collect(context.Background(), core.AccountSpec{Name: "tenant"}, g)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(res.Runs) != tt.wantRuns {
				t.Fatalf("runs = %+v", res.Runs)
			}
			if len(res.Errors) != len(tt.failSubs) {
				t.Fatalf("errors = %v", res.Errors)
			}
			if _, ok := g.Node(core.AccountNodeID("azure", "disabled")); ok {
				t.Fatal("disabled subscription collected")
			}
		})
	}
}

func TestInterfaceConformance(t *testing.T) {
	var _ core.Collector = New()
	if New().Name() != "azure" || New().Provider() != "azure" {
		t.Fatal("name/provider")
	}
}
