// Package azure collects Azure subscriptions agentlessly with the official
// azure-sdk-for-go: Resource Graph for fast enumeration, then ARM clients for
// compute, network, storage, SQL and Key Vault. Every service sits behind a narrow
// pager interface so tests inject fakes built with runtime.NewPager.
package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// VMLister lists every virtual machine in the subscription.
type VMLister interface {
	NewListAllPager(*armcompute.VirtualMachinesClientListAllOptions) *runtime.Pager[armcompute.VirtualMachinesClientListAllResponse]
}

// DiskLister lists managed disks.
type DiskLister interface {
	NewListPager(*armcompute.DisksClientListOptions) *runtime.Pager[armcompute.DisksClientListResponse]
}

// NSGLister lists network security groups.
type NSGLister interface {
	NewListAllPager(*armnetwork.SecurityGroupsClientListAllOptions) *runtime.Pager[armnetwork.SecurityGroupsClientListAllResponse]
}

// NICLister lists network interfaces.
type NICLister interface {
	NewListAllPager(*armnetwork.InterfacesClientListAllOptions) *runtime.Pager[armnetwork.InterfacesClientListAllResponse]
}

// PublicIPLister lists public IP addresses.
type PublicIPLister interface {
	NewListAllPager(*armnetwork.PublicIPAddressesClientListAllOptions) *runtime.Pager[armnetwork.PublicIPAddressesClientListAllResponse]
}

// StorageLister lists storage accounts.
type StorageLister interface {
	NewListPager(*armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse]
}

// SQLServerLister lists Azure SQL logical servers.
type SQLServerLister interface {
	NewListPager(*armsql.ServersClientListOptions) *runtime.Pager[armsql.ServersClientListResponse]
}

// SQLFirewallLister lists server-level firewall rules.
type SQLFirewallLister interface {
	NewListByServerPager(resourceGroupName, serverName string, options *armsql.FirewallRulesClientListByServerOptions) *runtime.Pager[armsql.FirewallRulesClientListByServerResponse]
}

// VaultLister lists key vaults.
type VaultLister interface {
	NewListBySubscriptionPager(*armkeyvault.VaultsClientListBySubscriptionOptions) *runtime.Pager[armkeyvault.VaultsClientListBySubscriptionResponse]
}

// ResourceGraph runs Azure Resource Graph (KQL) queries.
type ResourceGraph interface {
	Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

// SubscriptionLister lists subscriptions visible to the credential.
type SubscriptionLister interface {
	NewListPager(*armsubscription.SubscriptionsClientListOptions) *runtime.Pager[armsubscription.SubscriptionsClientListResponse]
}

// Clients are the per-subscription service clients. Nil members are skipped.
type Clients struct {
	SubscriptionID string
	Graph          ResourceGraph
	VMs            VMLister
	Disks          DiskLister
	NSGs           NSGLister
	NICs           NICLister
	PublicIPs      PublicIPLister
	Storage        StorageLister
	SQLServers     SQLServerLister
	SQLFirewall    SQLFirewallLister
	Vaults         VaultLister
}

// NewSDKClients builds real ARM clients for spec.SubscriptionID with DefaultAzureCredential.
// ARM clients carry the SDK's default retry policy (exponential backoff on 429/5xx).
func NewSDKClients(_ context.Context, spec core.AccountSpec) (*Clients, error) {
	if spec.SubscriptionID == "" {
		return nil, fmt.Errorf("azure: subscription id required")
	}
	cred, err := core.AzureCredential(spec)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	sub := spec.SubscriptionID
	c := &Clients{SubscriptionID: sub}
	var errs []error
	keep := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	rg, err := armresourcegraph.NewClient(cred, nil)
	keep(err)
	if err == nil {
		c.Graph = rg
	}
	if computeF, err := armcompute.NewClientFactory(sub, cred, nil); err == nil {
		c.VMs = computeF.NewVirtualMachinesClient()
		c.Disks = computeF.NewDisksClient()
	} else {
		keep(err)
	}
	if netF, err := armnetwork.NewClientFactory(sub, cred, nil); err == nil {
		c.NSGs = netF.NewSecurityGroupsClient()
		c.NICs = netF.NewInterfacesClient()
		c.PublicIPs = netF.NewPublicIPAddressesClient()
	} else {
		keep(err)
	}
	if st, err := armstorage.NewAccountsClient(sub, cred, nil); err == nil {
		c.Storage = st
	} else {
		keep(err)
	}
	if srv, err := armsql.NewServersClient(sub, cred, nil); err == nil {
		c.SQLServers = srv
	} else {
		keep(err)
	}
	if fw, err := armsql.NewFirewallRulesClient(sub, cred, nil); err == nil {
		c.SQLFirewall = fw
	} else {
		keep(err)
	}
	if kv, err := armkeyvault.NewVaultsClient(sub, cred, nil); err == nil {
		c.Vaults = kv
	} else {
		keep(err)
	}
	if len(errs) > 0 && c.VMs == nil && c.Storage == nil && c.NSGs == nil {
		return nil, fmt.Errorf("azure clients: %v", errs)
	}
	return c, nil
}

// ListSDKSubscriptions enumerates enabled subscriptions for the credential (used when
// spec.SubscriptionID is empty).
func ListSDKSubscriptions(ctx context.Context, spec core.AccountSpec) ([]string, error) {
	cred, err := core.AzureCredential(spec)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	cl, err := armsubscription.NewSubscriptionsClient(cred, nil)
	if err != nil {
		return nil, err
	}
	return listSubscriptions(ctx, cl)
}

func listSubscriptions(ctx context.Context, l SubscriptionLister) ([]string, error) {
	var out []string
	err := drain(ctx, l.NewListPager(nil), func(p armsubscription.SubscriptionsClientListResponse) {
		for _, s := range p.Value {
			if s == nil || s.SubscriptionID == nil {
				continue
			}
			if s.State != nil && *s.State != armsubscription.SubscriptionStateEnabled {
				continue
			}
			out = append(out, *s.SubscriptionID)
		}
	})
	return out, err
}

// drain walks every page of an SDK pager.
func drain[T any](ctx context.Context, p *runtime.Pager[T], each func(T)) error {
	if p == nil {
		return nil
	}
	for p.More() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		each(page)
	}
	return nil
}
