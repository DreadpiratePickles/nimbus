package azure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Collector implements core.Collector for Azure subscriptions.
type Collector struct {
	// NewClients builds the per-subscription clients (spec.SubscriptionID is always set).
	NewClients func(ctx context.Context, spec core.AccountSpec) (*Clients, error)
	// Subscriptions enumerates subscriptions when spec.SubscriptionID is empty.
	Subscriptions func(ctx context.Context, spec core.AccountSpec) ([]string, error)
	// Concurrency bounds parallel service calls per subscription (default 6).
	Concurrency int
	Now         func() time.Time
}

// New returns a collector backed by the real Azure SDK.
func New() *Collector {
	return &Collector{NewClients: NewSDKClients, Subscriptions: ListSDKSubscriptions, Concurrency: 6, Now: time.Now}
}

func (c *Collector) Name() string     { return "azure" }
func (c *Collector) Provider() string { return model.ProviderAzure }

// Collect gathers every subscription named by (or visible to) spec. Partial failures
// are reported in Result.Errors; an error is returned only when nothing could be collected.
func (c *Collector) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	var res core.Result
	subs := []string{spec.SubscriptionID}
	if spec.SubscriptionID == "" {
		if c.Subscriptions == nil {
			return res, errors.New("azure: no subscription id and no subscription lister")
		}
		list, err := c.Subscriptions(ctx, spec)
		if err != nil {
			return res, fmt.Errorf("azure: list subscriptions: %w", err)
		}
		if len(list) == 0 {
			return res, errors.New("azure: credential sees no enabled subscriptions")
		}
		subs = list
	}
	var failed int
	for _, sub := range subs {
		s := spec
		s.SubscriptionID = sub
		r, err := c.collectSubscription(ctx, s, g)
		res.Merge(r)
		if err != nil {
			failed++
			res.Errors = append(res.Errors, err)
		}
	}
	if failed == len(subs) {
		return res, fmt.Errorf("azure: all %d subscription(s) failed: %w", failed, errors.Join(res.Errors...))
	}
	return res, nil
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) collectSubscription(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	run := model.ToolRun{Tool: "nimbus-azure", Account: spec.SubscriptionID, Status: "ok"}
	if c.NewClients == nil {
		return core.Result{}, errors.New("azure: no client factory")
	}
	cl, err := c.NewClients(ctx, spec)
	if err != nil {
		run.Status, run.Message = "failed", err.Error()
		return core.Result{Runs: []model.ToolRun{run}}, fmt.Errorf("azure %s: %w", spec.SubscriptionID, err)
	}
	acc := &core.Acc{}
	inv := c.fetch(ctx, cl, acc)
	build(spec, inv, g, acc, c.now())
	r := acc.Result()
	run.Findings = len(r.Findings)
	if len(r.Errors) > 0 {
		run.Message = fmt.Sprintf("%d partial error(s)", len(r.Errors))
	}
	r.Runs = append(r.Runs, run)
	return r, nil
}

// inventory is the raw subscription snapshot. Each field is written by exactly one task.
type inventory struct {
	Subscription string
	VMs          []*armcompute.VirtualMachine
	PowerState   map[string]string // lower(vm id) -> PowerState/<x>
	Disks        []*armcompute.Disk
	NSGs         []*armnetwork.SecurityGroup
	NICs         []*armnetwork.Interface
	PublicIPs    []*armnetwork.PublicIPAddress
	Storage      []*armstorage.Account
	SQL          []sqlServer
	Vaults       []*armkeyvault.Vault
	AKS          []map[string]any
	TypeCounts   map[string]int
}

type sqlServer struct {
	Server   *armsql.Server
	Rules    []*armsql.FirewallRule
	RulesErr error
}

func (c *Collector) fetch(ctx context.Context, cl *Clients, acc *core.Acc) *inventory {
	inv := &inventory{Subscription: cl.SubscriptionID, PowerState: map[string]string{}, TypeCounts: map[string]int{}}
	var tasks []core.Task
	add := func(name string, ok bool, fn func(ctx context.Context) error) {
		if ok {
			tasks = append(tasks, core.Task{Name: "azure/" + cl.SubscriptionID + "/" + name, Fn: fn})
		}
	}
	add("resourcegraph", cl.Graph != nil, func(ctx context.Context) error { return fetchGraph(ctx, cl, inv) })
	add("compute.vms", cl.VMs != nil, func(ctx context.Context) error {
		if err := drain(ctx, cl.VMs.NewListAllPager(nil), func(p armcompute.VirtualMachinesClientListAllResponse) {
			inv.VMs = append(inv.VMs, p.Value...)
		}); err != nil {
			return err
		}
		// statusOnly returns the instance view (power state) for the whole subscription in one listing.
		err := drain(ctx, cl.VMs.NewListAllPager(&armcompute.VirtualMachinesClientListAllOptions{StatusOnly: to.Ptr("true")}), func(p armcompute.VirtualMachinesClientListAllResponse) {
			for _, vm := range p.Value {
				if vm == nil || vm.ID == nil || vm.Properties == nil || vm.Properties.InstanceView == nil {
					continue
				}
				for _, st := range vm.Properties.InstanceView.Statuses {
					if st != nil && st.Code != nil && strings.HasPrefix(*st.Code, "PowerState/") {
						inv.PowerState[strings.ToLower(*vm.ID)] = *st.Code
					}
				}
			}
		})
		if err != nil {
			acc.Warn("azure %s: VM power state unavailable: %v", cl.SubscriptionID, err)
		}
		return nil
	})
	add("compute.disks", cl.Disks != nil, func(ctx context.Context) error {
		return drain(ctx, cl.Disks.NewListPager(nil), func(p armcompute.DisksClientListResponse) { inv.Disks = append(inv.Disks, p.Value...) })
	})
	add("network.nsgs", cl.NSGs != nil, func(ctx context.Context) error {
		return drain(ctx, cl.NSGs.NewListAllPager(nil), func(p armnetwork.SecurityGroupsClientListAllResponse) { inv.NSGs = append(inv.NSGs, p.Value...) })
	})
	add("network.nics", cl.NICs != nil, func(ctx context.Context) error {
		return drain(ctx, cl.NICs.NewListAllPager(nil), func(p armnetwork.InterfacesClientListAllResponse) { inv.NICs = append(inv.NICs, p.Value...) })
	})
	add("network.publicips", cl.PublicIPs != nil, func(ctx context.Context) error {
		return drain(ctx, cl.PublicIPs.NewListAllPager(nil), func(p armnetwork.PublicIPAddressesClientListAllResponse) {
			inv.PublicIPs = append(inv.PublicIPs, p.Value...)
		})
	})
	add("storage.accounts", cl.Storage != nil, func(ctx context.Context) error {
		return drain(ctx, cl.Storage.NewListPager(nil), func(p armstorage.AccountsClientListResponse) { inv.Storage = append(inv.Storage, p.Value...) })
	})
	add("sql.servers", cl.SQLServers != nil, func(ctx context.Context) error {
		var servers []*armsql.Server
		if err := drain(ctx, cl.SQLServers.NewListPager(nil), func(p armsql.ServersClientListResponse) { servers = append(servers, p.Value...) }); err != nil {
			return err
		}
		for _, s := range servers {
			if s == nil || s.ID == nil {
				continue
			}
			entry := sqlServer{Server: s}
			if cl.SQLFirewall != nil {
				entry.RulesErr = drain(ctx, cl.SQLFirewall.NewListByServerPager(ResourceGroup(*s.ID), str(s.Name), nil), func(p armsql.FirewallRulesClientListByServerResponse) {
					entry.Rules = append(entry.Rules, p.Value...)
				})
				if entry.RulesErr != nil {
					acc.Error("azure/"+cl.SubscriptionID+"/sql.firewallrules/"+str(s.Name), entry.RulesErr)
				}
			}
			inv.SQL = append(inv.SQL, entry)
		}
		return nil
	})
	add("keyvault.vaults", cl.Vaults != nil, func(ctx context.Context) error {
		return drain(ctx, cl.Vaults.NewListBySubscriptionPager(nil), func(p armkeyvault.VaultsClientListBySubscriptionResponse) {
			inv.Vaults = append(inv.Vaults, p.Value...)
		})
	})
	limit := c.Concurrency
	if limit <= 0 {
		limit = 6
	}
	core.RunTasks(ctx, limit, acc, tasks)
	return inv
}

const (
	typeCountQuery = "Resources | summarize count() by type"
	aksQuery       = "Resources | where type =~ 'microsoft.containerservice/managedclusters' | project id, name, location, tags, enableRBAC = properties.enableRBAC, aadProfile = properties.aadProfile"
)

// fetchGraph uses Resource Graph for a fast whole-subscription inventory count and for
// AKS clusters (RBAC flag), following $skipToken pagination.
func fetchGraph(ctx context.Context, cl *Clients, inv *inventory) error {
	err := queryGraph(ctx, cl.Graph, cl.SubscriptionID, typeCountQuery, func(row map[string]any) {
		t, _ := row["type"].(string)
		inv.TypeCounts[strings.ToLower(t)] += toInt(row["count_"])
	})
	if err != nil {
		return err
	}
	return queryGraph(ctx, cl.Graph, cl.SubscriptionID, aksQuery, func(row map[string]any) { inv.AKS = append(inv.AKS, row) })
}

func queryGraph(ctx context.Context, rg ResourceGraph, sub, q string, each func(map[string]any)) error {
	var skip *string
	for range 1000 {
		resp, err := rg.Resources(ctx, armresourcegraph.QueryRequest{
			Query:         to.Ptr(q),
			Subscriptions: []*string{to.Ptr(sub)},
			Options:       &armresourcegraph.QueryRequestOptions{ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray), SkipToken: skip},
		}, nil)
		if err != nil {
			return err
		}
		if rows, ok := resp.Data.([]any); ok {
			for _, r := range rows {
				if m, ok := r.(map[string]any); ok {
					each(m)
				}
			}
		}
		if resp.SkipToken == nil || *resp.SkipToken == "" {
			return nil
		}
		skip = resp.SkipToken
	}
	return nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// ResourceGroup extracts the resource group name from an ARM resource ID.
func ResourceGroup(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

func tagsOf(t map[string]*string) map[string]string {
	if len(t) == 0 {
		return nil
	}
	out := make(map[string]string, len(t))
	for k, v := range t {
		out[k] = str(v)
	}
	return out
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func i32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

func boolv(p *bool) bool { return p != nil && *p }
