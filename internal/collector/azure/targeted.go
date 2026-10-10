package azure

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Targeted re-collection (plan v3 RM4, W6-VERIFY r4 #8, W7-VERIFY r5 #6): `cloud-posture verify`
// re-reads the storage accounts, network security groups, virtual machines, SQL servers (with
// their firewall rules) and Key Vaults of one Issue through the same build() code as
// Collect and returns the findings and graph fragment of the anchors plus their one-hop
// neighbours. A storage account needs only the storage listing; an NSG needs the network
// inventory its exposure verdict depends on (NSGs, NICs, public IPs, VMs: subnet and NIC NSGs
// layer) and so does a VM, but only the anchor and what is one hop from it is returned. A SQL
// server re-reads the server listing and the firewall rules of the requested servers only; a
// vault the vault listing.

type azRef struct{ id, sub, kind string } // kind: storage | nsg | vm | sql | keyvault

// parseAzureTarget classifies an ARM id; ok=false for a type this collector cannot target yet.
func parseAzureTarget(id string) (azRef, bool) {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	if len(parts) < 8 || !strings.EqualFold(parts[0], "subscriptions") || parts[1] == "" {
		return azRef{}, false
	}
	low := strings.ToLower(id)
	switch {
	case strings.Contains(low, "/providers/microsoft.storage/storageaccounts/") && len(parts) == 8:
		return azRef{id: id, sub: parts[1], kind: "storage"}, true
	case strings.Contains(low, "/providers/microsoft.network/networksecuritygroups/") && len(parts) == 8:
		return azRef{id: id, sub: parts[1], kind: "nsg"}, true
	case strings.Contains(low, "/providers/microsoft.compute/virtualmachines/") && len(parts) == 8:
		return azRef{id: id, sub: parts[1], kind: "vm"}, true
	case strings.Contains(low, "/providers/microsoft.sql/servers/") && len(parts) == 8:
		return azRef{id: id, sub: parts[1], kind: "sql"}, true
	case strings.Contains(low, "/providers/microsoft.keyvault/vaults/") && len(parts) == 8:
		return azRef{id: id, sub: parts[1], kind: "keyvault"}, true
	}
	return azRef{}, false
}

// Target implements core.Targeted. Only client construction failures are fatal; a failed
// listing is a partial error (the read is then inconclusive, never a confirmation).
func (c *Collector) Target(ctx context.Context, spec core.AccountSpec, ids []string) (*core.TargetResult, error) {
	out := &core.TargetResult{}
	bySub := map[string][]azRef{}
	for _, id := range ids {
		r, ok := parseAzureTarget(id)
		if !ok {
			out.Unsupported = append(out.Unsupported, id)
			continue
		}
		bySub[r.sub] = append(bySub[r.sub], r)
	}
	subs := make([]string, 0, len(bySub))
	for s := range bySub {
		subs = append(subs, s)
	}
	sort.Strings(subs)
	if c.NewClients == nil && len(subs) > 0 {
		return nil, fmt.Errorf("azure: no client factory")
	}
	out.Graph = graph.New()
	for _, sub := range subs {
		s := spec
		s.SubscriptionID = sub
		cl, err := c.NewClients(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("azure %s: %w", sub, err)
		}
		if err := c.targetSubscription(ctx, s, cl, bySub[sub], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Collector) targetSubscription(ctx context.Context, spec core.AccountSpec, cl *Clients, refs []azRef, out *core.TargetResult) error {
	inv := &inventory{Subscription: spec.SubscriptionID, PowerState: map[string]string{}, TypeCounts: map[string]int{}}
	acc := &core.Acc{}
	needStorage, needNet, needVaults := false, false, false
	wantSQL := map[string]bool{} // lower server id
	for _, r := range refs {
		switch r.kind {
		case "storage":
			needStorage = true
		case "nsg", "vm":
			needNet = true
		case "sql":
			wantSQL[key(r.id)] = true
		case "keyvault":
			needVaults = true
		}
	}
	listed := map[string]bool{} // kind -> listing succeeded
	pfx := "azure/" + spec.SubscriptionID + "/"
	if needStorage {
		if cl.Storage == nil {
			acc.Error(pfx+"storage.accounts", fmt.Errorf("no storage client"))
		} else if err := drain(ctx, cl.Storage.NewListPager(nil), func(p armstorage.AccountsClientListResponse) { inv.Storage = append(inv.Storage, p.Value...) }); err != nil {
			acc.Error(pfx+"storage.accounts", err)
		} else {
			listed["storage"] = true
		}
	}
	if needNet {
		ok := true
		step := func(name string, present bool, fn func() error) {
			if !present {
				ok = false
				acc.Error(pfx+name, fmt.Errorf("no client"))
				return
			}
			if err := fn(); err != nil {
				ok = false
				acc.Error(pfx+name, err)
			}
		}
		step("network.nsgs", cl.NSGs != nil, func() error {
			return drain(ctx, cl.NSGs.NewListAllPager(nil), func(p armnetwork.SecurityGroupsClientListAllResponse) { inv.NSGs = append(inv.NSGs, p.Value...) })
		})
		step("network.nics", cl.NICs != nil, func() error {
			return drain(ctx, cl.NICs.NewListAllPager(nil), func(p armnetwork.InterfacesClientListAllResponse) { inv.NICs = append(inv.NICs, p.Value...) })
		})
		step("network.publicips", cl.PublicIPs != nil, func() error {
			return drain(ctx, cl.PublicIPs.NewListAllPager(nil), func(p armnetwork.PublicIPAddressesClientListAllResponse) {
				inv.PublicIPs = append(inv.PublicIPs, p.Value...)
			})
		})
		step("compute.vms", cl.VMs != nil, func() error {
			return drain(ctx, cl.VMs.NewListAllPager(nil), func(p armcompute.VirtualMachinesClientListAllResponse) { inv.VMs = append(inv.VMs, p.Value...) })
		})
		listed["nsg"], listed["vm"] = ok, ok
	}
	if len(wantSQL) > 0 {
		// Only the requested servers' firewall rules are read; an unreadable rule list is a
		// partial error (the exposure verdict depends on it).
		if cl.SQLServers == nil {
			acc.Error(pfx+"sql.servers", fmt.Errorf("no SQL client"))
		} else {
			var servers []*armsql.Server
			if err := drain(ctx, cl.SQLServers.NewListPager(nil), func(p armsql.ServersClientListResponse) { servers = append(servers, p.Value...) }); err != nil {
				acc.Error(pfx+"sql.servers", err)
			} else {
				listed["sql"] = true
				for _, srv := range servers {
					if srv == nil || srv.ID == nil || !wantSQL[key(*srv.ID)] {
						continue
					}
					entry := sqlServer{Server: srv}
					if cl.SQLFirewall == nil {
						entry.RulesErr = fmt.Errorf("no SQL firewall client")
					} else {
						entry.RulesErr = drain(ctx, cl.SQLFirewall.NewListByServerPager(ResourceGroup(*srv.ID), str(srv.Name), nil), func(p armsql.FirewallRulesClientListByServerResponse) {
							entry.Rules = append(entry.Rules, p.Value...)
						})
					}
					if entry.RulesErr != nil {
						acc.Error(pfx+"sql.firewallrules/"+str(srv.Name), entry.RulesErr)
					}
					inv.SQL = append(inv.SQL, entry)
				}
			}
		}
	}
	if needVaults {
		if cl.Vaults == nil {
			acc.Error(pfx+"keyvault.vaults", fmt.Errorf("no Key Vault client"))
		} else if err := drain(ctx, cl.Vaults.NewListBySubscriptionPager(nil), func(p armkeyvault.VaultsClientListBySubscriptionResponse) {
			inv.Vaults = append(inv.Vaults, p.Value...)
		}); err != nil {
			acc.Error(pfx+"keyvault.vaults", err)
		} else {
			listed["keyvault"] = true
		}
	}
	have := map[string]string{} // lower id -> listing id
	for _, a := range inv.Storage {
		if a != nil && a.ID != nil {
			have[key(*a.ID)] = *a.ID
		}
	}
	for _, n := range inv.NSGs {
		if n != nil && n.ID != nil {
			have[key(*n.ID)] = *n.ID
		}
	}
	for _, v := range inv.VMs {
		if v != nil && v.ID != nil {
			have[key(*v.ID)] = *v.ID
		}
	}
	for _, s := range inv.SQL {
		have[key(*s.Server.ID)] = *s.Server.ID
	}
	for _, v := range inv.Vaults {
		if v != nil && v.ID != nil {
			have[key(*v.ID)] = *v.ID
		}
	}
	g := graph.New()
	build(spec, inv, g, acc, c.now())
	var anchors []string
	for _, r := range refs {
		if !listed[r.kind] {
			continue // a failed listing proves nothing either way
		}
		if real, ok := have[key(r.id)]; ok {
			anchors = append(anchors, real)
			out.Observed = append(out.Observed, r.id)
		} else {
			out.Missing = append(out.Missing, r.id)
		}
	}
	keep := core.OneHop(g, anchors)
	res := acc.Result()
	for _, f := range res.Findings {
		if keep[f.Resource.ID] {
			out.Findings = append(out.Findings, f)
		}
	}
	out.Graph.Merge(core.Subgraph(g, keep))
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, fmt.Errorf("azure %s: %w", spec.SubscriptionID, e))
	}
	out.Warnings = append(out.Warnings, res.Warnings...)
	return nil
}
