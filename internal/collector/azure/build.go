package azure

import (
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const provider = model.ProviderAzure

// builder turns an inventory snapshot into graph nodes/edges, findings and cost signals.
type builder struct {
	spec core.AccountSpec
	inv  *inventory
	g    *graph.Graph
	acc  *core.Acc
	now  time.Time
	sub  string

	nsgByID     map[string]*armnetwork.SecurityGroup // lower(id) -> nsg
	nsgBySubnet map[string]string                    // lower(subnet id) -> nsg id
	nicByID     map[string]*armnetwork.Interface     // lower(id) -> nic
	pipByID     map[string]*armnetwork.PublicIPAddress
	findings    []model.Finding
}

func build(spec core.AccountSpec, inv *inventory, g *graph.Graph, acc *core.Acc, now time.Time) {
	b := &builder{spec: spec, inv: inv, g: g, acc: acc, now: now, sub: inv.Subscription,
		nsgByID: map[string]*armnetwork.SecurityGroup{}, nsgBySubnet: map[string]string{},
		nicByID: map[string]*armnetwork.Interface{}, pipByID: map[string]*armnetwork.PublicIPAddress{}}
	acctID := core.EnsureAccount(g, provider, b.sub, spec.Name)
	if n, ok := g.Node(acctID); ok && len(inv.TypeCounts) > 0 {
		counts := map[string]any{}
		for k, v := range inv.TypeCounts {
			counts[k] = v
		}
		g.AddNode(&graph.Node{ID: acctID, Type: n.Type, Class: n.Class, Name: n.Name, Attributes: map[string]any{"resource_counts": counts}})
	}
	b.indexNetwork()
	b.nsgs()
	b.vms()
	b.disks()
	b.publicIPs()
	b.storage()
	b.sqlServers()
	b.vaults()
	b.aks()
	core.AttachFindings(g, b.findings)
	acc.Finding(b.findings...)
}

func (b *builder) check(checkID string, r model.Resource, region string, pass bool, detail string) {
	b.findings = append(b.findings, core.Check{
		CheckID: checkID, AliasSource: "prowler", Provider: provider, Account: b.sub, AccountLabel: b.spec.Name,
		Region: region, Resource: r, Pass: pass, Detail: detail,
	}.Finding(b.now))
}

func (b *builder) add(r model.Resource, region string, tags map[string]string, created *time.Time, sensitive bool) string {
	res := core.Res{Provider: provider, Account: b.sub, Region: region, Resource: r, Tags: tags, ForceSensitive: sensitive}
	if created != nil {
		res.Created = *created
	}
	return core.AddResource(b.g, res)
}

func key(id string) string { return strings.ToLower(id) }

func (b *builder) indexNetwork() {
	for _, n := range b.inv.NSGs {
		if n == nil || n.ID == nil {
			continue
		}
		b.nsgByID[key(*n.ID)] = n
		if n.Properties != nil {
			for _, s := range n.Properties.Subnets {
				if s != nil && s.ID != nil {
					b.nsgBySubnet[key(*s.ID)] = *n.ID
				}
			}
		}
	}
	for _, n := range b.inv.NICs {
		if n != nil && n.ID != nil {
			b.nicByID[key(*n.ID)] = n
		}
	}
	for _, p := range b.inv.PublicIPs {
		if p != nil && p.ID != nil {
			b.pipByID[key(*p.ID)] = p
		}
	}
}

// canonicalNSG maps a referenced NSG ID onto the casing used by the NSG listing.
func (b *builder) canonicalNSG(id string) string {
	if n, ok := b.nsgByID[key(id)]; ok {
		return *n.ID
	}
	return id
}

func (b *builder) nsgs() {
	for _, n := range b.inv.NSGs {
		if n == nil || n.ID == nil {
			continue
		}
		region := str(n.Location)
		open := InternetOpenPorts(n)
		r := model.Resource{ID: *n.ID, Type: "azure_network_security_group", Name: str(n.Name), Attributes: map[string]any{
			"location": region, "internet_open_ports": open, "resource_group": ResourceGroup(*n.ID),
		}}
		b.add(r, region, tagsOf(n.Tags), nil, false)
		ssh := InternetAllowsPort(n, 22)
		rdp := InternetAllowsPort(n, 3389)
		b.check("network_ssh_internet_access_restricted", r, region, !ssh, passFail(!ssh,
			"No inbound rule allows SSH (22/tcp) from the internet.", "An inbound Allow rule exposes SSH (22/tcp) to Internet/Any."))
		b.check("network_rdp_internet_access_restricted", r, region, !rdp, passFail(!rdp,
			"No inbound rule allows RDP (3389/tcp) from the internet.", "An inbound Allow rule exposes RDP (3389/tcp) to Internet/Any."))
	}
}

func passFail(pass bool, ok, bad string) string {
	if pass {
		return ok
	}
	return bad
}

type vmNet struct {
	nsgs      []string
	publicIPs []string
	pipIDs    []string
}

func (b *builder) vmNetwork(vm *armcompute.VirtualMachine) vmNet {
	var out vmNet
	seen := map[string]bool{}
	addNSG := func(id string) {
		id = b.canonicalNSG(id)
		if id != "" && !seen[key(id)] {
			seen[key(id)] = true
			out.nsgs = append(out.nsgs, id)
		}
	}
	if vm.Properties == nil || vm.Properties.NetworkProfile == nil {
		return out
	}
	for _, ref := range vm.Properties.NetworkProfile.NetworkInterfaces {
		if ref == nil || ref.ID == nil {
			continue
		}
		nic := b.nicByID[key(*ref.ID)]
		if nic == nil || nic.Properties == nil {
			continue
		}
		if nic.Properties.NetworkSecurityGroup != nil && nic.Properties.NetworkSecurityGroup.ID != nil {
			addNSG(*nic.Properties.NetworkSecurityGroup.ID)
		}
		for _, ipc := range nic.Properties.IPConfigurations {
			if ipc == nil || ipc.Properties == nil {
				continue
			}
			if sn := ipc.Properties.Subnet; sn != nil && sn.ID != nil {
				if nsg, ok := b.nsgBySubnet[key(*sn.ID)]; ok {
					addNSG(nsg)
				} else if sn.Properties != nil && sn.Properties.NetworkSecurityGroup != nil && sn.Properties.NetworkSecurityGroup.ID != nil {
					addNSG(*sn.Properties.NetworkSecurityGroup.ID)
				}
			}
			if pip := ipc.Properties.PublicIPAddress; pip != nil && pip.ID != nil {
				out.pipIDs = append(out.pipIDs, *pip.ID)
				addr := ""
				if full, ok := b.pipByID[key(*pip.ID)]; ok && full.Properties != nil {
					addr = str(full.Properties.IPAddress)
				} else if pip.Properties != nil {
					addr = str(pip.Properties.IPAddress)
				}
				if addr == "" {
					addr = *pip.ID // allocated but address unknown: still public
				}
				out.publicIPs = append(out.publicIPs, addr)
			}
		}
	}
	return out
}

func (b *builder) vms() {
	for _, vm := range b.inv.VMs {
		if vm == nil || vm.ID == nil {
			continue
		}
		region := str(vm.Location)
		net := b.vmNetwork(vm)
		attrs := map[string]any{"location": region, "resource_group": ResourceGroup(*vm.ID), "security_groups": net.nsgs}
		if len(net.nsgs) > 0 {
			attrs["nsg"] = net.nsgs[0]
		}
		if len(net.publicIPs) > 0 {
			attrs["public_ip"] = net.publicIPs[0]
			attrs["public_ips"] = net.publicIPs
		}
		var created *time.Time
		size := ""
		if p := vm.Properties; p != nil {
			created = p.TimeCreated
			if p.HardwareProfile != nil && p.HardwareProfile.VMSize != nil {
				size = string(*p.HardwareProfile.VMSize)
				attrs["vm_size"] = size
			}
			if p.StorageProfile != nil && p.StorageProfile.OSDisk != nil && p.StorageProfile.OSDisk.OSType != nil {
				attrs["os_type"] = string(*p.StorageProfile.OSDisk.OSType)
			}
		}
		if vm.Identity != nil && vm.Identity.Type != nil {
			attrs["identity"] = string(*vm.Identity.Type)
		}
		power := b.inv.PowerState[key(*vm.ID)]
		if power != "" {
			attrs["power_state"] = strings.TrimPrefix(power, "PowerState/")
		}
		r := model.Resource{ID: *vm.ID, Type: "azure_virtual_machine", Name: str(vm.Name), Attributes: attrs, Related: net.nsgs}
		id := b.add(r, region, tagsOf(vm.Tags), created, false)

		var exposedVia []string
		for _, nsgID := range net.nsgs {
			b.g.AddEdge(id, nsgID, graph.EdgeAttachedTo, nil)
			nsg := b.nsgByID[key(nsgID)]
			open := InternetOpenPorts(nsg)
			ports := AllowedInboundPorts(nsg)
			edge := map[string]any{"ports": strings.Join(ports, ",")}
			if len(open) > 0 {
				edge["internet_ports"] = strings.Join(open, ",")
				exposedVia = append(exposedVia, open...)
			}
			b.g.AddEdge(nsgID, id, graph.EdgeAllowsTrafficTo, edge)
		}
		if len(net.publicIPs) > 0 {
			switch {
			case len(net.nsgs) == 0:
				// No NSG on NIC or subnet: Azure permits all inbound traffic to the public IP.
				b.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "public_ip_no_nsg", "ports": "all", "public_ip": net.publicIPs[0]})
			case len(exposedVia) > 0:
				b.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "nsg_internet_rule", "ports": strings.Join(exposedVia, ","), "public_ip": net.publicIPs[0]})
			}
		}
		if power == "PowerState/stopped" {
			// "stopped" (not deallocated) VMs still bill compute.
			b.acc.Cost(core.CostSignal{Provider: provider, Account: b.sub, Region: region, ResourceID: *vm.ID, ResourceType: "azure_virtual_machine",
				Kind: core.KindStoppedInstance, InstanceType: size, Attributes: map[string]any{"power_state": "stopped"}})
		}
	}
}

func (b *builder) disks() {
	for _, d := range b.inv.Disks {
		if d == nil || d.ID == nil {
			continue
		}
		region := str(d.Location)
		attrs := map[string]any{"location": region}
		var size float64
		var created *time.Time
		state := ""
		if p := d.Properties; p != nil {
			size = float64(i32(p.DiskSizeGB))
			attrs["size_gb"] = size
			created = p.TimeCreated
			if p.DiskState != nil {
				state = string(*p.DiskState)
				attrs["disk_state"] = state
			}
			if p.Encryption != nil && p.Encryption.Type != nil {
				attrs["encryption"] = string(*p.Encryption.Type)
			}
		}
		sku := ""
		if d.SKU != nil && d.SKU.Name != nil {
			sku = string(*d.SKU.Name)
			attrs["sku"] = sku
		}
		r := model.Resource{ID: *d.ID, Type: "azure_managed_disk", Name: str(d.Name), Attributes: attrs}
		id := b.add(r, region, tagsOf(d.Tags), created, false)
		if d.ManagedBy != nil && *d.ManagedBy != "" {
			b.g.AddEdge(*d.ManagedBy, id, graph.EdgeAttachedTo, nil)
		}
		if state == string(armcompute.DiskStateUnattached) {
			b.acc.Cost(core.CostSignal{Provider: provider, Account: b.sub, Region: region, ResourceID: *d.ID, ResourceType: "azure_managed_disk",
				Kind: core.KindUnattachedVolume, SizeGB: size, Attributes: map[string]any{"sku": sku}})
		}
	}
}

func (b *builder) publicIPs() {
	for _, p := range b.inv.PublicIPs {
		if p == nil || p.ID == nil || p.Properties == nil {
			continue
		}
		if p.Properties.IPConfiguration != nil || p.Properties.NatGateway != nil {
			continue
		}
		sku := ""
		if p.SKU != nil && p.SKU.Name != nil {
			sku = string(*p.SKU.Name)
		}
		b.acc.Cost(core.CostSignal{Provider: provider, Account: b.sub, Region: str(p.Location), ResourceID: *p.ID, ResourceType: "azure_public_ip",
			Kind: core.KindUnassociatedIP, Attributes: map[string]any{"sku": sku, "ip_address": str(p.Properties.IPAddress)}})
	}
}

func (b *builder) storage() {
	for _, a := range b.inv.Storage {
		if a == nil || a.ID == nil {
			continue
		}
		region := str(a.Location)
		attrs := map[string]any{"location": region, "resource_group": ResourceGroup(*a.ID)}
		var blobPublic *bool
		var https *bool
		var created *time.Time
		if p := a.Properties; p != nil {
			blobPublic, https, created = p.AllowBlobPublicAccess, p.EnableHTTPSTrafficOnly, p.CreationTime
			if p.MinimumTLSVersion != nil {
				attrs["minimum_tls_version"] = string(*p.MinimumTLSVersion)
			}
			if p.PublicNetworkAccess != nil {
				attrs["public_network_access"] = string(*p.PublicNetworkAccess)
			}
		}
		attrs["allow_blob_public_access"] = boolv(blobPublic)
		attrs["https_only"] = boolv(https)
		r := model.Resource{ID: *a.ID, Type: "azure_storage_account", Name: str(a.Name), Attributes: attrs}
		id := b.add(r, region, tagsOf(a.Tags), created, false)

		networkOpen := a.Properties == nil || a.Properties.PublicNetworkAccess == nil || *a.Properties.PublicNetworkAccess != armstorage.PublicNetworkAccessDisabled
		disabled := blobPublic != nil && !*blobPublic
		b.check("storage_blob_public_access_level_is_disabled", r, region, disabled, passFail(disabled,
			"Anonymous blob access is disabled on the storage account.", "Storage account permits anonymous (public) blob/container access."))
		if blobPublic != nil && *blobPublic && networkOpen {
			b.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "blob_public_access"})
		}
		secure := https != nil && *https
		b.check("storage_secure_transfer_required_is_enabled", r, region, secure, passFail(secure,
			"Secure transfer (HTTPS only) is required.", "Storage account accepts unencrypted HTTP requests."))
	}
}

// internetRule reports a SQL firewall rule spanning the whole IPv4 space.
// 0.0.0.0–0.0.0.0 is the "Allow Azure services" rule and is not internet exposure.
func internetRule(r *armsql.FirewallRule) bool {
	if r == nil || r.Properties == nil {
		return false
	}
	start, end := str(r.Properties.StartIPAddress), str(r.Properties.EndIPAddress)
	return start == "0.0.0.0" && end == "255.255.255.255"
}

func (b *builder) sqlServers() {
	for _, s := range b.inv.SQL {
		srv := s.Server
		region := str(srv.Location)
		attrs := map[string]any{"location": region, "resource_group": ResourceGroup(*srv.ID)}
		publicAccess := true
		if p := srv.Properties; p != nil {
			attrs["fqdn"] = str(p.FullyQualifiedDomainName)
			attrs["version"] = str(p.Version)
			attrs["minimal_tls_version"] = str(p.MinimalTLSVersion)
			if p.PublicNetworkAccess != nil {
				attrs["public_network_access"] = string(*p.PublicNetworkAccess)
				publicAccess = *p.PublicNetworkAccess != armsql.ServerNetworkAccessFlagDisabled
			}
		}
		var openRules []string
		for _, r := range s.Rules {
			if internetRule(r) {
				openRules = append(openRules, str(r.Name))
			}
		}
		attrs["internet_firewall_rules"] = openRules
		r := model.Resource{ID: *srv.ID, Type: "azure_sql_server", Name: str(srv.Name), Attributes: attrs}
		id := b.add(r, region, tagsOf(srv.Tags), nil, true)
		if s.RulesErr != nil && publicAccess {
			continue // cannot evaluate without the rules; error already recorded
		}
		exposed := publicAccess && len(openRules) > 0
		b.check("sqlserver_firewall_rules_no_ingress_from_internet", r, region, !exposed, passFail(!exposed,
			"No server firewall rule admits 0.0.0.0-255.255.255.255 (or public network access is disabled).",
			fmt.Sprintf("Firewall rule(s) %s admit the entire internet.", strings.Join(openRules, ", "))))
		if exposed {
			b.g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "sql_firewall_rule", "ports": "1433"})
		}
	}
}

func (b *builder) vaults() {
	for _, v := range b.inv.Vaults {
		if v == nil || v.ID == nil {
			continue
		}
		region := str(v.Location)
		attrs := map[string]any{"location": region, "resource_group": ResourceGroup(*v.ID)}
		soft, purge := true, false // soft delete is enforced on all vaults since 2020 when unset
		if p := v.Properties; p != nil {
			if p.EnableSoftDelete != nil {
				soft = *p.EnableSoftDelete
			}
			purge = boolv(p.EnablePurgeProtection)
			attrs["public_network_access"] = str(p.PublicNetworkAccess)
		}
		attrs["soft_delete"], attrs["purge_protection"] = soft, purge
		var created *time.Time
		if v.SystemData != nil {
			created = v.SystemData.CreatedAt
		}
		r := model.Resource{ID: *v.ID, Type: "azure_key_vault", Name: str(v.Name), Attributes: attrs}
		b.add(r, region, tagsOf(v.Tags), created, true)
		ok := soft && purge
		b.check("keyvault_recoverable", r, region, ok, passFail(ok,
			"Soft delete and purge protection are enabled.", "Key Vault lacks soft delete and/or purge protection; secrets can be permanently destroyed."))
	}
}

func (b *builder) aks() {
	for _, row := range b.inv.AKS {
		id, _ := row["id"].(string)
		if id == "" {
			continue
		}
		name, _ := row["name"].(string)
		region, _ := row["location"].(string)
		tags := map[string]string{}
		if t, ok := row["tags"].(map[string]any); ok {
			for k, v := range t {
				tags[k] = fmt.Sprint(v)
			}
		}
		rbac, known := row["enableRBAC"].(bool)
		r := model.Resource{ID: id, Type: "azure_kubernetes_cluster", Name: name, Attributes: map[string]any{"location": region, "rbac_enabled": rbac}}
		b.add(r, region, tags, nil, false)
		if !known {
			continue
		}
		b.check("aks_cluster_rbac_enabled", r, region, rbac, passFail(rbac,
			"Kubernetes RBAC is enabled on the AKS cluster.", "AKS cluster has Kubernetes RBAC disabled; every authenticated identity is effectively admin."))
	}
}
