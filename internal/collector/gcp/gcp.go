// Package gcp collects Google Cloud inventory (Compute Engine, Cloud Storage,
// Cloud SQL, IAM service accounts), evaluates Prowler-equivalent checks, builds
// security-graph nodes/edges and emits cost signals.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	compute "google.golang.org/api/compute/v1"
	iamv1 "google.golang.org/api/iam/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

const (
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	defaultSASuffix    = "-compute@developer.gserviceaccount.com"
)

// Collector implements core.Collector for one GCP project.
type Collector struct {
	// NewClients builds service clients; defaults to SDK-backed NewClients.
	NewClients  func(ctx context.Context, spec core.AccountSpec) (*Clients, error)
	Concurrency int
	Now         func() time.Time
}

// New returns a collector using the real Google Cloud SDKs.
func New() *Collector { return &Collector{NewClients: NewClients, Concurrency: 5, Now: time.Now} }

func (c *Collector) Name() string     { return "gcp" }
func (c *Collector) Provider() string { return model.ProviderGCP }

type inventory struct {
	project   *ProjectInfo
	instances []*compute.Instance
	firewalls []*compute.Firewall
	disks     []*compute.Disk
	addresses []*compute.Address
	buckets   []BucketInfo
	sql       []*sqladmin.DatabaseInstance
	sas       []*iamv1.ServiceAccount
	iam       []IAMBinding
}

// Collect gathers the project in parallel, then evaluates checks and builds the graph.
func (c *Collector) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	project := spec.ProjectID
	if project == "" {
		return core.Result{}, errors.New("gcp: project_id is required")
	}
	newClients := c.NewClients
	if newClients == nil {
		newClients = NewClients
	}
	cl, err := newClients(ctx, spec)
	if err != nil {
		return core.Result{}, fmt.Errorf("gcp clients: %w", err)
	}
	defer cl.Close()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	acc := &core.Acc{}
	inv := &inventory{}
	var tasks []core.Task
	if cl.Projects != nil {
		tasks = append(tasks, core.Task{Name: "gcp/resourcemanager", Fn: func(ctx context.Context) (err error) {
			inv.project, err = cl.Projects.Project(ctx, project)
			return err
		}})
	}
	if cl.Compute != nil {
		tasks = append(tasks,
			core.Task{Name: "gcp/compute.instances", Fn: func(ctx context.Context) (err error) {
				inv.instances, err = cl.Compute.Instances(ctx, project)
				return err
			}},
			core.Task{Name: "gcp/compute.firewalls", Fn: func(ctx context.Context) (err error) {
				inv.firewalls, err = cl.Compute.Firewalls(ctx, project)
				return err
			}},
			core.Task{Name: "gcp/compute.disks", Fn: func(ctx context.Context) (err error) {
				inv.disks, err = cl.Compute.Disks(ctx, project)
				return err
			}},
			core.Task{Name: "gcp/compute.addresses", Fn: func(ctx context.Context) (err error) {
				inv.addresses, err = cl.Compute.Addresses(ctx, project)
				return err
			}})
	}
	if cl.Storage != nil {
		tasks = append(tasks, core.Task{Name: "gcp/storage", Fn: func(ctx context.Context) (err error) {
			inv.buckets, err = cl.Storage.Buckets(ctx, project)
			return err
		}})
	}
	if cl.SQL != nil {
		tasks = append(tasks, core.Task{Name: "gcp/sqladmin", Fn: func(ctx context.Context) (err error) {
			inv.sql, err = cl.SQL.Instances(ctx, project)
			return err
		}})
	}
	if cl.ProjectIAM != nil {
		tasks = append(tasks, core.Task{Name: "gcp/resourcemanager.getIamPolicy", Fn: func(ctx context.Context) (err error) {
			inv.iam, err = cl.ProjectIAM.IAMPolicy(ctx, project)
			return err
		}})
	}
	if cl.IAM != nil {
		tasks = append(tasks, core.Task{Name: "gcp/iam", Fn: func(ctx context.Context) (err error) {
			inv.sas, err = cl.IAM.ServiceAccounts(ctx, project)
			return err
		}})
	}
	core.RunTasks(ctx, c.Concurrency, acc, tasks)

	b := &builder{g: g, acc: acc, spec: spec, project: project, now: now()}
	b.build(inv)
	res := acc.Result()
	core.AttachFindings(g, res.Findings)
	run := model.ToolRun{Tool: "nimbus-gcp", Account: project, Status: "ok", Findings: len(res.Findings)}
	if n := len(res.Errors); n > 0 {
		run.Message = fmt.Sprintf("%d of %d API calls failed: %v", n, len(tasks), errors.Join(res.Errors...))
		if n == len(tasks) {
			run.Status = "failed"
		}
	}
	res.Runs = append(res.Runs, run)
	return res, nil
}

type builder struct {
	g       *graph.Graph
	acc     *core.Acc
	spec    core.AccountSpec
	project string
	now     time.Time
}

func (b *builder) check(id, region string, r model.Resource, pass bool, detail string) {
	b.acc.Finding(core.Check{CheckID: id, AliasSource: "prowler", Provider: model.ProviderGCP, Account: b.project, AccountLabel: b.spec.Name,
		Region: region, Resource: r, Pass: pass, Detail: detail}.Finding(b.now))
}

func (b *builder) add(region string, r model.Resource, labels map[string]string, created time.Time) string {
	return core.AddResource(b.g, core.Res{Provider: model.ProviderGCP, Account: b.project, Region: region, Resource: r, Tags: labels, Created: created})
}

func (b *builder) build(inv *inventory) {
	acct := core.EnsureAccount(b.g, model.ProviderGCP, b.project, b.spec.Name)
	if p := inv.project; p != nil {
		attrs := map[string]any{"project_number": p.Number}
		if len(p.Labels) > 0 {
			attrs["tags"] = core.TagsAny(p.Labels)
		}
		crit := core.Criticality(p.Name, p.Labels)
		if crit == "unknown" {
			crit = ""
		}
		b.g.AddNode(&graph.Node{ID: acct, Type: core.AccountType(model.ProviderGCP), Class: graph.ClassAccount, Name: firstNonEmpty(b.spec.Name, p.Name, b.project),
			Provider: model.ProviderGCP, Account: b.project, Attributes: attrs, Criticality: crit, Owner: core.Owner(p.Labels)})
	}
	for _, sa := range inv.sas {
		b.add("global", model.Resource{ID: saID(b.project, sa.Email), Type: "gcp_service_account", Name: sa.Email,
			Attributes: map[string]any{"email": sa.Email, "disabled": sa.Disabled, "unique_id": sa.UniqueId}}, nil, time.Time{})
	}
	b.projectIAM(inv.iam)
	b.firewallChecks(inv.firewalls)
	b.instances(inv.instances, inv.firewalls)
	b.disks(inv.disks)
	b.addresses(inv.addresses)
	b.buckets(inv.buckets)
	b.sqlInstances(inv.sql)
}

// ------------------------------------------------------------------ firewalls

func fwID(project string, fw *compute.Firewall) string {
	if fw.SelfLink != "" {
		return fw.SelfLink
	}
	return fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/firewalls/%s", project, fw.Name)
}

func isIngress(fw *compute.Firewall) bool {
	return fw.Direction == "" || strings.EqualFold(fw.Direction, "INGRESS")
}

func openToInternet(fw *compute.Firewall) bool {
	for _, s := range fw.SourceRanges {
		if core.IsOpenCIDR(s) {
			return true
		}
	}
	return false
}

// allowsTCPPort reports whether any allow rule permits TCP traffic on port.
func allowsTCPPort(fw *compute.Firewall, port int) bool {
	for _, a := range fw.Allowed {
		proto := strings.ToLower(a.IPProtocol)
		if proto != "tcp" && proto != "all" && proto != "6" {
			continue
		}
		if len(a.Ports) == 0 {
			return true
		}
		for _, p := range a.Ports {
			if portSpecContains(p, port) {
				return true
			}
		}
	}
	return false
}

func portSpecContains(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, e1 := strconv.Atoi(lo)
		h, e2 := strconv.Atoi(hi)
		return e1 == nil && e2 == nil && port >= l && port <= h
	}
	p, err := strconv.Atoi(spec)
	return err == nil && p == port
}

// portsAttr renders "tcp:22,80;udp:all" for edge attributes.
func portsAttr(fw *compute.Firewall) string {
	var parts []string
	for _, a := range fw.Allowed {
		ports := "all"
		if len(a.Ports) > 0 {
			ports = strings.Join(a.Ports, ",")
		}
		parts = append(parts, strings.ToLower(a.IPProtocol)+":"+ports)
	}
	return strings.Join(parts, ";")
}

func (b *builder) firewallChecks(fws []*compute.Firewall) {
	for _, fw := range fws {
		active := isIngress(fw) && !fw.Disabled && len(fw.Allowed) > 0
		open := active && openToInternet(fw)
		r := model.Resource{ID: fwID(b.project, fw), Type: "gcp_compute_firewall", Name: fw.Name, Attributes: map[string]any{
			"network": lastSegment(fw.Network), "direction": firstNonEmpty(fw.Direction, "INGRESS"), "disabled": fw.Disabled,
			"source_ranges": fw.SourceRanges, "target_tags": fw.TargetTags, "allowed": portsAttr(fw), "priority": fw.Priority,
		}}
		b.add("global", r, nil, parseTime(fw.CreationTimestamp))
		for _, c := range []struct {
			id   string
			port int
			name string
		}{{"compute_firewall_ssh_access_from_the_internet_allowed", 22, "SSH"}, {"compute_firewall_rdp_access_from_the_internet_allowed", 3389, "RDP"}} {
			fail := open && allowsTCPPort(fw, c.port)
			detail := fmt.Sprintf("Firewall %s does not allow %s (tcp/%d) from 0.0.0.0/0.", fw.Name, c.name, c.port)
			if fail {
				if d := shadowingDeny(fw, fws, c.port); d != nil {
					fail = false
					detail = fmt.Sprintf("Firewall %s would allow %s (tcp/%d) from the internet but deny rule %s (priority %d) takes precedence.", fw.Name, c.name, c.port, d.Name, priority(d))
				}
			}
			if fail {
				detail = fmt.Sprintf("Firewall %s allows %s (tcp/%d) from the internet (%s).", fw.Name, c.name, c.port, strings.Join(fw.SourceRanges, ", "))
			}
			b.check(c.id, "global", r, !fail, detail)
		}
	}
}

// applies reports whether an ingress firewall governs traffic to the instance.
func applies(fw *compute.Firewall, inst *compute.Instance) bool {
	if !isIngress(fw) || fw.Disabled {
		return false
	}
	sameNet := false
	for _, nic := range inst.NetworkInterfaces {
		if sameNetwork(nic.Network, fw.Network) {
			sameNet = true
			break
		}
	}
	if !sameNet {
		return false
	}
	if len(fw.TargetTags) > 0 {
		var tags []string
		if inst.Tags != nil {
			tags = inst.Tags.Items
		}
		if !intersects(fw.TargetTags, tags) {
			return false
		}
	}
	if len(fw.TargetServiceAccounts) > 0 {
		var emails []string
		for _, sa := range inst.ServiceAccounts {
			emails = append(emails, sa.Email)
		}
		if !intersects(fw.TargetServiceAccounts, emails) {
			return false
		}
	}
	return true
}

func sameNetwork(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return networkKey(a) == networkKey(b)
}

// networkKey normalises full URLs and partial paths to "global/networks/<name>".
func networkKey(n string) string {
	if i := strings.Index(n, "global/networks/"); i >= 0 {
		return n[i:]
	}
	return "global/networks/" + lastSegment(n)
}

// ------------------------------------------------------------------ instances

func (b *builder) instances(insts []*compute.Instance, fws []*compute.Firewall) {
	for _, inst := range insts {
		zone := lastSegment(inst.Zone)
		region := regionOf(zone)
		id := inst.SelfLink
		if id == "" {
			id = fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s", b.project, zone, inst.Name)
		}
		var netTags []string
		if inst.Tags != nil {
			netTags = inst.Tags.Items
		}
		publicIP := ""
		var networks []string
		for _, nic := range inst.NetworkInterfaces {
			networks = append(networks, lastSegment(nic.Network))
			for _, ac := range nic.AccessConfigs {
				if ac.NatIP != "" && publicIP == "" {
					publicIP = ac.NatIP
				}
			}
		}
		saEmail := ""
		var scopes []string
		if len(inst.ServiceAccounts) > 0 {
			saEmail = inst.ServiceAccounts[0].Email
			scopes = inst.ServiceAccounts[0].Scopes
		}
		attrs := map[string]any{"zone": zone, "machine_type": lastSegment(inst.MachineType), "status": inst.Status, "network_tags": netTags, "networks": networks}
		if publicIP != "" {
			attrs["public_ip"] = publicIP
		}
		if saEmail != "" {
			attrs["service_account"] = saEmail
			attrs["iam_role"] = saID(b.project, saEmail)
		}
		r := model.Resource{ID: id, Type: "gcp_compute_instance", Name: inst.Name, Attributes: attrs}
		if saEmail != "" {
			r.Related = []string{saID(b.project, saEmail)}
		}
		b.add(region, r, inst.Labels, parseTime(inst.CreationTimestamp))

		if saEmail != "" {
			sa := saID(b.project, saEmail)
			b.add("global", model.Resource{ID: sa, Type: "gcp_service_account", Name: saEmail, Attributes: map[string]any{"email": saEmail}}, nil, time.Time{})
			b.g.AddEdge(id, sa, graph.EdgeRunsAs, map[string]any{"scopes": scopes})
		}
		var applicable []*compute.Firewall
		for _, fw := range fws {
			if !applies(fw, inst) {
				continue
			}
			applicable = append(applicable, fw)
			fid := fwID(b.project, fw)
			b.g.AddEdge(id, fid, graph.EdgeAttachedTo, nil)
			if len(fw.Allowed) > 0 {
				b.g.AddEdge(fid, id, graph.EdgeAllowsTrafficTo, map[string]any{"ports": portsAttr(fw), "sources": fw.SourceRanges})
			}
		}
		if publicIP != "" {
			if ex := evaluateIngress(applicable); len(ex.ports) > 0 {
				core.Expose(b.g, id, map[string]any{"via": strings.Join(ex.via, ","), "ports": strings.Join(ex.ports, ";"), "public_ip": publicIP}, ex.sources, b.spec.TrustedCIDRs)
			}
		}

		fullAccess := strings.HasSuffix(saEmail, defaultSASuffix) && contains(scopes, cloudPlatformScope)
		detail := fmt.Sprintf("Instance %s does not use the default compute service account with full API access.", inst.Name)
		if fullAccess {
			detail = fmt.Sprintf("Instance %s runs as default service account %s with the cloud-platform scope.", inst.Name, saEmail)
		}
		b.check("compute_instance_default_service_account_in_use_with_full_api_access", region, r, !fullAccess, detail)

		if inst.Status == "TERMINATED" || inst.Status == "STOPPED" || inst.Status == "SUSPENDED" {
			b.acc.Cost(core.CostSignal{Provider: model.ProviderGCP, Account: b.project, Region: region, ResourceID: id, ResourceType: "gcp_compute_instance",
				Kind: core.KindStoppedInstance, InstanceType: lastSegment(inst.MachineType), Attributes: map[string]any{"status": inst.Status, "zone": zone, "name": inst.Name}})
		}
	}
}

// ------------------------------------------------------------------ disks / addresses

func (b *builder) disks(disks []*compute.Disk) {
	for _, d := range disks {
		zone := lastSegment(d.Zone)
		region := regionOf(zone)
		if region == "" {
			region = lastSegment(d.Region)
		}
		id := d.SelfLink
		if id == "" {
			id = fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/disks/%s", b.project, zone, d.Name)
		}
		dtype := lastSegment(d.Type)
		r := model.Resource{ID: id, Type: "gcp_compute_disk", Name: d.Name, Attributes: map[string]any{"zone": zone, "size_gb": d.SizeGb, "disk_type": dtype, "users": d.Users}}
		b.add(region, r, d.Labels, parseTime(d.CreationTimestamp))
		for _, u := range d.Users {
			b.g.AddEdge(u, id, graph.EdgeAttachedTo, nil)
		}
		if len(d.Users) == 0 {
			b.acc.Cost(core.CostSignal{Provider: model.ProviderGCP, Account: b.project, Region: region, ResourceID: id, ResourceType: "gcp_compute_disk",
				Kind: core.KindUnattachedVolume, SizeGB: float64(d.SizeGb), Attributes: map[string]any{"disk_type": dtype, "zone": zone, "name": d.Name}})
		}
	}
}

func (b *builder) addresses(addrs []*compute.Address) {
	for _, a := range addrs {
		region := lastSegment(a.Region)
		if region == "" {
			region = "global"
		}
		id := a.SelfLink
		if id == "" {
			id = fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/regions/%s/addresses/%s", b.project, region, a.Name)
		}
		r := model.Resource{ID: id, Type: "gcp_compute_address", Name: a.Name, Attributes: map[string]any{"address": a.Address, "status": a.Status, "address_type": a.AddressType, "users": a.Users}}
		b.add(region, r, a.Labels, parseTime(a.CreationTimestamp))
		external := a.AddressType == "" || strings.EqualFold(a.AddressType, "EXTERNAL")
		if a.Status == "RESERVED" && external {
			b.acc.Cost(core.CostSignal{Provider: model.ProviderGCP, Account: b.project, Region: region, ResourceID: id, ResourceType: "gcp_compute_address",
				Kind: core.KindUnassociatedIP, Attributes: map[string]any{"address": a.Address, "name": a.Name}})
		}
	}
}

// ------------------------------------------------------------------ storage

// BucketID is the Cloud Asset-style full resource name for a bucket.
func BucketID(name string) string { return "//storage.googleapis.com/projects/_/buckets/" + name }

func (b *builder) buckets(bs []BucketInfo) {
	for _, bk := range bs {
		var publicMembers []string
		for _, m := range bk.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				publicMembers = append(publicMembers, m)
			}
		}
		public := len(publicMembers) > 0 && bk.PublicAccessPrevention != "enforced"
		region := strings.ToLower(bk.Location)
		r := model.Resource{ID: BucketID(bk.Name), Type: "gcp_storage_bucket", Name: bk.Name, Attributes: map[string]any{
			"location": bk.Location, "public": public, "public_access_prevention": bk.PublicAccessPrevention, "uniform_bucket_level_access": bk.UniformAccess,
		}}
		b.add(region, r, bk.Labels, bk.Created)
		if public {
			core.Expose(b.g, r.ID, map[string]any{"via": "iam:" + strings.Join(publicMembers, ",")}, nil, b.spec.TrustedCIDRs)
		}
		if bk.PolicyErr != nil {
			b.acc.Warn("gcp: bucket %s IAM policy unreadable: %v", bk.Name, bk.PolicyErr)
			continue
		}
		detail := fmt.Sprintf("Bucket %s is not publicly accessible.", bk.Name)
		if public {
			detail = fmt.Sprintf("Bucket %s grants access to %s.", bk.Name, strings.Join(publicMembers, ", "))
		}
		b.check("cloudstorage_bucket_public_access", region, r, !public, detail)
	}
}

// ------------------------------------------------------------------ cloud sql

func (b *builder) sqlInstances(insts []*sqladmin.DatabaseInstance) {
	for _, in := range insts {
		id := in.SelfLink
		if id == "" {
			id = fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1/projects/%s/instances/%s", b.project, in.Name)
		}
		var ipv4, requireSSL bool
		var sslMode string
		var openNets []string
		var labels map[string]string
		if s := in.Settings; s != nil {
			labels = s.UserLabels
			if ip := s.IpConfiguration; ip != nil {
				ipv4, requireSSL, sslMode = ip.Ipv4Enabled, ip.RequireSsl, ip.SslMode
				for _, n := range ip.AuthorizedNetworks {
					if n != nil && core.IsPublicSource(n.Value) {
						openNets = append(openNets, n.Value)
					}
				}
			}
		}
		publicIP := ""
		for _, a := range in.IpAddresses {
			if a.Type == "PRIMARY" {
				publicIP = a.IpAddress
			}
		}
		attrs := map[string]any{"database_version": in.DatabaseVersion, "ipv4_enabled": ipv4, "require_ssl": requireSSL, "ssl_mode": sslMode}
		if publicIP != "" {
			attrs["public_ip"] = publicIP
		}
		r := model.Resource{ID: id, Type: "gcp_sql_database_instance", Name: in.Name, Attributes: attrs}
		b.add(in.Region, r, labels, parseTime(in.CreateTime))
		if ipv4 && len(openNets) > 0 {
			core.Expose(b.g, id, map[string]any{"via": "authorized_networks", "sources": openNets}, openNets, b.spec.TrustedCIDRs)
		}
		detail := fmt.Sprintf("Cloud SQL instance %s has no public IPv4 address.", in.Name)
		if ipv4 {
			detail = fmt.Sprintf("Cloud SQL instance %s has a public IPv4 address", in.Name)
			if len(openNets) > 0 {
				detail += " and authorizes " + strings.Join(openNets, ", ")
			}
			detail += "."
		}
		b.check("cloudsql_instance_public_ip", in.Region, r, !ipv4, detail)
		sslOK := requireSSL || sslMode == "ENCRYPTED_ONLY" || sslMode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
		detail = fmt.Sprintf("Cloud SQL instance %s requires SSL connections.", in.Name)
		if !sslOK {
			detail = fmt.Sprintf("Cloud SQL instance %s accepts unencrypted connections (ssl_mode=%q).", in.Name, sslMode)
		}
		b.check("cloudsql_instance_ssl_connections", in.Region, r, sslOK, detail)
	}
}

// ------------------------------------------------------------------ firewall evaluation

// priority returns the rule priority. The Go struct cannot tell an explicit 0 from
// unset, so presence is carried in ForceSendFields: the API client marks every listed
// rule (the API always holds an effective priority; GCP fills in 1000 at creation),
// and an unmarked 0 (a hand-built rule) is GCP's default 1000.
func priority(fw *compute.Firewall) int64 {
	if fw.Priority == 0 && !priorityExplicit(fw) {
		return 1000
	}
	return fw.Priority
}

func priorityExplicit(fw *compute.Firewall) bool {
	for _, f := range fw.ForceSendFields {
		if f == "Priority" {
			return true
		}
	}
	return false
}

// markListedPriority records that a firewall returned by the API has an explicit
// priority, so priority 0 stays 0 (see priority).
func markListedPriority(fw *compute.Firewall) {
	if fw != nil && fw.Priority == 0 && !priorityExplicit(fw) {
		fw.ForceSendFields = append(fw.ForceSendFields, "Priority")
	}
}

// portRanged reports whether a protocol carries ports (an entry without a port list
// then means every port 0-65535).
func portRanged(proto string) bool {
	switch proto {
	case "tcp", "udp", "sctp", "all", "6", "17", "132":
		return true
	}
	return false
}

// specBounds parses "22" or "20-30" ("all" = 0-65535).
func specBounds(spec string) (int, int, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "all" {
		return 0, 65535, true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, e1 := strconv.Atoi(strings.TrimSpace(lo))
		h, e2 := strconv.Atoi(strings.TrimSpace(hi))
		return l, h, e1 == nil && e2 == nil && l <= h
	}
	p, err := strconv.Atoi(spec)
	return p, p, err == nil
}

// candidatePorts returns the ports of [lo,hi] at which the decision over the ordered
// rules can change: lo plus each other rule's port-range start and end+1 inside it.
// The decision is constant between consecutive candidates, so checking them finds
// any admitted port in the range.
func candidatePorts(ordered []*compute.Firewall, lo, hi int) []int {
	seen := map[int]bool{lo: true}
	out := []int{lo}
	add := func(p int) {
		if p > lo && p <= hi && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, fw := range ordered {
		entries, _ := entriesOf(fw)
		for _, e := range entries {
			for _, spec := range e.ports {
				if l, h, ok := specBounds(spec); ok {
					add(l)
					add(h + 1)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

type fwEntry struct {
	proto string
	ports []string
}

func entriesOf(fw *compute.Firewall) (entries []fwEntry, allow bool) {
	if len(fw.Denied) > 0 {
		for _, d := range fw.Denied {
			entries = append(entries, fwEntry{strings.ToLower(d.IPProtocol), d.Ports})
		}
		return entries, false
	}
	for _, a := range fw.Allowed {
		entries = append(entries, fwEntry{strings.ToLower(a.IPProtocol), a.Ports})
	}
	return entries, true
}

func protoMatches(entry, cand string) bool {
	norm := func(p string) string {
		switch p {
		case "6":
			return "tcp"
		case "17":
			return "udp"
		}
		return p
	}
	entry, cand = norm(entry), norm(cand)
	return entry == "all" || entry == cand
}

// matchesTraffic reports whether a rule entry covers (proto, port); port < 0 means
// "every port", which only an entry without a port list covers.
func (e fwEntry) matchesTraffic(proto string, port int) bool {
	if !protoMatches(e.proto, proto) {
		return false
	}
	if len(e.ports) == 0 {
		return true
	}
	if port < 0 {
		return false
	}
	for _, p := range e.ports {
		if portSpecContains(p, port) {
			return true
		}
	}
	return false
}

// familyPrefix parses a firewall source range keeping its address family: "::/0" is
// IPv6 (core.ParseSource maps every open spelling to 0.0.0.0/0). Family-less open
// spellings ("*", "any", "internet") report both=true.
func familyPrefix(s string) (p netip.Prefix, both, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "*", "any", "internet":
		return netip.Prefix{}, true, true
	}
	if pp, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
		return pp.Masked(), false, true
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		if a.IsUnspecified() {
			return netip.PrefixFrom(a, 0), false, true // "0.0.0.0" / "::" spelled as /0
		}
		return netip.PrefixFrom(a, a.BitLen()), false, true
	}
	return netip.Prefix{}, false, false
}

// rangeCovers reports whether a firewall source range includes every address of cand.
// IPv4 and IPv6 ranges never cover each other: a 0.0.0.0/0 deny leaves a ::/0 allow
// open, so IPv6 exposure is decided independently of IPv4 denies.
func rangeCovers(rangeSrc, cand string) bool {
	rp, rBoth, ok1 := familyPrefix(rangeSrc)
	if ok1 && rBoth {
		return true
	}
	cp, cBoth, ok2 := familyPrefix(cand)
	if !ok1 || !ok2 || cBoth {
		return false
	}
	return rp.Addr().Is4() == cp.Addr().Is4() && rp.Bits() <= cp.Bits() && rp.Contains(cp.Addr())
}

// orderRules sorts ingress rules the way GCP evaluates them: priority ascending,
// deny before allow at the same priority.
func orderRules(fws []*compute.Firewall) []*compute.Firewall {
	var out []*compute.Firewall
	for _, fw := range fws {
		if isIngress(fw) && !fw.Disabled && (len(fw.Allowed) > 0 || len(fw.Denied) > 0) {
			out = append(out, fw)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := priority(out[i]), priority(out[j])
		if pi != pj {
			return pi < pj
		}
		return len(out[i].Denied) > 0 && len(out[j].Denied) == 0
	})
	return out
}

// decide returns the first rule (in GCP order) that matches traffic from src.
func decide(ordered []*compute.Firewall, src, proto string, port int) (*compute.Firewall, bool) {
	for _, fw := range ordered {
		covered := false
		for _, r := range fw.SourceRanges {
			if rangeCovers(r, src) {
				covered = true
				break
			}
		}
		if !covered {
			continue
		}
		entries, allow := entriesOf(fw)
		for _, e := range entries {
			if e.matchesTraffic(proto, port) {
				return fw, allow
			}
		}
	}
	return nil, false // implied deny ingress
}

type ingressExposure struct {
	ports, sources, via []string
}

// evaluateIngress finds the internet traffic that the applicable firewall rules
// actually admit: every (public source, protocol, port spec) of an allow rule is
// re-decided over all rules by priority with deny precedence.
func evaluateIngress(applicable []*compute.Firewall) ingressExposure {
	ordered := orderRules(applicable)
	var ex ingressExposure
	seenP, seenS, seenV := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, fw := range ordered {
		entries, allow := entriesOf(fw)
		if !allow {
			continue
		}
		for _, src := range fw.SourceRanges {
			if !core.IsPublicSource(src) {
				continue
			}
			for _, e := range entries {
				specs := e.ports
				if len(specs) == 0 {
					specs = []string{"all"}
				}
				for _, spec := range specs {
					// Every port of the range is decided, not only its lowest: a deny on
					// 20 in front of an allow on 20-30 still leaves 21-30 open.
					ports := []int{-1}
					if portRanged(e.proto) {
						if lo, hi, ok := specBounds(spec); ok {
							ports = candidatePorts(ordered, lo, hi)
						}
					}
					var winner *compute.Firewall
					for _, port := range ports {
						if w, ok := decide(ordered, src, e.proto, port); ok && w != nil {
							winner = w
							break
						}
					}
					if winner == nil {
						continue
					}
					p := e.proto + ":" + spec
					if !seenP[p] {
						seenP[p] = true
						ex.ports = append(ex.ports, p)
					}
					if !seenS[src] {
						seenS[src] = true
						ex.sources = append(ex.sources, src)
					}
					if !seenV[winner.Name] {
						seenV[winner.Name] = true
						ex.via = append(ex.via, winner.Name)
					}
				}
			}
		}
	}
	sort.Strings(ex.ports)
	sort.Strings(ex.sources)
	return ex
}

// shadowingDeny returns a deny rule that blocks internet tcp/port for every target
// of allow rule fw at an equal or higher precedence (nil when none).
func shadowingDeny(fw *compute.Firewall, fws []*compute.Firewall, port int) *compute.Firewall {
	for _, d := range fws {
		if len(d.Denied) == 0 || !isIngress(d) || d.Disabled || !sameNetwork(d.Network, fw.Network) || priority(d) > priority(fw) {
			continue
		}
		if len(d.TargetServiceAccounts) > 0 || (len(d.TargetTags) > 0 && (len(fw.TargetTags) == 0 || !subset(fw.TargetTags, d.TargetTags))) {
			continue
		}
		wide := false
		for _, r := range d.SourceRanges {
			if core.IsOpenCIDR(r) {
				wide = true
			}
		}
		if !wide {
			continue
		}
		entries, _ := entriesOf(d)
		for _, e := range entries {
			if e.matchesTraffic("tcp", port) {
				return d
			}
		}
	}
	return nil
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ project IAM

// RoleID is the graph node ID of a role bound in project's IAM policy
// ("roles/editor" → //cloudresourcemanager.googleapis.com/projects/<p>/roles/editor;
// custom roles keep their full name).
func RoleID(project, role string) string {
	if strings.HasPrefix(role, "roles/") {
		return "//cloudresourcemanager.googleapis.com/projects/" + project + "/roles/" + strings.TrimPrefix(role, "roles/")
	}
	return "//iam.googleapis.com/" + role
}

var primitiveRoles = map[string]bool{"roles/owner": true, "roles/editor": true}

// memberNode maps an IAM member to a graph node (ID, type, name); ok=false for
// members that are not principals in this graph (allUsers, domain:…, deleted:…).
func memberNode(project, member string) (id, typ, name string, ok bool) {
	kind, val, found := strings.Cut(member, ":")
	if !found {
		return "", "", "", false
	}
	switch kind {
	case "serviceAccount":
		return saID(project, val), "gcp_service_account", val, true
	case "user":
		return "gcp:user/" + val, "gcp_user", val, true
	case "group":
		return "gcp:group/" + val, "gcp_group", val, true
	}
	return "", "", "", false
}

// projectIAM adds role nodes and principal -[has_policy]-> role edges (attrs: role,
// member, condition) for every binding, and flags primitive owner/editor roles.
func (b *builder) projectIAM(bindings []IAMBinding) {
	for _, bd := range bindings {
		if bd.Role == "" {
			continue
		}
		rid := RoleID(b.project, bd.Role)
		roleRes := model.Resource{ID: rid, Type: "gcp_iam_role", Name: bd.Role, Attributes: map[string]any{"role": bd.Role, "primitive": primitiveRoles[bd.Role]}}
		b.add("global", roleRes, nil, time.Time{})
		var principals, public []string
		for _, m := range bd.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				public = append(public, m)
				continue
			}
			id, typ, name, ok := memberNode(b.project, m)
			if !ok {
				continue
			}
			b.add("global", model.Resource{ID: id, Type: typ, Name: name, Attributes: map[string]any{"email": name}}, nil, time.Time{})
			attr := map[string]any{"role": bd.Role, "member": m}
			if bd.Condition != "" {
				attr["condition"] = bd.Condition
			}
			b.g.AddEdge(id, rid, graph.EdgeHasPolicy, attr)
			if typ == "gcp_service_account" || typ == "gcp_user" {
				principals = append(principals, m)
			}
		}
		if len(public) > 0 {
			b.acc.Warn("gcp: project %s binds %s to %s", b.project, bd.Role, strings.Join(public, ", "))
		}
		if primitiveRoles[bd.Role] && len(principals) > 0 && bd.Condition == "" {
			roleRes.Related = principals
			b.check("iam_role_assigned_to_user_or_sa_primitive", "global", roleRes, false,
				fmt.Sprintf("Primitive role %s is granted on project %s to %s.", bd.Role, b.project, strings.Join(principals, ", ")))
		}
	}
}

// ------------------------------------------------------------------ helpers

func saID(project, email string) string {
	return "//iam.googleapis.com/projects/" + project + "/serviceAccounts/" + email
}

func lastSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// regionOf maps a zone ("us-central1-a") to its region ("us-central1").
func regionOf(zone string) string {
	if i := strings.LastIndex(zone, "-"); i > 0 {
		return zone[:i]
	}
	return zone
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ core.Collector = (*Collector)(nil)
