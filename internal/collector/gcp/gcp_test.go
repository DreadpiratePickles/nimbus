package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	compute "google.golang.org/api/compute/v1"
	iamv1 "google.golang.org/api/iam/v1"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

const proj = "acme-prod"

type fakeCompute struct {
	inst  []*compute.Instance
	fws   []*compute.Firewall
	disks []*compute.Disk
	addrs []*compute.Address
	err   error
}

func (f *fakeCompute) Instances(context.Context, string) ([]*compute.Instance, error) {
	return f.inst, f.err
}
func (f *fakeCompute) Firewalls(context.Context, string) ([]*compute.Firewall, error) {
	return f.fws, nil
}
func (f *fakeCompute) Disks(context.Context, string) ([]*compute.Disk, error) { return f.disks, nil }
func (f *fakeCompute) Addresses(context.Context, string) ([]*compute.Address, error) {
	return f.addrs, nil
}

type fakeStorage struct {
	b   []BucketInfo
	err error
}

func (f *fakeStorage) Buckets(context.Context, string) ([]BucketInfo, error) { return f.b, f.err }

type fakeSQL struct{ in []*sqladmin.DatabaseInstance }

func (f *fakeSQL) Instances(context.Context, string) ([]*sqladmin.DatabaseInstance, error) {
	return f.in, nil
}

type fakeProjects struct{}

func (fakeProjects) Project(context.Context, string) (*ProjectInfo, error) {
	return &ProjectInfo{ID: proj, Number: 42, Name: "Acme Prod", Labels: map[string]string{"env": "production", "owner": "platform"}}, nil
}

type fakeIAM struct{}

func (fakeIAM) ServiceAccounts(context.Context, string) ([]*iamv1.ServiceAccount, error) {
	return []*iamv1.ServiceAccount{{Email: "app@acme-prod.iam.gserviceaccount.com"}}, nil
}

const net = "https://www.googleapis.com/compute/v1/projects/acme-prod/global/networks/default"

func fixture() *Clients {
	defSA := "123-compute@developer.gserviceaccount.com"
	return &Clients{
		Projects: fakeProjects{},
		IAM:      fakeIAM{},
		Compute: &fakeCompute{
			inst: []*compute.Instance{
				{Name: "web", SelfLink: "https://compute/projects/acme-prod/zones/us-central1-a/instances/web", Zone: "zones/us-central1-a", Status: "RUNNING",
					MachineType: "zones/us-central1-a/machineTypes/e2-standard-4", Tags: &compute.Tags{Items: []string{"web"}},
					NetworkInterfaces: []*compute.NetworkInterface{{Network: net, AccessConfigs: []*compute.AccessConfig{{NatIP: "34.1.2.3"}}}},
					ServiceAccounts:   []*compute.ServiceAccount{{Email: defSA, Scopes: []string{cloudPlatformScope}}},
					Labels:            map[string]string{"env": "prod", "team": "web"}, CreationTimestamp: "2024-01-02T03:04:05Z"},
				{Name: "batch", SelfLink: "https://compute/projects/acme-prod/zones/europe-west1-b/instances/batch", Zone: "zones/europe-west1-b", Status: "TERMINATED",
					MachineType:       "zones/europe-west1-b/machineTypes/n2-standard-8",
					NetworkInterfaces: []*compute.NetworkInterface{{Network: "global/networks/default"}},
					ServiceAccounts:   []*compute.ServiceAccount{{Email: "app@acme-prod.iam.gserviceaccount.com", Scopes: []string{cloudPlatformScope}}}},
			},
			fws: []*compute.Firewall{
				{Name: "allow-ssh", SelfLink: "fw/allow-ssh", Network: net, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"web"},
					Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}},
				{Name: "allow-rdp-range", SelfLink: "fw/allow-rdp-range", Network: net, SourceRanges: []string{"0.0.0.0/0"}, TargetTags: []string{"win"},
					Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"3000-4000"}}}},
				{Name: "internal", SelfLink: "fw/internal", Network: net, SourceRanges: []string{"10.0.0.0/8"},
					Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}}},
				{Name: "disabled-all", SelfLink: "fw/disabled-all", Network: net, SourceRanges: []string{"0.0.0.0/0"}, Disabled: true,
					Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}}},
			},
			disks: []*compute.Disk{
				{Name: "orphan", SelfLink: "disk/orphan", Zone: "zones/us-central1-a", SizeGb: 200, Type: "zones/us-central1-a/diskTypes/pd-ssd"},
				{Name: "web-boot", SelfLink: "disk/web-boot", Zone: "zones/us-central1-a", SizeGb: 10, Type: "diskTypes/pd-standard", Users: []string{"https://compute/projects/acme-prod/zones/us-central1-a/instances/web"}},
			},
			addrs: []*compute.Address{
				{Name: "spare", SelfLink: "addr/spare", Region: "regions/us-central1", Status: "RESERVED", AddressType: "EXTERNAL", Address: "35.0.0.1"},
				{Name: "used", SelfLink: "addr/used", Region: "regions/us-central1", Status: "IN_USE", Address: "34.1.2.3"},
				{Name: "internal", SelfLink: "addr/internal", Region: "regions/us-central1", Status: "RESERVED", AddressType: "INTERNAL"},
			},
		},
		Storage: &fakeStorage{b: []BucketInfo{
			{Name: "customer-exports", Location: "US", Members: []string{"allUsers", "projectOwner:acme-prod"}},
			{Name: "locked", Location: "US", Members: []string{"allUsers"}, PublicAccessPrevention: "enforced"},
			{Name: "private", Location: "EU", Members: []string{"user:a@acme.com"}, Labels: map[string]string{"classification": "pii"}},
		}},
		SQL: &fakeSQL{in: []*sqladmin.DatabaseInstance{
			{Name: "orders", SelfLink: "sql/orders", Region: "us-central1", Settings: &sqladmin.Settings{IpConfiguration: &sqladmin.IpConfiguration{
				Ipv4Enabled: true, AuthorizedNetworks: []*sqladmin.AclEntry{{Value: "0.0.0.0/0"}}}}},
			{Name: "ledger", SelfLink: "sql/ledger", Region: "us-central1", Settings: &sqladmin.Settings{IpConfiguration: &sqladmin.IpConfiguration{
				SslMode: "ENCRYPTED_ONLY"}}},
		}},
	}
}

func collect(t *testing.T, cl *Clients) (core.Result, *graph.Graph) {
	t.Helper()
	c := &Collector{NewClients: func(context.Context, core.AccountSpec) (*Clients, error) { return cl, nil },
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	g := graph.New()
	res, err := c.Collect(context.Background(), core.AccountSpec{Name: "prod", Provider: "gcp", ProjectID: proj}, g)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return res, g
}

func statusOf(res core.Result, check, resourceID string) model.Status {
	for _, f := range res.Findings {
		if f.CheckID == check && f.Resource.ID == resourceID {
			return f.Status
		}
	}
	return ""
}

func TestFindings(t *testing.T) {
	res, _ := collect(t, fixture())
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
	cases := []struct {
		check, id string
		want      model.Status
	}{
		{"compute_firewall_ssh_access_from_the_internet_allowed", "fw/allow-ssh", model.Fail},
		{"compute_firewall_rdp_access_from_the_internet_allowed", "fw/allow-ssh", model.Pass},
		{"compute_firewall_rdp_access_from_the_internet_allowed", "fw/allow-rdp-range", model.Fail},
		{"compute_firewall_ssh_access_from_the_internet_allowed", "fw/internal", model.Pass},
		{"compute_firewall_ssh_access_from_the_internet_allowed", "fw/disabled-all", model.Pass},
		{"compute_instance_default_service_account_in_use_with_full_api_access", "https://compute/projects/acme-prod/zones/us-central1-a/instances/web", model.Fail},
		{"compute_instance_default_service_account_in_use_with_full_api_access", "https://compute/projects/acme-prod/zones/europe-west1-b/instances/batch", model.Pass},
		{"cloudstorage_bucket_public_access", BucketID("customer-exports"), model.Fail},
		{"cloudstorage_bucket_public_access", BucketID("locked"), model.Pass},
		{"cloudstorage_bucket_public_access", BucketID("private"), model.Pass},
		{"cloudsql_instance_public_ip", "sql/orders", model.Fail},
		{"cloudsql_instance_public_ip", "sql/ledger", model.Pass},
		{"cloudsql_instance_ssl_connections", "sql/orders", model.Fail},
		{"cloudsql_instance_ssl_connections", "sql/ledger", model.Pass},
	}
	for _, tc := range cases {
		t.Run(tc.check+"/"+tc.id, func(t *testing.T) {
			if got := statusOf(res, tc.check, tc.id); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
	for _, f := range res.Findings {
		if f.Source != core.Source || f.CanonicalID == "" || f.Provider != "gcp" || f.Account != proj {
			t.Errorf("bad finding envelope: %+v", f)
		}
	}
	if len(res.Runs) != 1 || res.Runs[0].Status != "ok" {
		t.Errorf("runs = %+v", res.Runs)
	}
}

func hasEdge(g *graph.Graph, from, to, kind string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

func TestGraph(t *testing.T) {
	_, g := collect(t, fixture())
	web := "https://compute/projects/acme-prod/zones/us-central1-a/instances/web"
	batch := "https://compute/projects/acme-prod/zones/europe-west1-b/instances/batch"
	acct := core.AccountNodeID("gcp", proj)
	cases := []struct {
		name, from, to, kind string
		want                 bool
	}{
		{"web attached to tagged ssh fw", web, "fw/allow-ssh", graph.EdgeAttachedTo, true},
		{"web not attached to win fw", web, "fw/allow-rdp-range", graph.EdgeAttachedTo, false},
		{"web attached to untargeted fw", web, "fw/internal", graph.EdgeAttachedTo, true},
		{"disabled fw never applies", web, "fw/disabled-all", graph.EdgeAttachedTo, false},
		{"fw allows traffic to web", "fw/allow-ssh", web, graph.EdgeAllowsTrafficTo, true},
		{"internet exposes web", graph.InternetNodeID, web, graph.EdgeExposes, true},
		{"internal net (partial path) matches", batch, "fw/internal", graph.EdgeAttachedTo, true},
		{"batch has no public ip", graph.InternetNodeID, batch, graph.EdgeExposes, false},
		{"internet exposes public bucket", graph.InternetNodeID, BucketID("customer-exports"), graph.EdgeExposes, true},
		{"PAP-enforced bucket not exposed", graph.InternetNodeID, BucketID("locked"), graph.EdgeExposes, false},
		{"internet exposes open sql", graph.InternetNodeID, "sql/orders", graph.EdgeExposes, true},
		{"web runs as default SA", web, saID(proj, "123-compute@developer.gserviceaccount.com"), graph.EdgeRunsAs, true},
		{"account contains web", acct, web, graph.EdgeContains, true},
		{"account contains SA", acct, saID(proj, "app@acme-prod.iam.gserviceaccount.com"), graph.EdgeContains, true},
		{"web attached to boot disk", web, "disk/web-boot", graph.EdgeAttachedTo, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasEdge(g, tc.from, tc.to, tc.kind); got != tc.want {
				t.Fatalf("edge %s -[%s]-> %s = %v, want %v", tc.from, tc.kind, tc.to, got, tc.want)
			}
		})
	}
	n, ok := g.Node(web)
	if !ok {
		t.Fatal("web node missing")
	}
	if n.Region != "us-central1" || n.Criticality != "production" || n.Owner != "web" || n.ModifiedAt != "2024-01-02T03:04:05Z" {
		t.Errorf("web node context = region %q crit %q owner %q mod %q", n.Region, n.Criticality, n.Owner, n.ModifiedAt)
	}
	if !n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Errorf("web node weaknesses = %v", n.Weaknesses)
	}
	if b, _ := g.Node(BucketID("private")); !b.Sensitive {
		t.Error("pii-labelled bucket should be sensitive")
	}
	if b, _ := g.Node(BucketID("customer-exports")); !b.Sensitive {
		t.Error("customer bucket should be sensitive by name")
	}
	if a, _ := g.Node(core.AccountNodeID("gcp", proj)); a.Owner != "platform" || a.Type != "gcp_project" {
		t.Errorf("account node = %+v", a)
	}
}

func TestCostSignals(t *testing.T) {
	res, _ := collect(t, fixture())
	got := map[string]core.CostSignal{}
	for _, c := range res.Cost {
		got[c.Kind+"|"+c.ResourceID] = c
	}
	cases := []struct {
		key   string
		check func(core.CostSignal) bool
	}{
		{core.KindUnattachedVolume + "|disk/orphan", func(c core.CostSignal) bool {
			return c.SizeGB == 200 && c.Attributes["disk_type"] == "pd-ssd" && c.Region == "us-central1"
		}},
		{core.KindUnassociatedIP + "|addr/spare", func(c core.CostSignal) bool { return c.Region == "us-central1" }},
		{core.KindStoppedInstance + "|https://compute/projects/acme-prod/zones/europe-west1-b/instances/batch", func(c core.CostSignal) bool { return c.InstanceType == "n2-standard-8" && c.Region == "europe-west1" }},
	}
	for _, tc := range cases {
		c, ok := got[tc.key]
		if !ok || !tc.check(c) {
			t.Errorf("signal %s = %+v (present %v)", tc.key, c, ok)
		}
	}
	if len(res.Cost) != len(cases) {
		t.Errorf("got %d cost signals, want %d: %+v", len(res.Cost), len(cases), res.Cost)
	}
}

func TestPartialFailure(t *testing.T) {
	cl := fixture()
	cl.Compute.(*fakeCompute).err = errors.New("permission denied")
	cl.Storage = &fakeStorage{err: errors.New("storage down")}
	res, g := collect(t, cl)
	if len(res.Errors) != 2 {
		t.Fatalf("errors = %v", res.Errors)
	}
	if statusOf(res, "cloudsql_instance_public_ip", "sql/orders") != model.Fail {
		t.Error("sql findings should survive partial failure")
	}
	if statusOf(res, "compute_firewall_ssh_access_from_the_internet_allowed", "fw/allow-ssh") != model.Fail {
		t.Error("firewall findings should survive instance listing failure")
	}
	if _, ok := g.Node("sql/orders"); !ok {
		t.Error("sql node missing")
	}
	if res.Runs[0].Status != "ok" || res.Runs[0].Message == "" {
		t.Errorf("run = %+v", res.Runs[0])
	}
}

func TestCollectErrors(t *testing.T) {
	cases := []struct {
		name string
		spec core.AccountSpec
		cl   func(context.Context, core.AccountSpec) (*Clients, error)
	}{
		{"missing project", core.AccountSpec{Provider: "gcp"}, func(context.Context, core.AccountSpec) (*Clients, error) { return &Clients{}, nil }},
		{"client failure", core.AccountSpec{ProjectID: proj}, func(context.Context, core.AccountSpec) (*Clients, error) { return nil, errors.New("no ADC") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (&Collector{NewClients: tc.cl}).Collect(context.Background(), tc.spec, graph.New()); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	ports := []struct {
		spec string
		port int
		want bool
	}{{"22", 22, true}, {"20-30", 22, true}, {"3389", 22, false}, {"1-1000", 3389, false}, {"bad", 22, false}}
	for _, p := range ports {
		if got := portSpecContains(p.spec, p.port); got != p.want {
			t.Errorf("portSpecContains(%q,%d) = %v", p.spec, p.port, got)
		}
	}
	allow := []struct {
		fw   *compute.Firewall
		port int
		want bool
	}{
		{&compute.Firewall{Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}}}, 3389, true},
		{&compute.Firewall{Allowed: []*compute.FirewallAllowed{{IPProtocol: "udp"}}}, 22, false},
		{&compute.Firewall{Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}}, 22, true},
	}
	for i, a := range allow {
		if got := allowsTCPPort(a.fw, a.port); got != a.want {
			t.Errorf("case %d allowsTCPPort = %v", i, got)
		}
	}
	saFW := &compute.Firewall{Network: net, TargetServiceAccounts: []string{"x@y"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}}}
	inst := &compute.Instance{NetworkInterfaces: []*compute.NetworkInterface{{Network: net}}, ServiceAccounts: []*compute.ServiceAccount{{Email: "x@y"}}}
	if !applies(saFW, inst) {
		t.Error("firewall targeting the instance SA should apply")
	}
	inst.ServiceAccounts[0].Email = "z@y"
	if applies(saFW, inst) {
		t.Error("firewall targeting another SA should not apply")
	}
	egress := &compute.Firewall{Network: net, Direction: "EGRESS"}
	if applies(egress, inst) {
		t.Error("egress firewall should not apply")
	}
	if regionOf("us-central1-a") != "us-central1" {
		t.Error("regionOf")
	}
}

// Defect 15(d): GCP evaluates ingress rules by priority (lower number first) and a
// deny wins over an allow at the same priority.
func TestFirewallDenyAndPriority(t *testing.T) {
	webID := "https://compute/projects/acme-prod/zones/us-central1-a/instances/web"
	deny := func(name string, prio int64, src string, ports ...string) *compute.Firewall {
		return &compute.Firewall{Name: name, SelfLink: "fw/" + name, Network: net, Priority: prio, SourceRanges: []string{src},
			Denied: []*compute.FirewallDenied{{IPProtocol: "tcp", Ports: ports}}}
	}
	allow := func(name string, prio int64, src string, ports ...string) *compute.Firewall {
		return &compute.Firewall{Name: name, SelfLink: "fw/" + name, Network: net, Priority: prio, SourceRanges: []string{src}, TargetTags: []string{"web"},
			Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: ports}}}
	}
	cases := []struct {
		name    string
		extra   []*compute.Firewall
		replace bool // replace the fixture's allow-ssh (priority 0 = default 1000)
		exposed bool
		width   string
		sshFail bool // compute_firewall_ssh_access_from_the_internet_allowed on fw/allow-ssh
	}{
		{"baseline allow 0.0.0.0/0", nil, false, true, core.ExposureWide, true},
		{"higher-priority deny blocks", []*compute.Firewall{deny("deny-ssh", 900, "0.0.0.0/0", "22")}, false, false, "", false},
		{"equal-priority deny wins", []*compute.Firewall{deny("deny-ssh", 1000, "0.0.0.0/0", "22")}, false, false, "", false},
		{"lower-priority deny is shadowed", []*compute.Firewall{deny("deny-ssh", 2000, "0.0.0.0/0", "22")}, false, true, core.ExposureWide, true},
		{"deny on another port does not block", []*compute.Firewall{deny("deny-rdp", 100, "0.0.0.0/0", "3389")}, false, true, core.ExposureWide, true},
		{"narrow source", []*compute.Firewall{allow("ssh-office", 1000, "198.51.100.0/24", "22")}, true, true, core.ExposureNarrow, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl := fixture()
			fc := cl.Compute.(*fakeCompute)
			if tc.replace {
				fc.fws = fc.fws[1:]
			}
			fc.fws = append(fc.fws, tc.extra...)
			res, g := collect(t, cl)
			var attr map[string]any
			for _, e := range g.Out(graph.InternetNodeID) {
				if e.To == webID && e.Kind == graph.EdgeExposes {
					attr = e.Attr
				}
			}
			if (attr != nil) != tc.exposed {
				t.Fatalf("exposed = %v (%v), want %v", attr != nil, attr, tc.exposed)
			}
			if tc.exposed && attr[core.AttrExposure] != tc.width {
				t.Errorf("exposure = %v, want %s", attr[core.AttrExposure], tc.width)
			}
			if !tc.replace {
				want := model.Pass
				if tc.sshFail {
					want = model.Fail
				}
				if got := statusOf(res, "compute_firewall_ssh_access_from_the_internet_allowed", "fw/allow-ssh"); got != want {
					t.Errorf("ssh finding on allow-ssh = %q, want %q", got, want)
				}
			}
		})
	}
}

type fakeProjectIAM struct {
	b   []IAMBinding
	err error
}

func (f fakeProjectIAM) IAMPolicy(context.Context, string) ([]IAMBinding, error) { return f.b, f.err }

// Defect 15(d): project IAM is collected so GCP SA → role edges exist for attack paths.
func TestProjectIAMBindings(t *testing.T) {
	defSA := "123-compute@developer.gserviceaccount.com"
	cl := fixture()
	cl.ProjectIAM = fakeProjectIAM{b: []IAMBinding{
		{Role: "roles/editor", Members: []string{"serviceAccount:" + defSA, "user:alice@acme.com"}},
		{Role: "roles/storage.objectViewer", Members: []string{"serviceAccount:app@acme-prod.iam.gserviceaccount.com", "group:eng@acme.com"}},
		{Role: "projects/acme-prod/roles/customDeployer", Members: []string{"serviceAccount:app@acme-prod.iam.gserviceaccount.com"}, Condition: "expires 2027"},
	}}
	res, g := collect(t, cl)
	sa := saID(proj, defSA)
	editor := RoleID(proj, "roles/editor")
	if editor != "//cloudresourcemanager.googleapis.com/projects/acme-prod/roles/editor" {
		t.Fatalf("RoleID = %s", editor)
	}
	has := func(from, to string) map[string]any {
		for _, e := range g.Out(from) {
			if e.To == to && e.Kind == graph.EdgeHasPolicy {
				return e.Attr
			}
		}
		return nil
	}
	if a := has(sa, editor); a == nil || a["role"] != "roles/editor" || a["member"] != "serviceAccount:"+defSA {
		t.Fatalf("SA → roles/editor has_policy edge = %v", a)
	}
	if has("gcp:user/alice@acme.com", editor) == nil || has("gcp:group/eng@acme.com", RoleID(proj, "roles/storage.objectViewer")) == nil {
		t.Error("user / group binding edges missing")
	}
	custom := RoleID(proj, "projects/acme-prod/roles/customDeployer")
	if a := has(saID(proj, "app@acme-prod.iam.gserviceaccount.com"), custom); a == nil || a["condition"] != "expires 2027" {
		t.Errorf("custom role edge = %v", a)
	}
	n, _ := g.Node(editor)
	if n == nil || n.Type != "gcp_iam_role" || n.Class != graph.ClassIdentity || !n.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Fatalf("editor role node = %+v", n)
	}
	if v, _ := g.Node(RoleID(proj, "roles/storage.objectViewer")); v.HasWeakness("OVERPRIVILEGED_IDENTITY") {
		t.Error("non-primitive role flagged as overprivileged")
	}
	if got := statusOf(res, "iam_role_assigned_to_user_or_sa_primitive", editor); got != model.Fail {
		t.Errorf("primitive role finding = %q", got)
	}
	// Unreadable IAM policy is a coverage error, not a silent gap.
	cl = fixture()
	cl.ProjectIAM = fakeProjectIAM{err: errors.New("googleapi: Error 403: Permission denied, forbidden")}
	res, _ = collect(t, cl)
	ces := res.CollectErrors()
	if len(ces) != 1 || ces[0].API != "gcp/resourcemanager.getIamPolicy" || ces[0].Reason != core.ReasonAccessDenied {
		t.Fatalf("collect errors = %+v", ces)
	}
}
