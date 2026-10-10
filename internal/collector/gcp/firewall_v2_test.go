package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// V2 defect 8 (GCP): explicit priority 0 is not the 1000 default, and a port range is
// exposed when any port in it is admitted. Adapted from the verifier probe zz_verify_fw_test.go.

func v2fw(name string, prio int64, allow bool, src []string, proto string, ports ...string) *compute.Firewall {
	fw := &compute.Firewall{Name: name, Network: "global/networks/default", Priority: prio, SourceRanges: src}
	if prio == 0 {
		fw.Priority = 1000 // unset: GCP's default
	}
	if prio < 0 { // explicit priority 0, as the API client marks it
		fw.Priority = 0
		fw.ForceSendFields = []string{"Priority"}
	}
	if allow {
		fw.Allowed = []*compute.FirewallAllowed{{IPProtocol: proto, Ports: ports}}
	} else {
		fw.Denied = []*compute.FirewallDenied{{IPProtocol: proto, Ports: ports}}
	}
	return fw
}

func TestEvaluateIngressPriorityZeroAndRanges(t *testing.T) {
	world := []string{"0.0.0.0/0"}
	cases := []struct {
		name string
		fws  []*compute.Firewall
		want string
	}{
		{"tie: allow+deny at 1000 -> deny wins", []*compute.Firewall{v2fw("a", 1000, true, world, "tcp", "22"), v2fw("d", 1000, false, world, "tcp", "22")}, ""},
		{"deny 0/0 at 65535, allow at 1000 -> exposed", []*compute.Firewall{v2fw("d", 65535, false, world, "all"), v2fw("a", 1000, true, world, "tcp", "22")}, "tcp:22"},
		{"explicit priority 0 deny vs allow 500", []*compute.Firewall{v2fw("d", -1, false, world, "tcp", "22"), v2fw("a", 500, true, world, "tcp", "22")}, ""},
		{"explicit priority 0 allow vs deny 500", []*compute.Firewall{v2fw("a", -1, true, world, "tcp", "22"), v2fw("d", 500, false, world, "tcp", "22")}, "tcp:22"},
		{"unset priority (1000) allow vs deny 500", []*compute.Firewall{v2fw("a", 0, true, world, "tcp", "22"), v2fw("d", 500, false, world, "tcp", "22")}, ""},
		{"range 20-30 with deny 20 first (21-30 open)", []*compute.Firewall{v2fw("d", 100, false, world, "tcp", "20"), v2fw("a", 1000, true, world, "tcp", "20-30")}, "tcp:20-30"},
		{"range 20-30 fully denied by two rules", []*compute.Firewall{v2fw("d", 100, false, world, "tcp", "20-25"), v2fw("d2", 100, false, world, "tcp", "26-30"), v2fw("a", 1000, true, world, "tcp", "20-30")}, ""},
		{"allow tcp all ports, deny tcp 0-65535 first", []*compute.Firewall{v2fw("d", 100, false, world, "tcp", "0-65535"), v2fw("a", 1000, true, world, "tcp")}, ""},
		{"allow tcp all ports, deny tcp 22 first", []*compute.Firewall{v2fw("d", 100, false, world, "tcp", "22"), v2fw("a", 1000, true, world, "tcp")}, "tcp:all"},
		{"allow proto 6 deny tcp", []*compute.Firewall{v2fw("d", 100, false, world, "tcp", "22"), v2fw("a", 1000, true, world, "6", "22")}, ""},
	}
	for _, c := range cases {
		if got := strings.Join(evaluateIngress(c.fws).ports, ";"); got != c.want {
			t.Errorf("%s: ports=%q want %q", c.name, got, c.want)
		}
	}
}

// Every firewall the API lists carries its effective priority (GCP fills in 1000 at
// creation), so a listed rule with priority 0 is an explicit 0 and is marked as such.
func TestComputeClientMarksExplicitPriorityZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[{"name":"zero","priority":0},{"name":"omitted"},{"name":"def","priority":1000}]}`))
	}))
	defer srv.Close()
	svc, err := compute.NewService(context.Background(), option.WithEndpoint(srv.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	fws, err := (&computeClient{svc: svc}).Firewalls(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, fw := range fws {
		got[fw.Name] = priority(fw)
	}
	if got["zero"] != 0 || got["omitted"] != 0 || got["def"] != 1000 {
		t.Fatalf("priorities %v", got)
	}
}
