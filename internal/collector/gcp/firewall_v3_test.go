package gcp

import (
	"strings"
	"testing"

	compute "google.golang.org/api/compute/v1"
)

// Verify-3 defect 9: an IPv4 0.0.0.0/0 deny does not cover IPv6 sources, so a ::/0
// allow behind it still exposes the port (and vice versa).
func TestEvaluateIngressIPv6IndependentOfIPv4Deny(t *testing.T) {
	v4, v6 := []string{"0.0.0.0/0"}, []string{"::/0"}
	cases := []struct {
		name        string
		fws         []*compute.Firewall
		ports, srcs string
	}{
		{"v4 deny shadows nothing on ::/0 allow", []*compute.Firewall{v2fw("deny4", 100, false, v4, "tcp", "22"), v2fw("allow6", 1000, true, v6, "tcp", "22")}, "tcp:22", "::/0"},
		{"v4 deny all + v6 allow ssh", []*compute.Firewall{v2fw("deny4", 100, false, v4, "all"), v2fw("allow6", 1000, true, v6, "tcp", "22")}, "tcp:22", "::/0"},
		{"v6 deny does not shadow v4 allow", []*compute.Firewall{v2fw("deny6", 100, false, v6, "tcp", "22"), v2fw("allow4", 1000, true, v4, "tcp", "22")}, "tcp:22", "0.0.0.0/0"},
		{"v6 deny shadows v6 allow", []*compute.Firewall{v2fw("deny6", 100, false, v6, "tcp", "22"), v2fw("allow6", 1000, true, v6, "tcp", "22")}, "", ""},
		{"dual allow, v4 denied: v6 still open", []*compute.Firewall{v2fw("deny4", 100, false, v4, "tcp", "22"), v2fw("allow", 1000, true, []string{"0.0.0.0/0", "::/0"}, "tcp", "22")}, "tcp:22", "::/0"},
		{"v6 prefix deny covers v6 /0 allow only partly", []*compute.Firewall{v2fw("deny6", 100, false, []string{"2001:db8::/32"}, "tcp", "22"), v2fw("allow6", 1000, true, v6, "tcp", "22")}, "tcp:22", "::/0"},
	}
	for _, c := range cases {
		ex := evaluateIngress(c.fws)
		if got := strings.Join(ex.ports, ";"); got != c.ports {
			t.Errorf("%s: ports=%q want %q", c.name, got, c.ports)
		}
		if got := strings.Join(ex.sources, ";"); got != c.srcs {
			t.Errorf("%s: sources=%q want %q", c.name, got, c.srcs)
		}
	}
}
