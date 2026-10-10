package azure

import (
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
)

// V2 defect 8 (Azure): a port range is exposed when any port in it is admitted, not
// only its lowest port. Adapted from the verifier probe zz_verify_nsg_test.go.
func TestLayeredExposurePortRanges(t *testing.T) {
	const A, D = armnetwork.SecurityRuleAccessAllow, armnetwork.SecurityRuleAccessDeny
	n := func(rules ...*armnetwork.SecurityRule) *armnetwork.SecurityGroup {
		return nsg("/x/"+strings.Repeat("n", len(rules)), rules)
	}
	cases := []struct {
		name   string
		layers []*armnetwork.SecurityGroup
		want   string
	}{
		{"range 20-30 open", []*armnetwork.SecurityGroup{n(rule("a", 100, A, "Internet", "20-30"))}, "20-30"},
		{"range 20-30, port 20 denied first (21-30 open)", []*armnetwork.SecurityGroup{n(rule("d", 100, D, "Internet", "20"), rule("a", 200, A, "Internet", "20-30"))}, "20-30"},
		{"range 20-30 fully denied by two rules", []*armnetwork.SecurityGroup{n(rule("d", 100, D, "Internet", "20-25"), rule("d2", 101, D, "Internet", "26-30"), rule("a", 200, A, "Internet", "20-30"))}, ""},
		{"two layers, NIC 20-30, subnet allows 22 only", []*armnetwork.SecurityGroup{n(rule("a", 100, A, "*", "22")), n(rule("a", 100, A, "*", "20-30"))}, "20-30,22"},
		{"NIC * open, subnet denies 0-1024 then allows *", []*armnetwork.SecurityGroup{n(rule("d", 100, D, "*", "0-1024"), rule("a", 200, A, "*", "*")), n(rule("a", 100, A, "*", "*"))}, "*"},
		{"subnet denies 22 only, NIC allows 22-22", []*armnetwork.SecurityGroup{n(rule("d", 100, D, "*", "22"), rule("a", 200, A, "*", "*")), n(rule("a", 100, A, "*", "22-22"))}, ""},
	}
	for _, c := range cases {
		p, _ := LayeredInternetExposure(c.layers)
		if got := strings.Join(p, ","); got != c.want {
			t.Errorf("%s: ports=%q want %q", c.name, got, c.want)
		}
	}
}

func TestInternetOpenPortsRange(t *testing.T) {
	const A, D = armnetwork.SecurityRuleAccessAllow, armnetwork.SecurityRuleAccessDeny
	g := nsg("/x/g", []*armnetwork.SecurityRule{rule("d", 100, D, "Internet", "20"), rule("a", 200, A, "Internet", "20-30")})
	if got := strings.Join(InternetOpenPorts(g), ","); got != "20-30" {
		t.Fatalf("InternetOpenPorts=%q, want 20-30 (21-30 are open)", got)
	}
}
