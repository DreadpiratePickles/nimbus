package catalog

import (
	"strings"
	"testing"
)

// W7-ENGINE item 8 (verification 7 defect 9): Trivy AVD-AZU-0047 means "an inbound rule allows
// traffic from any source address" on whatever port that rule opens, not "any port". It maps to
// its own unrestricted-source canonical (HIGH, PUBLIC_NETWORK_EXPOSURE, no RDP/SSH controls), so
// one RDP-from-* rule is AZ_NSG_OPEN_RDP plus an unrestricted-source finding, never a CRITICAL
// "any port" one.
func TestAZU0047IsUnrestrictedSourceNotAnyPort(t *testing.T) {
	c := Default()
	for _, id := range []string{"AVD-AZU-0047", "AZU-0047"} {
		e, ok := c.Lookup("trivy", id)
		if !ok || e.ID != "AZ_NSG_UNRESTRICTED_SOURCE" {
			t.Fatalf("trivy %s → %v, want AZ_NSG_UNRESTRICTED_SOURCE", id, e)
		}
		if strings.Contains(strings.ToLower(e.Title), "any port") || e.Severity == "CRITICAL" {
			t.Errorf("%s: title %q severity %s", e.ID, e.Title, e.Severity)
		}
		if len(e.Compliance["cis_azure"]) != 0 {
			t.Errorf("%s maps to CIS Azure %v (RDP/SSH controls); the port is not known", e.ID, e.Compliance["cis_azure"])
		}
	}
	if _, ok := c.Get("AZ_NSG_OPEN_ALL"); ok {
		t.Errorf("AZ_NSG_OPEN_ALL (\"any port\") must be gone")
	}
}
