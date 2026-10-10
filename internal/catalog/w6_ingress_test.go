package catalog

import "testing"

// W6-ENGINE item 3 (competitive delta r4 #11): the two security-relevant unmapped scanner ids map
// to open-ingress canonicals that carry PUBLIC_NETWORK_EXPOSURE (so the engine and compliance
// see them), not to a canonical with another meaning.
func TestOpenIngressScannerIDsMapped(t *testing.T) {
	c := Default()
	for _, x := range []struct{ src, id, want, rtype string }{
		{"checkov", "CKV_AWS_260", "EC2_SG_OPEN_HTTP", "aws_security_group"},
		{"trivy", "AVD-AZU-0047", "AZ_NSG_UNRESTRICTED_SOURCE", "azure_network_security_group"},
		{"trivy", "AZU-0047", "AZ_NSG_UNRESTRICTED_SOURCE", "azure_network_security_group"},
	} {
		e, ok := c.Lookup(x.src, x.id)
		if !ok || e.ID != x.want {
			t.Errorf("%s %s → %v, want %s", x.src, x.id, e, x.want)
			continue
		}
		if e.ResourceType != x.rtype || len(e.Weaknesses) != 1 || e.Weaknesses[0] != "PUBLIC_NETWORK_EXPOSURE" || len(e.Remediation) == 0 {
			t.Errorf("%s: resource %s weaknesses %v remediation %v", e.ID, e.ResourceType, e.Weaknesses, e.Remediation)
		}
	}
}
