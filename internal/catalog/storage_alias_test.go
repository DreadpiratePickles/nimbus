package catalog

import "testing"

// P1-ENGINE noise round, decision 5: storage checks that are not "anonymous read" must not map
// to a canonical that carries PUBLIC_DATA_STORE (the engine reads that as "readable by anyone").
// The noise estate's halyardbackups / halyardcrmexports (private-endpoint-only, TLS 1.1) were
// reported at 10.00 through prowler storage_ensure_minimum_tls_version_12 → AZ_STORAGE_PUBLIC_BLOB.
func TestStorageAliasesMatchTheirWeakness(t *testing.T) {
	c := Default()
	hasPublic := func(e *Entry) bool {
		for _, w := range e.Weaknesses {
			if w == "PUBLIC_DATA_STORE" {
				return true
			}
		}
		return false
	}
	// TLS checks → AZ_STORAGE_TLS_MIN_VERSION (WEAK_TLS).
	for src, id := range map[string]string{"prowler": "storage_ensure_minimum_tls_version_12", "checkov": "CKV_AZURE_44", "trivy": "AVD-AZU-0011"} {
		e, ok := c.Lookup(src, id)
		if !ok || e.ID != "AZ_STORAGE_TLS_MIN_VERSION" {
			t.Errorf("%s %s → %v, want AZ_STORAGE_TLS_MIN_VERSION", src, id, e)
			continue
		}
		if len(e.Weaknesses) != 1 || e.Weaknesses[0] != "WEAK_TLS" {
			t.Errorf("AZ_STORAGE_TLS_MIN_VERSION weaknesses %v, want [WEAK_TLS]", e.Weaknesses)
		}
	}
	// Network-rule checks (endpoint reachable, authentication still required) and GCS uniform
	// bucket-level access are not anonymous read either.
	for src, ids := range map[string][]string{
		"checkov":    {"CKV_AZURE_59", "CKV_GCP_29"},
		"trivy":      {"AVD-AZU-0012", "AVD-GCP-0002"},
		"scoutsuite": {"storageaccounts-public-traffic-allowed"},
		"steampipe":  {"storage_account_default_network_access_rule_denied", "storage_bucket_uniform_access_enabled"},
	} {
		for _, id := range ids {
			e, ok := c.Lookup(src, id)
			if !ok {
				t.Errorf("%s %s: no longer catalogued", src, id)
				continue
			}
			if hasPublic(e) {
				t.Errorf("%s %s → %s carries PUBLIC_DATA_STORE", src, id, e.ID)
			}
		}
	}
	// The real anonymous-read checks keep their mapping.
	for src, want := range map[string][2]string{
		"prowler":   {"storage_blob_public_access_level_is_disabled", "AZ_STORAGE_PUBLIC_BLOB"},
		"checkov":   {"CKV_AZURE_190", "AZ_STORAGE_PUBLIC_BLOB"},
		"trivy":     {"AVD-GCP-0001", "GCP_BUCKET_PUBLIC"},
		"steampipe": {"storage_bucket_not_publicly_accessible", "GCP_BUCKET_PUBLIC"},
	} {
		if e, ok := c.Lookup(src, want[0]); !ok || e.ID != want[1] || !hasPublic(e) {
			t.Errorf("%s %s → %v, want %s with PUBLIC_DATA_STORE", src, want[0], e, want[1])
		}
	}
}
