package catalog

import "testing"

// Competitive delta 2026-10-09-r2 shortfall #15, third alias tranche (Checkov golden coverage
// 72.6% → ≥80%). Meanings checked against check_name / Title in lab/golden/<tool>/<version>/*.json;
// every alias names the same resource family, the same property and the same direction as its
// canonical. No existing canonical had these meanings, so each gets its own entry.
func TestScannerAliasBatch3Meanings(t *testing.T) {
	c := Default()
	checkov := map[string]string{
		"CKV_GCP_49":    "GCP_SA_IMPERSONATION_ROLE",        // roles that impersonate/manage SAs at project level
		"CKV_GCP_41":    "GCP_SA_IMPERSONATION_ROLE",        // SA User / Token Creator at project level
		"CKV_GCP_46":    "GCP_DEFAULT_SA_PROJECT_ROLE",      // default service account not used at project level
		"CKV2_AZURE_40": "AZ_STORAGE_SHARED_KEY_ENABLED",    // storage account not configured with Shared Key authorization
		"CKV2_AZURE_41": "AZ_STORAGE_SAS_NO_EXPIRATION",     // storage account configured with SAS expiration policy
		"CKV2_AZURE_33": "AZ_STORAGE_NO_PRIVATE_ENDPOINT",   // storage account configured with private endpoint
		"CKV_AWS_273":   "IAM_USER_NOT_FEDERATED",           // access controlled through SSO, not IAM-defined users
		"CKV_K8S_43":    "K8S_IMAGE_NOT_PINNED_BY_DIGEST",   // image should use digest
		"CKV_K8S_15":    "K8S_IMAGE_PULL_POLICY_NOT_ALWAYS", // image pull policy should be Always
		"CKV_AWS_353":   "RDS_NO_PERFORMANCE_INSIGHTS",      // RDS instances have performance insights enabled
		"CKV_AWS_126":   "EC2_NO_DETAILED_MONITORING",       // detailed monitoring enabled for EC2 instances
		// Still deferred: operational / reliability with no security meaning, or no equivalent canonical.
		"CKV_AWS_135":   "",                 // EC2 EBS-optimized (performance)
		"CKV_AWS_118":   "",                 // RDS enhanced monitoring (OS metrics; not performance insights, not DB logs)
		"CKV_AWS_260":   "EC2_SG_OPEN_HTTP", // 0.0.0.0/0 to port 80 (W6-ENGINE, r4 #11)
		"CKV_K8S_8":     "",                 // liveness probe
		"CKV_K8S_9":     "",                 // readiness probe
		"CKV2_AZURE_38": "",                 // storage soft-delete
		"CKV_AZURE_206": "",                 // storage replication
		"CKV_AWS_144":   "",                 // S3 cross-region replication
		"CKV2_AWS_61":   "",                 // S3 lifecycle configuration
		"CKV2_AWS_62":   "",                 // S3 event notifications
		"CKV2_AWS_60":   "",                 // RDS copy tags to snapshots
		"CKV2_AWS_5":    "",                 // security group attached to a resource
		"CKV_AWS_115":   "",                 // Lambda concurrency limit
		"CKV_AWS_116":   "",                 // Lambda dead-letter queue
	}
	for id, want := range checkov {
		wantCanonical(t, c, "checkov", id, want)
	}
	// Trivy AWS-0133 "Enable Performance Insights to detect potential problems" = CKV_AWS_353.
	wantCanonical(t, c, "trivy", "AWS-0133", "RDS_NO_PERFORMANCE_INSIGHTS")
	wantCanonical(t, c, "prowler", "ec2_instance_detailed_monitoring_enabled", "EC2_NO_DETAILED_MONITORING")
}

func TestScannerAliasBatch3Entries(t *testing.T) {
	c := Default()
	want := map[string]struct {
		provider, severity string
		weaknesses         []string
	}{
		"GCP_SA_IMPERSONATION_ROLE":        {"gcp", "HIGH", []string{"OVERPRIVILEGED_IDENTITY"}},
		"GCP_DEFAULT_SA_PROJECT_ROLE":      {"gcp", "MEDIUM", []string{"DEFAULT_SERVICE_ACCOUNT"}},
		"AZ_STORAGE_SHARED_KEY_ENABLED":    {"azure", "MEDIUM", nil},
		"AZ_STORAGE_SAS_NO_EXPIRATION":     {"azure", "LOW", nil},
		"AZ_STORAGE_NO_PRIVATE_ENDPOINT":   {"azure", "LOW", nil},
		"IAM_USER_NOT_FEDERATED":           {"aws", "LOW", nil},
		"K8S_IMAGE_NOT_PINNED_BY_DIGEST":   {"kubernetes", "LOW", nil},
		"K8S_IMAGE_PULL_POLICY_NOT_ALWAYS": {"kubernetes", "LOW", nil},
		"RDS_NO_PERFORMANCE_INSIGHTS":      {"aws", "LOW", nil},
		"EC2_NO_DETAILED_MONITORING":       {"aws", "LOW", nil},
	}
	for id, w := range want {
		e, ok := c.Get(id)
		if !ok {
			t.Errorf("%s missing from catalog.yaml", id)
			continue
		}
		if e.Title == "" || e.ResourceType == "" || len(e.Compliance) == 0 {
			t.Errorf("%s: incomplete entry %+v", id, e)
		}
		if string(e.Provider) != w.provider || string(e.Severity) != w.severity {
			t.Errorf("%s: provider/severity %s/%s, want %s/%s", id, e.Provider, e.Severity, w.provider, w.severity)
		}
		if len(e.Weaknesses) != len(w.weaknesses) {
			t.Errorf("%s: weaknesses %v, want %v", id, e.Weaknesses, w.weaknesses)
			continue
		}
		for i := range w.weaknesses {
			if e.Weaknesses[i] != w.weaknesses[i] {
				t.Errorf("%s: weaknesses %v, want %v", id, e.Weaknesses, w.weaknesses)
			}
		}
	}
}
