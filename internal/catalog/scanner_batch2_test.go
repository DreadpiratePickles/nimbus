package catalog

import (
	"strings"
	"testing"
)

// Competitive delta 2026-10-09-r2 shortfall #15: second alias tranche driven by the lab IaC goldens
// (lab/golden/checkov/3.3.26, lab/golden/trivy/0.75.0). Meanings checked against check_name / Title
// in the golden JSON; each canonical below means the same thing in both scanners.
func TestScannerAliasBatch2Meanings(t *testing.T) {
	c := Default()
	checkov := map[string]string{
		"CKV_AWS_23":    "EC2_SG_NO_DESCRIPTION",        // every security group and rule has a description
		"CKV_AWS_382":   "EC2_SG_OPEN_EGRESS",           // no egress from 0.0.0.0:0 to port -1
		"CKV_AWS_293":   "RDS_NO_DELETION_PROTECTION",   // database instances have deletion protection
		"CKV_AWS_161":   "RDS_NO_IAM_AUTH",              // RDS database has IAM authentication enabled
		"CKV_AWS_129":   "RDS_LOGGING_DISABLED",         // respective logs of RDS are enabled
		"CKV2_AWS_30":   "RDS_LOGGING_DISABLED",         // Postgres RDS has query logging enabled
		"CKV_AWS_145":   "S3_NO_CMK",                    // S3 buckets encrypted with KMS by default
		"CKV_AWS_40":    "IAM_POLICY_ON_USER",           // IAM policies attached only to groups or roles
		"CKV_AWS_50":    "LAMBDA_NO_TRACING",            // X-Ray tracing is enabled for Lambda
		"CKV_AWS_117":   "LAMBDA_NOT_IN_VPC",            // Lambda function configured inside a VPC
		"CKV_AWS_272":   "LAMBDA_NO_CODE_SIGNING",       // Lambda validates code-signing
		"CKV_K8S_28":    "K8S_CAPABILITIES_NOT_DROPPED", // containers with the NET_RAW capability
		"CKV_K8S_37":    "K8S_CAPABILITIES_NOT_DROPPED", // containers with capabilities assigned
		"CKV_K8S_22":    "K8S_WRITABLE_ROOT_FS",         // read-only filesystem for containers
		"CKV_K8S_31":    "K8S_NO_SECCOMP",               // seccomp profile docker/default or runtime/default
		"CKV_K8S_29":    "K8S_NO_SECURITY_CONTEXT",      // security context on pods and containers
		"CKV_K8S_30":    "K8S_NO_SECURITY_CONTEXT",      // security context on containers
		"CKV2_AZURE_1":  "AZ_STORAGE_NO_CMK",            // storage encrypted with Customer Managed Key
		"CKV2_AZURE_21": "AZ_STORAGE_LOGGING_DISABLED",  // Storage logging for Blob service read requests
		"CKV_AZURE_33":  "AZ_STORAGE_LOGGING_DISABLED",  // Storage logging for Queue service
		"CKV_GCP_32":    "GCP_PROJECT_SSH_KEYS_ALLOWED", // Block Project-wide SSH keys
		"CKV_GCP_39":    "GCP_SHIELDED_VM_DISABLED",     // Shielded VM enabled
		"CKV_GCP_38":    "GCP_DISK_NO_CSEK",             // VM disks encrypted with CSEK
		// Deferred: no canonical with that meaning (operational / reliability, or no equivalent).
		// CKV_GCP_46/49, CKV_AWS_126/273, CKV_K8S_43 and Trivy AWS-0133 got entries in batch 3.
		"CKV_AWS_260":   "EC2_SG_OPEN_HTTP", // 0.0.0.0/0 to port 80 (W6-ENGINE, r4 #11)
		"CKV_AWS_118":   "",                 // RDS enhanced monitoring (operational)
		"CKV2_AZURE_38": "",                 // storage soft-delete
	}
	for id, want := range checkov {
		wantCanonical(t, c, "checkov", id, want)
	}
	trivy := map[string]string{
		"AWS-0099": "EC2_SG_NO_DESCRIPTION",        // missing description for security group
		"AWS-0124": "EC2_SG_NO_DESCRIPTION",        // missing description for security group rule
		"AWS-0104": "EC2_SG_OPEN_EGRESS",           // unrestricted egress to any IP address
		"AWS-0177": "RDS_NO_DELETION_PROTECTION",   // RDS Deletion Protection Disabled
		"AWS-0176": "RDS_NO_IAM_AUTH",              // RDS IAM Database Authentication Disabled
		"AWS-0077": "RDS_BACKUP_RETENTION_LOW",     // backup retention longer than default 1 day
		"AWS-0132": "S3_NO_CMK",                    // S3 encryption should use Customer Managed Keys
		"AWS-0143": "IAM_POLICY_ON_USER",           // IAM policies should not be granted directly to users
		"AWS-0066": "LAMBDA_NO_TRACING",            // Lambda functions should have X-Ray tracing enabled
		"KSV-0003": "K8S_CAPABILITIES_NOT_DROPPED", // some containers do not drop all
		"KSV-0004": "K8S_CAPABILITIES_NOT_DROPPED", // some containers do not drop any
		"KSV-0106": "K8S_CAPABILITIES_NOT_DROPPED", // capabilities must only include NET_BIND_SERVICE
		"KSV-0014": "K8S_WRITABLE_ROOT_FS",         // root file system is not read-only
		"KSV-0030": "K8S_NO_SECCOMP",               // Runtime/Default Seccomp profile not set
		"KSV-0104": "K8S_NO_SECCOMP",               // Seccomp policies disabled
		"KSV-0118": "K8S_NO_SECURITY_CONTEXT",      // default security context configured
		"AZU-0060": "AZ_STORAGE_NO_CMK",            // storage account customer-managed keys
		"AZU-0057": "AZ_STORAGE_LOGGING_DISABLED",  // storage account logging enabled
		"GCP-0030": "GCP_PROJECT_SSH_KEYS_ALLOWED", // disable project-wide SSH keys
		"GCP-0041": "GCP_SHIELDED_VM_DISABLED",     // Shielded VM VTPM
		"GCP-0045": "GCP_SHIELDED_VM_DISABLED",     // Shielded VM integrity monitoring
		"GCP-0067": "GCP_SHIELDED_VM_DISABLED",     // Shielded VM secure boot
		"GCP-0033": "GCP_DISK_NO_CSEK",             // VM disks encrypted with CSEK
		// Deferred.
		"AZU-0047": "AZ_NSG_UNRESTRICTED_SOURCE", // unrestricted-source ingress (W7-ENGINE, V7 defect 9)
		"AZU-0058": "",                           // geo-redundant replication (reliability)
		"AZU-0061": "",                           // infrastructure (double) encryption
		"GCP-0073": "",                           // default firewall rules
		"KSV-0117": "",                           // binding to privileged ports
		"KSV-0125": "",                           // trusted registries
	}
	for id, want := range trivy {
		wantCanonical(t, c, "trivy", id, want)
	}
	// Kubescape C-0017 "Immutable container filesystem" means the same as KSV-0014 / CKV_K8S_22.
	wantCanonical(t, c, "kubescape", "C-0017", "K8S_WRITABLE_ROOT_FS")
}

// New entries carry no PUBLIC_* weakness: none of them is an internet exposure, so the attack-path
// engine must not read them as one.
func TestScannerAliasBatch2Entries(t *testing.T) {
	c := Default()
	for _, id := range []string{"EC2_SG_NO_DESCRIPTION", "EC2_SG_OPEN_EGRESS", "RDS_NO_DELETION_PROTECTION", "RDS_NO_IAM_AUTH",
		"RDS_BACKUP_RETENTION_LOW", "RDS_LOGGING_DISABLED", "S3_NO_CMK", "IAM_POLICY_ON_USER", "LAMBDA_NO_TRACING",
		"LAMBDA_NOT_IN_VPC", "LAMBDA_NO_CODE_SIGNING", "K8S_CAPABILITIES_NOT_DROPPED", "K8S_WRITABLE_ROOT_FS",
		"K8S_NO_SECCOMP", "K8S_NO_SECURITY_CONTEXT", "AZ_STORAGE_NO_CMK", "AZ_STORAGE_LOGGING_DISABLED",
		"GCP_PROJECT_SSH_KEYS_ALLOWED", "GCP_SHIELDED_VM_DISABLED", "GCP_DISK_NO_CSEK"} {
		e, ok := c.Get(id)
		if !ok {
			t.Errorf("%s missing from catalog.yaml", id)
			continue
		}
		if e.Title == "" || e.Provider == "" || e.Severity == "" || e.ResourceType == "" || len(e.Compliance) == 0 {
			t.Errorf("%s: incomplete entry %+v", id, e)
		}
		for _, w := range e.Weaknesses {
			if w == "PUBLIC_DATA_STORE" || w == "PUBLIC_NETWORK_EXPOSURE" {
				t.Errorf("%s carries %s", id, w)
			}
		}
	}
}

// An alias claimed by two canonicals resolves to whichever the map iteration indexes last; every
// (source, alias) pair, in its normalised Trivy spelling, must belong to exactly one entry.
func TestNoAliasClaimedTwice(t *testing.T) {
	c, err := Parse(catalogYAML)
	if err != nil {
		t.Fatal(err)
	}
	owner := map[string]string{}
	for _, id := range c.IDs() {
		for src, aliases := range c.Entries[id].Aliases {
			for _, a := range aliases {
				key := strings.ToLower(strings.TrimSpace(a))
				if trivySpelled(strings.ToLower(src)) {
					key = strings.ToLower(NormalizeTrivyID(key))
				}
				k := strings.ToLower(src) + "|" + key
				if prev, ok := owner[k]; ok && prev != id {
					t.Errorf("%s alias %s claimed by %s and %s", src, a, prev, id)
				}
				owner[k] = id
			}
		}
	}
}
