package catalog

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Integration pass 3 item #10 (competitive delta 2026-10-09 shortfall #10, rows RP6/VS1/IC1):
// scanner check ids must resolve to the canonical id with the same meaning whatever spelling the
// scanner version emits, and an alias must not map a check onto a canonical with another meaning.

func wantCanonical(t *testing.T, c *Catalog, source, id, want string) {
	t.Helper()
	e, ok := c.Lookup(source, id)
	switch {
	case want == "" && ok:
		t.Errorf("%s %s → %s, want unmapped", source, id, e.ID)
	case want != "" && !ok:
		t.Errorf("%s %s unmapped, want %s", source, id, want)
	case want != "" && e.ID != want:
		t.Errorf("%s %s → %s, want %s", source, id, e.ID, want)
	}
}

// Trivy emitted AVDID "AVD-AWS-0028" (and ID "KSV017") up to ~0.5x; Trivy 0.6x+ emits only
// ID "AWS-0028" / "KSV-0111". All spellings resolve to one alias.
func TestTrivyIDSpellingsResolveToOneAlias(t *testing.T) {
	c := Default()
	for _, id := range []string{"AVD-AWS-0028", "AWS-0028", "aws-0028", "AWS0028", "avd-aws-28"} {
		wantCanonical(t, c, "trivy", id, "EC2_IMDSV1")
	}
	for _, id := range []string{"KSV017", "KSV-0017", "KSV0017", "AVD-KSV-0017", "ksv-17"} {
		wantCanonical(t, c, "trivy", id, "K8S_PRIVILEGED_CONTAINER")
	}
	for _, id := range []string{"KSV-0111", "KSV111", "KSV0111", "AVD-KSV-0111"} {
		wantCanonical(t, c, "trivy", id, "K8S_CLUSTER_ADMIN_BINDING")
	}
	// trivy-operator reports reuse Trivy's check ids (KSV001 in the CRDs, KSV-0001 in newer ones).
	for _, id := range []string{"KSV001", "KSV-0001"} {
		wantCanonical(t, c, "trivy-operator", id, "K8S_PRIVILEGE_ESCALATION")
	}
	// Normalisation must not swallow CVE / secret rule ids.
	wantCanonical(t, c, "trivy", "CVE-2024-6387", "CVE_VULNERABILITY")
	wantCanonical(t, c, "trivy", "aws-access-key-id", "SECRET_HARDCODED")
	wantCanonical(t, c, "trivy", "AWS-9999", "")
	if got := NormalizeTrivyID("KSV111"); got != "AVD-KSV-0111" {
		t.Errorf("NormalizeTrivyID(KSV111) = %q, want AVD-KSV-0111", got)
	}
	if got := NormalizeTrivyID("CVE-2024-6387"); got != "CVE-2024-6387" {
		t.Errorf("NormalizeTrivyID must leave non-check ids alone, got %q", got)
	}
}

// Every Trivy 0.75.0 check that fires on a lab weakness in lab/golden/trivy (titles from the
// golden JSON / the Trivy checks bundle), plus the meaning fixes for aliases that the id
// normalisation would otherwise activate on the wrong canonical.
func TestTrivyAliasMeanings(t *testing.T) {
	c := Default()
	for id, want := range map[string]string{
		"AWS-0087": "S3_PUBLIC_BUCKET",          // S3 Access block should block public policy
		"AWS-0093": "S3_PUBLIC_BUCKET",          // ... restrict public bucket
		"AWS-0107": "EC2_SG_OPEN_SSH",           // unrestricted ingress to SSH or RDP
		"AWS-0028": "EC2_IMDSV1",                // IMDS session tokens
		"AWS-0180": "RDS_PUBLIC",                // RDS Publicly Accessible
		"KSV-0111": "K8S_CLUSTER_ADMIN_BINDING", // User with admin access (cluster-admin binding)
		"GCP-0071": "GCP_FIREWALL_OPEN_SSH",     // SSH Access Is Not Restricted
		"GCP-0070": "GCP_FIREWALL_OPEN_RDP",     // RDP Access Is Not Restricted
		"GCP-0031": "GCP_INSTANCE_PUBLIC_IP",    // Instances should not have public IP addresses
		"AZU-0007": "AZ_STORAGE_PUBLIC_BLOB",    // blob containers public access
		"AZU-0048": "AZ_NSG_OPEN_RDP",           // RDP from any IP
		"AZU-0050": "AZ_NSG_OPEN_SSH",           // SSH from any IP
		"AZU-0022": "AZ_SQL_PUBLIC",             // databases not publicly accessible
		"AZU-0029": "AZ_SQL_PUBLIC",             // database firewalls do not permit public access
		// Removed: the alias named a check with another meaning.
		"AZU-0047": "AZ_NSG_UNRESTRICTED_SOURCE", // unrestricted-source ingress, not SSH (W7-ENGINE)
		"AZU-0025": "",                           // SQL auditing retention
		"AZU-0046": "",                           // security center contacts
		"AZU-0040": "",                           // AKS logging, not RBAC
		"GCP-0018": "",                           // Postgres error logging, not public SQL
		"GCP-0053": "",                           // GKE public control plane, not legacy ABAC
		"GCP-0005": "",                           // service-account user at folder level, not a primitive role
		"GCP-0011": "",                           // service-account user at project level, not a primitive role
		"GCP-0004": "",                           // role on a default SA, not a primitive role
		"OCI-0001": "",                           // compute public IP pool, not a public bucket
		"AWS-0342": "",                           // IAM PassRole filtering, not *:*
		"AWS-0345": "",                           // unrestricted S3 IAM policy, not *:*
		"KSV043":   "",                           // impersonation of privileged groups, not secrets in env
		"KSV047":   "",                           // node proxy escalation, not a cluster-admin binding
	} {
		wantCanonical(t, c, "trivy", id, want)
	}
}

// Checkov 3.3.26 check meanings verified from check_name in lab/golden/checkov/3.3.26/*.json.
func TestCheckovAliasMeanings(t *testing.T) {
	c := Default()
	for id, want := range map[string]string{
		"CKV_AWS_70":    "S3_PUBLIC_BUCKET",       // S3 bucket does not allow an action with any Principal
		"CKV_AWS_274":   "IAM_ADMIN_POLICY",       // AdministratorAccess attached
		"CKV_AWS_258":   "LAMBDA_PUBLIC",          // Lambda function URL AuthType NONE
		"CKV_AWS_8":     "EBS_UNENCRYPTED",        // launch config / instance EBS encrypted
		"CKV_AZURE_34":  "AZ_STORAGE_PUBLIC_BLOB", // blob container public access level
		"CKV2_AZURE_47": "AZ_STORAGE_PUBLIC_BLOB", // storage account without blob anonymous access
		"CKV_GCP_117":   "GCP_IAM_PRIMITIVE_ROLE", // basic roles at project level
		"CKV_GCP_40":    "GCP_INSTANCE_PUBLIC_IP", // Compute instances do not have public IPs
		// Review verdicts (alias named another meaning → removed, no canonical with that meaning):
		// CKV_GCP_49 / CKV_GCP_41 (SA impersonation roles, not primitive roles): GCP_SA_IMPERSONATION_ROLE (batch 3).
		"CKV_GCP_49":  "GCP_SA_IMPERSONATION_ROLE",
		"CKV_GCP_41":  "GCP_SA_IMPERSONATION_ROLE",
		"CKV_AWS_260": "EC2_SG_OPEN_HTTP", // 0.0.0.0/0 to port 80 (W6-ENGINE)
		"CKV_K8S_21":  "",                 // default namespace in use, not SA token automount
	} {
		wantCanonical(t, c, "checkov", id, want)
	}
}

func TestGCPInstancePublicIPEntry(t *testing.T) {
	c := Default()
	e, ok := c.Get("GCP_INSTANCE_PUBLIC_IP")
	if !ok {
		t.Fatal("GCP_INSTANCE_PUBLIC_IP missing from catalog.yaml")
	}
	if e.Provider != model.ProviderGCP || e.ResourceType != "gcp_compute_instance" || e.Title == "" || e.Severity == "" {
		t.Errorf("entry: %+v", e)
	}
	if len(e.Weaknesses) != 1 || e.Weaknesses[0] != "PUBLIC_NETWORK_EXPOSURE" {
		t.Errorf("weaknesses %v, want [PUBLIC_NETWORK_EXPOSURE] (as EC2_PUBLIC_IP)", e.Weaknesses)
	}
	wantCanonical(t, c, "prowler", "compute_instance_public_ip", "GCP_INSTANCE_PUBLIC_IP")
}

// Kubescape control ids (C-00xx) map only where the control means the same as an existing
// canonical; others stay unmapped.
func TestKubescapeAliases(t *testing.T) {
	c := Default()
	for id, want := range map[string]string{
		"C-0057": "K8S_PRIVILEGED_CONTAINER",  // Privileged container
		"C-0016": "K8S_PRIVILEGE_ESCALATION",  // Allow privilege escalation
		"C-0034": "K8S_DEFAULT_SA_TOKEN",      // Automatic mapping of service account
		"C-0035": "K8S_CLUSTER_ADMIN_BINDING", // Administrative Roles
		"C-0185": "K8S_CLUSTER_ADMIN_BINDING", // cluster-admin role only used where required
		"C-0041": "K8S_HOST_NETWORK",          // HostNetwork access
		"C-0038": "K8S_HOST_NETWORK",          // Host PID/IPC privileges
		"C-0048": "K8S_HOST_PATH",             // HostPath mount
		"C-0013": "K8S_RUN_AS_ROOT",           // Non-root containers
		"C-0009": "K8S_NO_RESOURCE_LIMITS",    // Resource limits
		"C-0270": "K8S_NO_RESOURCE_LIMITS",    // Ensure CPU limits are set
		"C-0271": "K8S_NO_RESOURCE_LIMITS",    // Ensure memory limits are set
		"C-0260": "K8S_NO_NETWORK_POLICY",     // Missing network policy
	} {
		wantCanonical(t, c, "kubescape", id, want)
	}
}

// kube-bench numbers checks per benchmark ("5.1.1" in cis-1.8 is not "5.1.1" in eks-1.2.0), so
// aliases carry the benchmark ("cis-1.8:5.1.1") and Enrich builds the key from the finding's
// benchmark tag; a bare number never maps.
func TestKubeBenchAliasesNeedTheBenchmark(t *testing.T) {
	c := Default()
	enrich := func(bench, num string) string {
		f := model.Finding{Source: "kube-bench", CheckID: num, Status: model.Fail, Severity: model.Medium,
			Tags: map[string]string{"benchmark": bench}}
		c.Enrich(&f)
		return f.CanonicalID
	}
	for num, want := range map[string]string{
		"5.1.1":  "K8S_CLUSTER_ADMIN_BINDING", // cluster-admin role only used where required
		"5.1.6":  "K8S_DEFAULT_SA_TOKEN",      // SA tokens only mounted where necessary
		"5.2.2":  "K8S_PRIVILEGED_CONTAINER",  // privileged containers
		"5.2.5":  "K8S_HOST_NETWORK",          // hostNetwork
		"5.2.6":  "K8S_PRIVILEGE_ESCALATION",  // allowPrivilegeEscalation
		"5.2.7":  "K8S_RUN_AS_ROOT",           // root containers
		"5.3.2":  "K8S_NO_NETWORK_POLICY",     // namespaces have network policies
		"5.4.1":  "K8S_SECRETS_IN_ENV",        // secrets as files over env
		"1.2.16": "",                          // --profiling: no canonical
	} {
		if got := enrich("cis-1.8", num); got != want {
			t.Errorf("kube-bench cis-1.8 %s → %q, want %q", num, got, want)
		}
	}
	if got := enrich("eks-1.2.0", "5.1.1"); got != "" {
		t.Errorf("eks-1.2.0 5.1.1 must not reuse the cis-1.8 mapping, got %q", got)
	}
	wantCanonical(t, c, "kube-bench", "5.1.1", "")
	wantCanonical(t, c, "kube-bench", "cis-1.8:5.1.1", "K8S_CLUSTER_ADMIN_BINDING")
}

// kube-bench states the exact CIS control of its benchmark; the catalog entry's cis_k8s list
// (written against another benchmark revision) must not be merged into it: cis-1.8 5.2.6 is
// allowPrivilegeEscalation, while K8S_PRIVILEGE_ESCALATION lists 5.2.5 (hostNetwork in cis-1.8).
func TestKubeBenchKeepsItsOwnCISControl(t *testing.T) {
	f := model.Finding{Source: "kube-bench", CheckID: "5.2.6", Status: model.Fail, Severity: model.Medium,
		Tags: map[string]string{"benchmark": "cis-1.8"}}
	f.AddCompliance("cis_k8s", "5.2.6")
	Default().Enrich(&f)
	if f.CanonicalID != "K8S_PRIVILEGE_ESCALATION" {
		t.Fatalf("canonical %q", f.CanonicalID)
	}
	if got := f.Compliance["cis_k8s"]; len(got) != 1 || got[0] != "5.2.6" {
		t.Errorf("cis_k8s %v, want [5.2.6]", got)
	}
	if len(f.Compliance["nist_800_53"]) == 0 {
		t.Errorf("other frameworks still come from the catalog: %v", f.Compliance)
	}
}
