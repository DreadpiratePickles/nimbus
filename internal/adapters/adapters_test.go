package adapters

import (
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func parse(t *testing.T, file, source string) []model.Finding {
	t.Helper()
	fs, name, err := ParseFile(filepath.Join("..", "..", "testdata", file), source, Options{})
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if source != "" && name != source {
		t.Fatalf("adapter %s, want %s", name, source)
	}
	return fs
}

func byCanonical(fs []model.Finding) map[string][]model.Finding {
	m := map[string][]model.Finding{}
	for _, f := range fs {
		m[f.CanonicalID] = append(m[f.CanonicalID], f)
	}
	return m
}

func TestProwlerOCSF(t *testing.T) {
	fs := parse(t, "prowler.ocsf.json", "")
	if len(fs) != 13 {
		t.Fatalf("want 13 findings, got %d", len(fs))
	}
	m := byCanonical(fs)
	pub := m["S3_PUBLIC_BUCKET"]
	if len(pub) != 1 {
		t.Fatalf("S3_PUBLIC_BUCKET mapped %d", len(pub))
	}
	f := pub[0]
	if f.Severity != model.High || f.Status != model.Fail || f.Provider != "aws" || f.Account != "123456789012" || f.Region != "us-east-1" {
		t.Errorf("bad core fields: %+v", f)
	}
	if !f.HasWeakness("PUBLIC_DATA_STORE") {
		t.Errorf("weakness missing: %v", f.Weaknesses)
	}
	if got := f.Compliance["cis_aws"]; len(got) == 0 || got[0] != "2.1.4" {
		t.Errorf("cis mapping: %v", f.Compliance)
	}
	if len(f.Compliance["nist_800_53"]) < 2 {
		t.Errorf("nist should merge tool + catalog controls: %v", f.Compliance["nist_800_53"])
	}
	if f.ID == "" || f.ID != f.Fingerprint() {
		t.Errorf("fingerprint not set")
	}
	imds := m["EC2_IMDSV1"][0]
	if len(imds.Resource.Related) < 2 {
		t.Errorf("expected related sg + role hints, got %v", imds.Resource.Related)
	}
	if m["KMS_ROTATION_DISABLED"][0].Status != model.Pass {
		t.Errorf("PASS status lost")
	}
}

func TestCheckov(t *testing.T) {
	fs := parse(t, "checkov.json", "")
	m := byCanonical(fs)
	if len(fs) != 5 {
		t.Fatalf("want 5, got %d", len(fs))
	}
	f := m["S3_PUBLIC_BUCKET"][0]
	if f.File != "infra/s3.tf" || f.LineStart != 14 || f.LineEnd != 20 || f.Provider != "aws" || f.Status != model.Fail {
		t.Errorf("iac location wrong: %+v", f)
	}
	if m["SECRET_HARDCODED"][0].Severity != model.Critical {
		t.Errorf("secret severity")
	}
	if m["S3_NO_VERSIONING"][0].Status != model.Pass {
		t.Errorf("passed check should be PASS")
	}
}

func TestTrivy(t *testing.T) {
	fs := parse(t, "trivy.json", "")
	m := byCanonical(fs)
	if len(m["K8S_PRIVILEGED_CONTAINER"]) != 1 || len(m["K8S_HOST_NETWORK"]) != 1 {
		t.Fatalf("k8s mapping: %v", keys(m))
	}
	if m["K8S_PRIVILEGED_CONTAINER"][0].Provider != "kubernetes" || m["K8S_PRIVILEGED_CONTAINER"][0].LineStart != 22 {
		t.Errorf("provider/line: %+v", m["K8S_PRIVILEGED_CONTAINER"][0])
	}
	cve := m["CVE_VULNERABILITY"]
	if len(cve) != 1 || cve[0].Severity != model.Critical || !cve[0].HasWeakness("UNPATCHED") {
		t.Errorf("cve: %+v", cve)
	}
}

func TestSteampipe(t *testing.T) {
	fs := parse(t, "steampipe.json", "")
	m := byCanonical(fs)
	if len(fs) != 3 {
		t.Fatalf("want 3, got %d", len(fs))
	}
	pub := m["S3_PUBLIC_BUCKET"]
	if len(pub) != 2 {
		t.Fatalf("expected alarm+ok rows mapped, got %d", len(pub))
	}
	for _, f := range pub {
		if f.Account != "123456789012" || f.Region != "us-east-1" {
			t.Errorf("dimensions not applied: %+v", f)
		}
	}
	if m["OKTA_ADMIN_NO_MFA"][0].Provider != "okta" || m["OKTA_ADMIN_NO_MFA"][0].Account != "acme.okta.com" {
		t.Errorf("okta: %+v", m["OKTA_ADMIN_NO_MFA"][0])
	}
}

func TestScoutSuite(t *testing.T) {
	fs := parse(t, "scoutsuite_results_azure.js", "")
	m := byCanonical(fs)
	pub := m["AZ_STORAGE_PUBLIC_BLOB"]
	if len(pub) != 2 {
		t.Fatalf("want 2 flagged items, got %d (%v)", len(pub), keys(m))
	}
	found := false
	for _, f := range pub {
		if f.Resource.Name == "acmeprodfiles" && f.Resource.ID == "/subscriptions/sub-0000/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/acmeprodfiles" {
			found = true
		}
		if f.Provider != "azure" || f.Status != model.Fail || f.Severity != model.Critical {
			t.Errorf("fields: %+v", f)
		}
		if f.Compliance["cis_azure"][0] != "3.7" {
			t.Errorf("compliance: %v", f.Compliance)
		}
	}
	if !found {
		t.Errorf("resource not resolved from service tree")
	}
	if len(m["AZ_STORAGE_HTTP_ALLOWED"]) != 1 || m["AZ_STORAGE_HTTP_ALLOWED"][0].Status != model.Pass {
		t.Errorf("empty items should yield PASS")
	}
}

func TestNativeAndOverrides(t *testing.T) {
	fs := parse(t, "native.findings.json", "native")
	if fs[0].CanonicalID != "OKTA_ADMIN_NO_MFA" || fs[0].ID == "" {
		t.Errorf("native: %+v", fs[0])
	}
	fs2, _, _ := ParseFile(filepath.Join("..", "..", "testdata", "checkov.json"), "", Options{Account: "iac-repo"})
	if fs2[0].Tags["account_label"] != "iac-repo" {
		t.Errorf("account label override missing")
	}
}

func TestDetectUnknown(t *testing.T) {
	if _, ok := Detect("x.txt", []byte("hello")); ok {
		t.Errorf("should not detect")
	}
}

func keys(m map[string][]model.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
