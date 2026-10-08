package compliance

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestReportAndDerivation(t *testing.T) {
	fs := []model.Finding{
		{ID: "a", Status: model.Fail, Severity: model.High, CanonicalID: "S3_PUBLIC_BUCKET", Resource: model.Resource{Name: "pii"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}, Compliance: map[string][]string{"cis_aws": {"2.1.4"}}},
		{ID: "b", Status: model.Pass, Severity: model.High, CanonicalID: "IAM_ROOT_NO_MFA", Resource: model.Resource{Name: "root"}, Weaknesses: []string{"NO_MFA"}, Compliance: map[string][]string{"cis_aws": {"1.5"}}},
	}
	rep, err := Build("cis_aws", fs, "acct 123")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failing != 1 || rep.Passing != 1 || rep.ScorePercent != 50 {
		t.Errorf("score: %+v", rep)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "2.1.4") || !strings.Contains(md, "FAIL") || !strings.Contains(md, "50.0%") {
		t.Errorf("markdown: %s", md)
	}
	soc, _ := Build("soc2", fs, "")
	var cc66 *ControlStatus
	for i := range soc.Controls {
		if soc.Controls[i].ID == "CC6.6" {
			cc66 = &soc.Controls[i]
		}
	}
	if cc66 == nil || cc66.Status != "FAIL" {
		t.Errorf("soc2 derivation failed: %+v", soc.Controls)
	}
	iso, _ := Build("iso_27001", fs, "")
	if iso.Framework.Version != "2022" || iso.Failing == 0 {
		t.Errorf("iso: %+v", iso)
	}
	custom := []byte("name: Acme Baseline\nversion: '1'\ncontrols:\n  ACME-1:\n    title: No public data\n    weaknesses: [PUBLIC_DATA_STORE]\n  ACME-2:\n    title: Root MFA\n    canonical_ids: [IAM_ROOT_NO_MFA]\n")
	fw, err := LoadCustom(custom, fs)
	if err != nil {
		t.Fatal(err)
	}
	if fw.Key != "acme_baseline" || len(fs[0].Compliance["acme_baseline"]) != 1 {
		t.Errorf("custom: %+v %v", fw, fs[0].Compliance)
	}
	if ResolveKey("cis", "kubernetes") != "cis_k8s" || ResolveKey("PCI-DSS", "") != "pci_dss" || ResolveKey("nist", "") != "nist_800_53" {
		t.Errorf("resolve")
	}
	if !controlLess("1.5", "1.10") || controlLess("AC-6(1)", "AC-6") {
		t.Errorf("ordering")
	}
}
