package remediation

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestEveryCatalogTemplateRenders(t *testing.T) {
	cat := catalog.Default()
	n := 0
	for _, id := range cat.IDs() {
		e, _ := cat.Get(id)
		for _, f := range Formats(id) {
			fix, err := Generate(model.Finding{CanonicalID: id, Provider: e.Provider, Account: "123", Region: "us-east-1",
				Resource: model.Resource{ID: "arn:aws:x:::thing/my-res", Name: "my-res", Type: e.ResourceType, Attributes: map[string]any{"vpc_id": "vpc-1", "namespace": "prod"}}}, f)
			if err != nil {
				t.Errorf("%s %s: %v", id, f, err)
				continue
			}
			if fix.Generic || !strings.Contains(fix.Content, "my-res") && !strings.Contains(fix.Content, "my_res") || fix.Apply == "" {
				t.Errorf("%s %s: generic=%v apply=%q", id, f, fix.Generic, fix.Apply)
			}
			n++
		}
	}
	if n < 40 {
		t.Errorf("expected >=40 typed templates, got %d", n)
	}
}

func TestGenericFallbackAndFormats(t *testing.T) {
	fix, err := Generate(model.Finding{CanonicalID: "OKTA_NO_MFA_POLICY", Remediation: "Require MFA in the sign-on policy.", Resource: model.Resource{Name: "default-policy"}}, Terraform)
	if err != nil || !fix.Generic || !strings.Contains(fix.Content, "Require MFA") {
		t.Errorf("generic: %v %+v", err, fix)
	}
	for _, s := range []string{"tf", "cfn", "k8s", "bicep"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if fs := Formats("S3_PUBLIC_BUCKET"); len(fs) != 2 {
		t.Errorf("formats: %v", fs)
	}
	bicep, err := Generate(model.Finding{CanonicalID: "AZ_NSG_OPEN_SSH", Resource: model.Resource{Name: "web-nsg", Attributes: map[string]any{"resource_group": "rg1"}}}, Bicep)
	if err != nil || !strings.Contains(bicep.Content, "destinationPortRange: '22'") || !strings.Contains(bicep.Apply, "rg1") {
		t.Errorf("bicep: %v %s %s", err, bicep.Content, bicep.Apply)
	}
	if slugify("123 my-bucket.name!") != "r_123_my_bucket_name" {
		t.Errorf("slug: %s", slugify("123 my-bucket.name!"))
	}
}
