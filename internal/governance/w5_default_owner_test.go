package governance

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W5-ISSUES item 3 (r3 #5, Microsoft Defender's default owner per subscription): an Issue
// nothing else assigns routes to its account's owner (accounts.<name>.owner, then
// defaults.account_owners), then its provider's (defaults.provider_owners), then defaults.owner.
// W6-POLISH (r4 #5): every defaults.* owner is source "default" (assigned by default, reported
// apart in doctor and `issues metrics`); only accounts.<name>.owner is source "account".
func TestFallbackRoutesToAccountThenProviderThenDefault(t *testing.T) {
	c := &config.Config{Governance: config.Governance{Defaults: config.GovernanceDefaults{
		Owner:          "secops",
		AccountOwners:  map[string]string{"aws/111": "finance", "222": "batch-team"},
		ProviderOwners: map[string]string{"gcp": "gcp-platform"},
	}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(c.Governance, nil)
	cases := []struct {
		s            Subject
		owner, src   string
		whyFragments string
	}{
		{Subject{Provider: "aws", Account: "111", Severity: model.High}, "finance", SourceDefault, "default account owner (defaults.account_owners aws/111)"},
		{Subject{Provider: "aws", Account: "222", Severity: model.High}, "batch-team", SourceDefault, "defaults.account_owners 222"},
		{Subject{Provider: "aws", Account: "111", AccountOwner: "cfg-owner"}, "cfg-owner", SourceAccount, "account owner"},
		{Subject{Provider: "aws", Account: "111", Tags: map[string]string{"owner": "web-team"}}, "web-team", SourceTag, "owner from tag owner"},
		{Subject{Provider: "gcp", Account: "proj"}, "gcp-platform", SourceDefault, "defaults.provider_owners gcp"},
		{Subject{Provider: "okta", Account: "x"}, "secops", SourceDefault, "default owner"},
	}
	for _, c := range cases {
		a := r.Resolve(c.s)
		if a.Owner != c.owner || a.Source != c.src || !strings.Contains(a.Why, c.whyFragments) {
			t.Errorf("%+v: got %s/%s (%s), want %s/%s (%s)", c.s, a.Owner, a.Source, a.Why, c.owner, c.src, c.whyFragments)
		}
	}
}

func TestUnassignedSinkValidated(t *testing.T) {
	c := &config.Config{Governance: config.Governance{Digest: config.DigestConfig{UnassignedSink: "pager"}}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unassigned_sink") {
		t.Fatalf("unknown unassigned_sink must fail validation: %v", err)
	}
	c = &config.Config{Governance: config.Governance{Digest: config.DigestConfig{UnassignedSink: "stdout"}, Defaults: config.GovernanceDefaults{AccountOwners: map[string]string{"aws/1": " "}}}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "account_owners") {
		t.Fatalf("blank account owner must fail validation: %v", err)
	}
}

// W6-POLISH (r4 #5): governance.defaults.min_owner_share is a share in (0, 1]; 0.5 when unset.
func TestMinOwnerShareValidated(t *testing.T) {
	if got := (config.GovernanceDefaults{}).MinOwnerShareOrDefault(); got != 0.5 {
		t.Fatalf("default min_owner_share %v, want 0.5", got)
	}
	for _, v := range []float64{0, -0.1, 1.5} {
		v := v
		c := &config.Config{Governance: config.Governance{Defaults: config.GovernanceDefaults{MinOwnerShare: &v}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "min_owner_share") {
			t.Errorf("min_owner_share %v must fail validation: %v", v, err)
		}
	}
	ok := 0.6
	c := &config.Config{Governance: config.Governance{Defaults: config.GovernanceDefaults{MinOwnerShare: &ok}}}
	if err := c.Validate(); err != nil {
		t.Errorf("min_owner_share 0.6: %v", err)
	}
}
