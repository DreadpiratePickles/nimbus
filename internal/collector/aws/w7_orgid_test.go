package aws

import (
	"errors"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// W7-ENGINE item 4 (r5 #15): the account's organisation id is collected
// (organizations:DescribeOrganization, callable from member accounts), falling back to the
// organisation in the SCP chain's customer policy ARNs; a denied read is a coverage row and the
// id stays unknown. attackpath evaluates aws:PrincipalOrgID trust conditions against it.
func TestCollectOrganizationID(t *testing.T) {
	acctNode := func(t *testing.T, f *fakeAWS) (map[string]any, []error) {
		res, g := collect(t, f)
		an, ok := g.Node(core.AccountNodeID("aws", acct))
		if !ok {
			t.Fatal("no account node")
		}
		return an.Attributes, res.Errors
	}
	t.Run("described", func(t *testing.T) {
		f := fixture()
		f.org = &fakeOrg{id: "o-abc123def4", parents: map[string][]OrgParent{acct: {{ID: "r-ab12", Type: "ROOT"}}}}
		a, _ := acctNode(t, f)
		if a["organization_id"] != "o-abc123def4" || a["organization_id_status"] != "collected" || a["organization_id_source"] != "organizations:DescribeOrganization" {
			t.Errorf("account attrs %v", a)
		}
	})
	t.Run("fallback to SCP policy ARN", func(t *testing.T) {
		f := fixture()
		f.org = &fakeOrg{
			fail:     map[string]error{"DescribeOrganization": apiErr("AccessDeniedException")},
			parents:  map[string][]OrgParent{acct: {{ID: "r-ab12", Type: "ROOT"}}},
			attached: map[string][]OrgPolicy{acct: {{ID: "p-noread", Name: "deny-pii-read", ARN: "arn:aws:organizations::999999999999:policy/o-fallback01/service_control_policy/p-noread"}}},
			content:  map[string]string{"p-noread": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}`},
		}
		a, _ := acctNode(t, f)
		if a["organization_id"] != "o-fallback01" || a["organization_id_status"] != "collected" || a["organization_id_source"] != "scp-policy-arn" {
			t.Errorf("account attrs %v", a)
		}
	})
	t.Run("denied", func(t *testing.T) {
		f := fixture()
		f.org = &fakeOrg{fail: map[string]error{"DescribeOrganization": apiErr("AccessDeniedException"), "ListParents": apiErr("AccessDeniedException")}}
		a, errs := acctNode(t, f)
		if _, ok := a["organization_id"]; ok || a["organization_id_status"] != "denied" {
			t.Errorf("account attrs %v, want status denied and no id", a)
		}
		found := false
		for _, err := range errs {
			var ce *core.CollectError
			if errors.As(err, &ce) && strings.Contains(ce.API, "organizations:DescribeOrganization") && ce.Reason == core.ReasonAccessDenied {
				found = true
			}
		}
		if !found {
			t.Errorf("no access_denied coverage row for organizations:DescribeOrganization: %v", errs)
		}
	})
	t.Run("not in an organisation", func(t *testing.T) {
		f := fixture()
		f.org = nil
		a, _ := acctNode(t, f)
		if _, ok := a["organization_id"]; ok || a["organization_id_status"] != "not_in_org" {
			t.Errorf("account attrs %v", a)
		}
	})
}
