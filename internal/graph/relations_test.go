package graph

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func edgeOf(g *Graph, from, to, kind string) *Edge {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return e
		}
	}
	return nil
}

// Track B2 item 1: typed relations in native findings become typed edges whose because comes
// from attr; untyped strings stay attached_to hints; aliases resolve kind and direction.
func TestAttachFindingsTypedRelations(t *testing.T) {
	role := "arn:aws:iam::1:role/export"
	bucket := "arn:aws:s3:::pii"
	ext := "arn:aws:iam::999:root"
	vm := "/subscriptions/s/providers/Microsoft.Compute/virtualMachines/jump"
	nsg := "/subscriptions/s/providers/Microsoft.Network/networkSecurityGroups/jump-nsg"
	repo := "github.com/acme/infra"
	deploy := "arn:aws:iam::1:role/gha-deploy"
	vendor := "arn:aws:iam::1:role/vendor"
	fs := []model.Finding{
		{ID: "f1", Status: model.Pass, Provider: "aws", Account: "1", Resource: model.Resource{ID: role, Type: "aws_iam_role",
			Related:   []string{"arn:aws:ec2:us-east-1:1:instance/i-9"},
			Relations: []model.Relation{{ID: bucket, Kind: "grants_access_to", Attr: map[string]any{"actions": "s3:GetObject", "because": "inline policy export-read allows s3:GetObject on pii/*"}}}}},
		{ID: "f2", Status: model.Fail, Provider: "azure", Account: "s", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"},
			Resource: model.Resource{ID: nsg, Type: "azure_network_security_group", Relations: []model.Relation{{ID: vm, Kind: "allows_traffic_to", Attr: map[string]any{"ports": "3389"}}}}},
		{ID: "f3", Status: model.Fail, Provider: "github", Account: "acme", Weaknesses: []string{"BRANCH_UNPROTECTED"},
			Resource: model.Resource{ID: repo, Type: "github_repository", Relations: []model.Relation{{ID: deploy, Kind: "can_assume", Attr: map[string]any{"via": "GitHub OIDC sub repo:acme/infra:*"}}}}},
		{ID: "f4", Status: model.Fail, Provider: "aws", Account: "1", Weaknesses: []string{"CROSS_ACCOUNT_TRUST"},
			Resource: model.Resource{ID: vendor, Type: "aws_iam_role", Relations: []model.Relation{
				{ID: ext, Kind: "trusts"},
				{ID: "arn:aws:iam::888:role/partner", Kind: "sts_assume_role_allows", Attr: map[string]any{"principal": "arn:aws:iam::888:role/partner"}},
				{ID: "arn:aws:iam::aws:policy/AdministratorAccess", Kind: "policy"},
				{ID: "x-unknown", Kind: "frobnicates"},
			}}},
	}
	g := New()
	g.AttachFindings(fs)

	e := edgeOf(g, role, bucket, EdgeGrantsAccessTo)
	if e == nil {
		t.Fatalf("role -grants_access_to-> bucket missing; out=%+v", g.Out(role))
	}
	if b, _ := e.Attr["because"].(string); !strings.Contains(b, "inline policy export-read") || e.Attr["actions"] != "s3:GetObject" || e.Attr["finding_id"] != "f1" {
		t.Errorf("typed edge attr/because: %+v", e.Attr)
	}
	if edgeOf(g, role, bucket, EdgeAttachedTo) != nil {
		t.Error("a typed relation must not also produce an attached_to hint")
	}
	if h := edgeOf(g, role, "arn:aws:ec2:us-east-1:1:instance/i-9", EdgeAttachedTo); h == nil || h.Attr["hint"] != true {
		t.Error("legacy string related must stay an attached_to hint")
	}
	if e := edgeOf(g, nsg, vm, EdgeAllowsTrafficTo); e == nil || !strings.Contains(e.Attr["because"].(string), "3389") {
		t.Errorf("nsg -allows_traffic_to-> vm with ports in because: %+v", e)
	}
	if edgeOf(g, repo, deploy, EdgeCanAssume) == nil {
		t.Error("repo -can_assume-> deploy role (OIDC trust) missing")
	}
	if edgeOf(g, vendor, ext, EdgeTrusts) == nil || edgeOf(g, ext, vendor, EdgeCanAssume) == nil {
		t.Error("trusts must add vendor -trusts-> external and external -can_assume-> vendor")
	}
	if e := edgeOf(g, "arn:aws:iam::888:role/partner", vendor, EdgeCanAssume); e == nil || !strings.Contains(e.Attr["because"].(string), "888:role/partner") {
		t.Errorf("sts_assume_role_allows is an inbound can_assume: %+v", e)
	}
	if edgeOf(g, vendor, "arn:aws:iam::aws:policy/AdministratorAccess", EdgeHasPolicy) == nil {
		t.Error("policy alias → has_policy")
	}
	if e := edgeOf(g, vendor, "x-unknown", EdgeAttachedTo); e == nil || e.Attr["declared_kind"] != "frobnicates" {
		t.Errorf("unknown kind → attached_to hint keeping declared_kind: %+v", e)
	}
}

func TestRelationEdgeAliases(t *testing.T) {
	cases := []struct {
		kind, want string
		reverse    bool
	}{
		{"attached_to", EdgeAttachedTo, false}, {"runs_as", EdgeRunsAs, false}, {"bound_to", EdgeBoundTo, false},
		{"member_of", EdgeMemberOf, false}, {"trusts", EdgeTrusts, false}, {"policy", EdgeHasPolicy, false},
		{"has_policy", EdgeHasPolicy, false}, {"grants_access_to", EdgeGrantsAccessTo, false}, {"resource", EdgeGrantsAccessTo, false},
		{"runs_on", EdgeRunsOn, false}, {"allows_traffic_to", EdgeAllowsTrafficTo, false}, {"can_assume", EdgeCanAssume, false},
		{"sts_assume_role_allows", EdgeCanAssume, true}, {"exposed_to_internet", EdgeExposes, true}, {"exposes", EdgeExposes, true},
		{"contains", EdgeContains, false}, {"stores_data_in", EdgeStoresDataIn, false}, {"RUNS_AS", EdgeRunsAs, false},
	}
	for _, c := range cases {
		kind, reverse, ok := RelationEdge(c.kind)
		if !ok || kind != c.want || reverse != c.reverse {
			t.Errorf("RelationEdge(%q) = %q,%v,%v want %q,%v", c.kind, kind, reverse, ok, c.want, c.reverse)
		}
	}
	if _, _, ok := RelationEdge("frobnicates"); ok {
		t.Error("unknown kind must not resolve")
	}
}

// Track B2 item 3: ingested exposure carries attributes.exposure_cidrs onto the internet edge
// and the node, so analysis can classify width against trusted_cidrs; exposed_to_internet
// relations become exposes edges too.
func TestAttachFindingsCarriesExposureCIDRs(t *testing.T) {
	inst := "arn:aws:ec2:us-east-1:1:instance/i-2"
	fn := "arn:aws:lambda:us-east-1:1:function:f"
	g := New()
	g.AttachFindings([]model.Finding{
		{ID: "w27", Status: model.Fail, Provider: "aws", Account: "1", Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE"},
			Resource: model.Resource{ID: inst, Type: "aws_instance", Attributes: map[string]any{"exposure_cidrs": []any{"203.0.113.0/24"}}}},
		{ID: "inv", Status: model.Pass, Provider: "aws", Account: "1",
			Resource: model.Resource{ID: fn, Type: "aws_lambda_function", Relations: []model.Relation{{ID: "internet", Kind: "exposed_to_internet", Attr: map[string]any{"via": "function URL AuthType NONE"}}}}},
	})
	e := edgeOf(g, InternetNodeID, inst, EdgeExposes)
	if e == nil {
		t.Fatal("no exposes edge")
	}
	cidrs, _ := e.Attr["exposure_cidrs"].([]string)
	if len(cidrs) != 1 || cidrs[0] != "203.0.113.0/24" {
		t.Errorf("exposure_cidrs on edge: %#v", e.Attr["exposure_cidrs"])
	}
	if e := edgeOf(g, InternetNodeID, fn, EdgeExposes); e == nil || !strings.Contains(e.Attr["because"].(string), "function URL") {
		t.Errorf("exposed_to_internet relation → internet -exposes-> function: %+v", e)
	}
}
