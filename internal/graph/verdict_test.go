package graph

import (
	"strings"
	"testing"
)

// verdictGraph: a VM behind an NSG; the NSG has the internet edge (a scanner finding on the rule),
// the VM only the NSG -allows_traffic_to-> VM edge (the jump-01 shape, C11).
func verdictGraph(nsgEdge, vmAttrs map[string]any) *Graph {
	g := New()
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet", Name: "internet"})
	g.AddNode(&Node{ID: "nsg-1", Type: "azure_network_security_group", Class: ClassNetwork, Name: "jump-nsg"})
	g.AddNode(&Node{ID: "/subscriptions/s/vm/jump-01", Type: "azure_virtual_machine", Name: "jump-01", Attributes: vmAttrs})
	g.AddEdge(InternetNodeID, "nsg-1", EdgeExposes, nsgEdge)
	g.AddEdge("nsg-1", "/subscriptions/s/vm/jump-01", EdgeAllowsTrafficTo, map[string]any{})
	return g
}

// C11: no verdict on the VM node or its edge: the control's verdict decides, never "".
func TestVerdictFallsBackToControlVerdict(t *testing.T) {
	g := verdictGraph(map[string]any{AttrReachability: "unknown", AttrReachUnknown: "routes are not modelled for azure in v1 (NSG/firewall only)"}, nil)
	v := g.Verdict("/subscriptions/s/vm/jump-01")
	if v.Status != VerdictUnknown || v.Reason == "" || !strings.Contains(v.Label, "routes are not modelled") {
		t.Fatalf("verdict %+v, want unknown with the NSG's reason", v)
	}
}

// On a graph the reachability pass ran on, a route nobody evaluated (no verdict on edge, node
// or control) is unknown with a reason.
func TestVerdictUnannotatedRouteIsUnknown(t *testing.T) {
	g := verdictGraph(map[string]any{}, nil)
	g.AddNode(&Node{ID: "i-9", Type: "aws_instance", Name: "other"})
	g.AddEdge(InternetNodeID, "i-9", EdgeExposes, map[string]any{AttrReachability: "reachable"})
	v := g.Verdict("/subscriptions/s/vm/jump-01")
	if v.Status != VerdictUnknown || v.Reason == "" || v.Label == "" {
		t.Fatalf("verdict %+v, want unknown with a reason", v)
	}
}

// W5 (brief item 5 / C11): an internet route with no exposure data anywhere — even on a graph
// the reachability pass never ran on — is unknown with a reason, never "". Width comes from
// the route's exposure label.
func TestVerdictNoExposureDataIsUnknown(t *testing.T) {
	g := verdictGraph(map[string]any{"exposure": "wide"}, nil)
	v := g.Verdict("/subscriptions/s/vm/jump-01")
	if v.Status != VerdictUnknown || v.Reason == "" || v.Routes != 1 || v.Width != "wide" {
		t.Fatalf("verdict %+v, want unknown (wide) with a reason on a graph without REACH data", v)
	}
	// A node with no internet route at all stays "" (not exposed).
	g.AddNode(&Node{ID: "db", Type: "aws_db_instance", Name: "db"})
	if v := g.Verdict("db"); v.Status != "" || v.Routes != 0 {
		t.Fatalf("no route: %+v", v)
	}
}

// The network control's own node-level verdict counts when its internet edge carries none
// (the verify-5 jump-shape probe: REACH on the NSG node).
func TestVerdictUsesControlNodeVerdict(t *testing.T) {
	g := verdictGraph(nil, nil)
	nsg, _ := g.Node("nsg-1")
	nsg.Attributes = map[string]any{AttrReachability: "unknown", AttrReachUnknown: "nsg rules not collected"}
	v := g.Verdict("/subscriptions/s/vm/jump-01")
	if v.Status != VerdictUnknown || !strings.Contains(v.Reason, "nsg rules not collected") {
		t.Fatalf("verdict %+v, want unknown with the NSG node's reason", v)
	}
}

// A control whose own internet route is blocked cuts the node off (already true) ...
func TestVerdictControlBlocked(t *testing.T) {
	g := verdictGraph(map[string]any{AttrReachability: "blocked", AttrReachBlocker: "NACL acl-1 rule 90 denies 22/tcp"},
		map[string]any{AttrReachability: "reachable", AttrReachWidth: "wide"})
	if v := g.Verdict("/subscriptions/s/vm/jump-01"); v.Status != VerdictBlocked {
		t.Fatalf("verdict %+v, want blocked", v)
	}
}

// ... and a control whose every internet route is private / trusted makes the node private, not
// the node's own "reachable (wide)" (C11, verdict.go fallback to the node verdict).
func TestVerdictControlPrivateNotWide(t *testing.T) {
	g := verdictGraph(map[string]any{"exposure": "private", "exposure_reason": "every source (10.0.0.0/8) is a private or non-routable range"},
		map[string]any{AttrReachability: "reachable", AttrReachWidth: "wide"})
	v := g.Verdict("/subscriptions/s/vm/jump-01")
	if v.Status != VerdictPrivate || !strings.HasPrefix(v.Label, "private (suppressed: every source") {
		t.Fatalf("verdict %+v, want private (suppressed: …)", v)
	}
}

// Delta r3 #14: a suppressed private bucket (Principal * conditioned on the org) reads
// "private (suppressed: <reason>)", not "reachable (wide)".
func TestVerdictSuppressedBucketIsPrivate(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet"})
	g.AddNode(&Node{ID: "arn:aws:s3:::shared-reports", Type: "aws_s3_bucket", Name: "shared-reports",
		Attributes: map[string]any{AttrReachability: "reachable", AttrReachWidth: "wide", "exposure": "private"}})
	g.AddEdge(InternetNodeID, "arn:aws:s3:::shared-reports", EdgeExposes, map[string]any{
		AttrReachability: "reachable", AttrReachWidth: "wide", "exposure": "private",
		"exposure_reason": "bucket policy Principal * is conditioned on aws:PrincipalOrgID"})
	v := g.Verdict("arn:aws:s3:::shared-reports")
	if v.Status != VerdictPrivate || v.Label != "private (suppressed: bucket policy Principal * is conditioned on aws:PrincipalOrgID)" {
		t.Fatalf("verdict %+v", v)
	}
	if v.Blocked() {
		t.Fatal("a suppressed exposure is not a network block")
	}
}

// A trusted-only exposure reads trusted (suppressed: …).
func TestVerdictSuppressedTrusted(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet"})
	g.AddNode(&Node{ID: "i-1", Type: "aws_instance", Name: "corp-tools", Attributes: map[string]any{AttrReachability: "reachable", AttrReachWidth: "narrow"}})
	g.AddEdge(InternetNodeID, "i-1", EdgeExposes, map[string]any{"exposure": "trusted", "exposure_reason": "every source (203.0.113.0/24) is inside trusted_cidrs"})
	v := g.Verdict("i-1")
	if v.Status != VerdictTrusted || v.Label != "trusted (suppressed: every source (203.0.113.0/24) is inside trusted_cidrs)" {
		t.Fatalf("verdict %+v", v)
	}
}

// A load-balancer target (no internet route of its own) still takes its node verdict.
func TestVerdictNodeOnlyStillUsed(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "i-2", Type: "aws_instance", Name: "app", Attributes: map[string]any{AttrReachability: "reachable", AttrReachWidth: "wide"}})
	if v := g.Verdict("i-2"); v.Status != VerdictReachable {
		t.Fatalf("verdict %+v", v)
	}
}

// Delta r3 #14: one short reason; no clause repeated, the node is named, not its full id.
func TestVerdictReasonShortNoRepeatedClause(t *testing.T) {
	id := "arn:aws:rds:us-east-1:111111111111:db:orders"
	g := New()
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet"})
	g.AddNode(&Node{ID: id, Type: "aws_db_instance", Name: "orders"})
	g.AddEdge(InternetNodeID, id, EdgeExposes, map[string]any{AttrReachability: "unknown",
		AttrReachUnknown: "security group rules for " + id + " not collected; subnet of " + id + " not known: route table and network ACL not evaluated; security group rules for " + id + " not collected"})
	v := g.Verdict(id)
	if v.Status != VerdictUnknown {
		t.Fatalf("verdict %+v", v)
	}
	if strings.Contains(v.Reason, id) {
		t.Errorf("reason names the full id: %q", v.Reason)
	}
	if c := repeatedClause(v.Reason); c != "" {
		t.Errorf("reason repeats %q: %q", c, v.Reason)
	}
	if c := repeatedClause(v.Label); c != "" {
		t.Errorf("label repeats %q: %q", c, v.Label)
	}
}

// repeatedClause returns a clause ("; "- or ": "-separated) that occurs twice in s.
func repeatedClause(s string) string {
	seen := map[string]bool{}
	for _, part := range strings.Split(s, "; ") {
		for _, c := range strings.Split(part, ": ") {
			c = strings.Trim(strings.TrimSpace(c), "()")
			if len(c) < 12 {
				continue
			}
			if seen[c] {
				return c
			}
			seen[c] = true
		}
	}
	return ""
}

// Every verdict on the lab: never an empty status for a node with an internet route, never a
// repeated clause.
func TestLabVerdictsHaveReasons(t *testing.T) {
	g := labEstateGraph(t)
	for _, n := range g.Nodes() {
		v := g.Verdict(n.ID)
		if v.Routes > 0 && v.Status == "" {
			t.Errorf("%s: %d route(s) but an empty verdict", n.Name, v.Routes)
		}
		if v.Status != "" && v.Status != VerdictReachable && v.Reason == "" {
			t.Errorf("%s: %s verdict without a reason", n.Name, v.Status)
		}
		if c := repeatedClause(v.Label); c != "" {
			t.Errorf("%s: label repeats %q: %q", n.Name, c, v.Label)
		}
	}
}

// Delta r3 #14 / C11, on a graph exposure annotation never ran on (the raw ingest graph the
// verifier read): an org-conditioned Principal * bucket reads "private (suppressed: …)" from its
// own resource policy, not "internet reachable (wide)".
func TestVerdictOrgConditionedBucketPrivateWithoutAnnotation(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: InternetNodeID, Type: "internet", Name: "internet"})
	g.AddNode(&Node{ID: "arn:aws:s3:::shared", Type: "aws_s3_bucket", Name: "shared", Attributes: map[string]any{
		AttrReachability: "reachable", AttrReachWidth: "wide",
		"bucket_policy": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::shared/*",
			"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-abc123"}}}}}}})
	g.AddEdge(InternetNodeID, "arn:aws:s3:::shared", EdgeExposes, map[string]any{AttrReachability: "reachable", AttrReachWidth: "wide"})
	v := g.Verdict("arn:aws:s3:::shared")
	if v.Status != VerdictPrivate || !strings.HasPrefix(v.Label, "private (suppressed: ") || !strings.Contains(v.Reason, "PrincipalOrgID") {
		t.Fatalf("verdict %+v, want private (suppressed: org-conditioned …)", v)
	}
}
