package graph

import (
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func labFinding(id, typ string, attrs map[string]any, related []string, fail bool) model.Finding {
	f := model.Finding{ID: "lab-" + id, Provider: "aws", Account: "111111111111", CheckID: "lab_inventory", Status: model.Pass,
		Resource: model.Resource{ID: id, Type: typ, Name: id, Attributes: attrs, Related: related}}
	if fail {
		f.Status = model.Fail
		f.Weaknesses = []string{"PUBLIC_NETWORK_EXPOSURE"}
		f.CanonicalID = "PUBLIC_NETWORK_EXPOSURE"
	}
	return f
}

const (
	f03Inst = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60004"
	f03SG   = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60004"
	f03ACL  = "arn:aws:ec2:us-east-1:111111111111:network-acl/acl-0a1b2c3d4e5f60001"
	f04DB   = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-ledger"
)

// The lab estate's F03 / F04 attribute shapes (lab/local/estate.yaml S16 / S17), ingested natively.
func labGraph() *Graph {
	g := New()
	inst := labFinding(f03Inst, "aws_instance", map[string]any{"public_ip": "198.51.100.50", "subnet_id": "subnet-0a1b2c3d4e5f60004",
		"network_acl": "acl-0a1b2c3d4e5f60001", "exposure_cidrs": []any{"0.0.0.0/0"}}, nil, true)
	sg := labFinding(f03SG, "aws_security_group", map[string]any{"ingress": []any{map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}}}, nil, false)
	acl := labFinding(f03ACL, "aws_network_acl", map[string]any{"subnet_ids": []any{"subnet-0a1b2c3d4e5f60004"}, "ingress": []any{
		map[string]any{"rule_number": 90, "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0", "action": "deny"},
		map[string]any{"rule_number": 100, "protocol": "-1", "from_port": 0, "to_port": 0, "cidr": "0.0.0.0/0", "action": "allow"},
	}}, nil, false)
	db := labFinding(f04DB, "aws_db_instance", map[string]any{"publicly_accessible": true, "db_subnet_group": "nimbus-lab-isolated",
		"subnet_route_tables":    []any{map[string]any{"route_table": "rtb-0a1b2c3d4e5f60001", "routes": []any{map[string]any{"destination": "10.20.0.0/16", "target": "local"}}}},
		"internet_gateway_route": false}, nil, true)
	g.AttachFindings([]model.Finding{inst, sg, acl, db})
	g.AddEdge(f03Inst, f03SG, EdgeAttachedTo, nil)
	g.AddEdge(f03SG, f03Inst, EdgeAllowsTrafficTo, nil)
	g.AnnotateReachability()
	return g
}

func internetEdge(g *Graph, to string) *Edge {
	for _, e := range g.Out(InternetNodeID) {
		if e.To == to && e.Kind == EdgeExposes {
			return e
		}
	}
	return nil
}

func TestReachabilityLabF03Blocked(t *testing.T) {
	g := labGraph()
	r, ok := g.ReachabilityOf(f03Inst)
	if !ok {
		t.Fatal("F03 instance carries no reachability")
	}
	if r.Status != "blocked" || !strings.Contains(r.Blocker, "NACL acl-0a1b2c3d4e5f60001 rule 90 denies 22/tcp from 0.0.0.0/0") {
		t.Fatalf("F03 = %+v", r)
	}
	e := internetEdge(g, f03Inst)
	if e == nil {
		t.Fatal("no exposes edge")
	}
	er, ok := e.Reachability()
	if !ok || er.Status != "blocked" || er.Blocker == "" || len(er.BlockedBy) == 0 {
		t.Fatalf("edge = %+v", er)
	}
	for _, k := range []string{AttrReachability, AttrReachPath, AttrReachBlocker, AttrReachConfidence} {
		if _, ok := e.Attr[k]; !ok {
			t.Errorf("edge lacks %s", k)
		}
	}
}

func TestReachabilityLabF04Blocked(t *testing.T) {
	g := labGraph()
	r, ok := g.ReachabilityOf(f04DB)
	if !ok || r.Status != "blocked" || !strings.Contains(r.Blocker, "route table rtb-0a1b2c3d4e5f60001 has no route to an internet gateway") {
		t.Fatalf("F04 = %+v (ok=%v)", r, ok)
	}
	if r.Confidence != "verified" {
		t.Errorf("confidence = %s", r.Confidence)
	}
}

// Missing route / NACL data never reads as reachable: unknown with the reason.
func TestReachabilityMissingDataUnknown(t *testing.T) {
	g := New()
	f := labFinding("arn:aws:ec2:us-east-1:111111111111:instance/i-x", "aws_instance", map[string]any{"public_ip": "198.51.100.9", "exposure_cidrs": []any{"0.0.0.0/0"}}, nil, true)
	g.AttachFindings([]model.Finding{f})
	r, ok := g.ReachabilityOf("arn:aws:ec2:us-east-1:111111111111:instance/i-x")
	if !ok || r.Status != "unknown" || r.Unknown == "" {
		t.Fatalf("got %+v", r)
	}
	if !strings.Contains(r.Unknown, "not known") && !strings.Contains(r.Unknown, "not collected") {
		t.Errorf("unknown reason = %q", r.Unknown)
	}
}

// AttachFindings runs the pass: a native ingest gets the attributes without another call.
func TestAttachFindingsAnnotates(t *testing.T) {
	g := New()
	f := labFinding("arn:aws:s3:::public", "aws_s3_bucket", map[string]any{}, nil, true)
	g.AttachFindings([]model.Finding{f})
	e := internetEdge(g, "arn:aws:s3:::public")
	if e == nil {
		t.Fatal("no edge")
	}
	if e.Attr[AttrReachability] != "reachable" {
		t.Fatalf("bucket edge attrs = %v", e.Attr)
	}
}

// Collector-shaped facts: subnet node with its effective route table, NACL node, SG ingress_rules,
// an internet-facing ALB forwarding to a private instance.
func TestReachabilityCollectorShapesAndLB(t *testing.T) {
	g := New()
	acct := "111111111111"
	add := func(id, typ string, attrs map[string]any) {
		g.AddNode(&Node{ID: id, Type: typ, Provider: "aws", Account: acct, Attributes: attrs})
	}
	allowAll := []any{map[string]any{"rule_number": 100, "protocol": "-1", "cidr": "0.0.0.0/0", "action": "allow"}}
	add("arn:aws:ec2:us-east-1:1:subnet/subnet-pub", "aws_subnet", map[string]any{"subnet_id": "subnet-pub", "vpc_id": "vpc-1",
		"route_table": map[string]any{"id": "rtb-pub", "routes": []any{map[string]any{"destination": "0.0.0.0/0", "target": "igw-1"}}}})
	add("arn:aws:ec2:us-east-1:1:subnet/subnet-priv", "aws_subnet", map[string]any{"subnet_id": "subnet-priv", "vpc_id": "vpc-1",
		"route_table": map[string]any{"id": "rtb-priv", "routes": []any{map[string]any{"destination": "0.0.0.0/0", "target": "nat-1"}}}})
	add("arn:aws:ec2:us-east-1:1:network-acl/acl-1", "aws_network_acl", map[string]any{"network_acl_id": "acl-1", "subnet_ids": []any{"subnet-pub", "subnet-priv"}, "ingress": allowAll, "egress": allowAll})
	add("arn:aws:ec2:us-east-1:1:security-group/sg-alb", "aws_security_group", map[string]any{"group_id": "sg-alb",
		"ingress_rules": []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": []any{"0.0.0.0/0"}}}})
	add("arn:aws:ec2:us-east-1:1:security-group/sg-app", "aws_security_group", map[string]any{"group_id": "sg-app",
		"ingress_rules": []any{map[string]any{"protocol": "tcp", "from_port": 8080, "to_port": 8080, "groups": []any{"sg-alb"}}}})
	inst := "arn:aws:ec2:us-east-1:1:instance/i-app"
	add(inst, "aws_instance", map[string]any{"instance_id": "i-app", "subnet_id": "subnet-priv", "public_ips": []any{}})
	lb := "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/web/1"
	add(lb, "aws_lb", map[string]any{"scheme": "internet-facing", "lb_type": "application", "subnet_ids": []any{"subnet-pub"}})
	g.AddEdge(inst, "arn:aws:ec2:us-east-1:1:security-group/sg-app", EdgeAttachedTo, nil)
	g.AddEdge(lb, "arn:aws:ec2:us-east-1:1:security-group/sg-alb", EdgeAttachedTo, nil)
	g.AddEdge(InternetNodeID, lb, EdgeExposes, map[string]any{"exposure": "wide", "exposure_cidrs": []string{"0.0.0.0/0"}})
	g.AddEdge(lb, inst, EdgeAllowsTrafficTo, map[string]any{"via": "elbv2_listener", "listener_arn": "listener/app/web/1/443", "listener_port": 443,
		"listener_protocol": "HTTPS", "target_group": "targetgroup/web/1", "target_port": 8080})
	g.AnnotateReachability()

	lr, ok := g.ReachabilityOf(lb)
	if !ok || lr.Status != "reachable" || lr.Width != "wide" {
		t.Fatalf("lb = %+v", lr)
	}
	ir, ok := g.ReachabilityOf(inst)
	if !ok || ir.Status != "reachable" || ir.Via != lb || ir.Port != "8080/tcp" {
		t.Fatalf("instance behind ALB = %+v (ok=%v)", ir, ok)
	}
	found := false
	for _, h := range ir.Path {
		if strings.Contains(h.Because, "listener listener/app/web/1/443") {
			found = true
		}
	}
	if !found {
		t.Errorf("instance path lacks the listener hop: %+v", ir.Path)
	}
}

// Persistence round trip: attributes decoded from JSON (graph_edges / graph_nodes) still parse.
func TestReachabilityOfJSONShapes(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "x", Type: "aws_instance", Attributes: map[string]any{
		AttrReachability: "blocked", AttrReachBlocker: "NACL acl-1 rule 90 denies 22/tcp from 0.0.0.0/0",
		AttrReachPath:       []any{map[string]any{"kind": "public_ip", "id": "x", "because": "public IPv4 1.2.3.4 is associated"}},
		AttrReachBlockedBy:  []any{map[string]any{"kind": "nacl_inbound", "id": "acl-1", "because": "NACL acl-1 rule 90 denies 22/tcp from 0.0.0.0/0"}},
		AttrReachConfidence: "verified",
	}})
	r, ok := g.ReachabilityOf("x")
	if !ok || r.Status != "blocked" || len(r.Path) != 1 || len(r.BlockedBy) != 1 || r.Confidence != "verified" {
		t.Fatalf("got %+v", r)
	}
	if _, ok := g.ReachabilityOf("missing"); ok {
		t.Fatal("missing node reported reachability")
	}
}

// A scanner finding on the security group itself (lab W34) is decided by the hosts it admits.
func TestReachabilityOfSecurityGroupFollowsItsTargets(t *testing.T) {
	g := labGraph()
	sgFail := labFinding(f03SG, "aws_security_group", map[string]any{"ingress": []any{map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}}}, nil, true)
	g.AttachFindings([]model.Finding{sgFail})
	r, ok := g.ReachabilityOf(f03SG)
	if !ok || r.Status != "blocked" || !strings.Contains(r.Blocker, "rule 90 denies 22/tcp") {
		t.Fatalf("sg = %+v (ok=%v)", r, ok)
	}
	// Provider inferred from the id when the finding has none; a Lambda URL by its auth type.
	g2 := New()
	fn := labFinding("arn:aws:lambda:us-east-1:111111111111:function:f", "aws_lambda_function", map[string]any{"function_url_auth_type": "NONE"}, nil, true)
	fn.Provider = ""
	g2.AttachFindings([]model.Finding{fn})
	if r, ok := g2.ReachabilityOf("arn:aws:lambda:us-east-1:111111111111:function:f"); !ok || r.Status != "reachable" || r.Port != "443/tcp" {
		t.Fatalf("lambda url = %+v", r)
	}
}
