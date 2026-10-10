package graph

import "testing"

// An instance without a public IPv4 but with an IPv6 address, an IGW ::/0 route and an SG
// admitting ::/0 is reachable over IPv6 (verify-4 R24); the same instance whose route table
// sends ::/0 to an egress-only IGW is blocked.
func TestV4IPv6OnlyInstanceReachable(t *testing.T) {
	build := func(v6Target string) *Graph {
		g := New()
		add := func(id, typ string, attrs map[string]any) {
			g.AddNode(&Node{ID: id, Type: typ, Provider: "aws", Account: "111111111111", Attributes: attrs})
		}
		allowAll := []any{map[string]any{"rule_number": 100, "protocol": "-1", "cidr": "0.0.0.0/0", "action": "allow"},
			map[string]any{"rule_number": 101, "protocol": "-1", "ipv6_cidr_block": "::/0", "action": "allow"}}
		add("arn:aws:ec2:us-east-1:1:subnet/subnet-pub", "aws_subnet", map[string]any{"subnet_id": "subnet-pub", "vpc_id": "vpc-1",
			"route_table": map[string]any{"id": "rtb-pub", "routes": []any{
				map[string]any{"destination": "0.0.0.0/0", "target": "igw-1", "state": "active"},
				map[string]any{"destination": "::/0", "target": v6Target, "state": "active"}}}})
		add("arn:aws:ec2:us-east-1:1:network-acl/acl-1", "aws_network_acl", map[string]any{"network_acl_id": "acl-1", "subnet_ids": []any{"subnet-pub"}, "ingress": allowAll, "egress": allowAll})
		sg := "arn:aws:ec2:us-east-1:1:security-group/sg-6"
		add(sg, "aws_security_group", map[string]any{"group_id": "sg-6",
			"ingress_rules": []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": []any{"::/0"}}}})
		inst := "arn:aws:ec2:us-east-1:1:instance/i-v6"
		add(inst, "aws_instance", map[string]any{"instance_id": "i-v6", "subnet_id": "subnet-pub", "public_ips": []any{}, "ipv6_addresses": []any{"2600:1f18::10"}})
		g.AddEdge(inst, sg, EdgeAttachedTo, nil)
		g.AddEdge(InternetNodeID, inst, EdgeExposes, map[string]any{"exposure": "wide", "exposure_cidrs": []string{"::/0"}, "ports": []string{"tcp/443"}})
		g.AnnotateReachability()
		return g
	}
	inst := "arn:aws:ec2:us-east-1:1:instance/i-v6"
	r, _ := build("igw-1").ReachabilityOf(inst)
	if r.Status != "reachable" {
		t.Errorf("IPv6-only instance via igw: want reachable, got %s (%s)", r.Status, r.Blocker)
	}
	r, _ = build("eigw-1").ReachabilityOf(inst)
	if r.Status != "blocked" {
		t.Errorf("IPv6-only instance via eigw: want blocked, got %s", r.Status)
	}
}
