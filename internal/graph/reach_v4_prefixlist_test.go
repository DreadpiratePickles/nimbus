package graph

import "testing"

// Collector shape: an SG whose only source is a managed prefix list (e.g. the CloudFront
// origin-facing list, which holds public CIDRs). The collector records it as prefix_lists;
// the verdict must not be "blocked".
func TestV4PrefixListSGSourceNotBlocked(t *testing.T) {
	g := New()
	add := func(id, typ string, attrs map[string]any) {
		g.AddNode(&Node{ID: id, Type: typ, Provider: "aws", Account: "111111111111", Attributes: attrs})
	}
	allowAll := []any{map[string]any{"rule_number": 100, "protocol": "-1", "cidr": "0.0.0.0/0", "action": "allow"}}
	add("arn:aws:ec2:us-east-1:1:subnet/subnet-pub", "aws_subnet", map[string]any{"subnet_id": "subnet-pub", "vpc_id": "vpc-1",
		"route_table": map[string]any{"id": "rtb-pub", "routes": []any{map[string]any{"destination": "0.0.0.0/0", "target": "igw-1", "state": "active"}}}})
	add("arn:aws:ec2:us-east-1:1:network-acl/acl-1", "aws_network_acl", map[string]any{"network_acl_id": "acl-1", "subnet_ids": []any{"subnet-pub"}, "ingress": allowAll, "egress": allowAll})
	sg := "arn:aws:ec2:us-east-1:1:security-group/sg-cf"
	add(sg, "aws_security_group", map[string]any{"group_id": "sg-cf",
		"ingress_rules": []any{map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidrs": []any{}, "prefix_lists": []any{"pl-3b927c52"}}}})
	inst := "arn:aws:ec2:us-east-1:1:instance/i-web"
	add(inst, "aws_instance", map[string]any{"instance_id": "i-web", "subnet_id": "subnet-pub", "public_ips": []any{"198.51.100.9"}})
	g.AddEdge(inst, sg, EdgeAttachedTo, nil)
	g.AddEdge(InternetNodeID, inst, EdgeExposes, map[string]any{"exposure": "wide", "exposure_cidrs": []string{"0.0.0.0/0"}, "ports": []string{"tcp/443"}})
	g.AnnotateReachability()
	r, ok := g.ReachabilityOf(inst)
	t.Logf("verdict: ok=%v %+v", ok, r)
	if r.Status != "unknown" {
		t.Errorf("prefix-list-sourced SG rule: want unknown, got %s", r.Status)
	}
	if r.Status == "blocked" {
		t.Errorf("prefix-list-sourced SG rule reported blocked: %s", r.Blocker)
	}
}
