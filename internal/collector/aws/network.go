package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Network reachability inputs (P2-REACH v1, docs/reachability.md). The collector gathers
// route tables, NACLs, subnets, ENIs, internet / NAT gateways and ELBv2 load balancers and
// writes them as facts the graph reachability pass (graph.AnnotateReachability ->
// internal/reach) reads:
//
//	aws_subnet       subnet_id, vpc_id, cidr, route_table {id, routes}, route_table_association,
//	                 internet_gateway_route, network_acl_id, nat_gateways
//	aws_network_acl  network_acl_id, vpc_id, default, subnet_ids, ingress / egress rules
//	aws_lb           scheme, lb_type, subnet_ids, security_groups, listeners; lb -allows_traffic_to->
//	                 target edges carry listener / target group / target port
//	account node     reach_coverage {input: collected | access_denied | ...}
//
// No new node types: route tables, gateways and listeners are attributes, so the registry
// and attack-path traversal are unchanged.

// Reachability inputs (keys of the account node's reach_coverage).
const (
	netRouteTables = "route_tables"
	netNACLs       = "network_acls"
	netSubnets     = "subnets"
	netENIs        = "network_interfaces"
	netIGWs        = "internet_gateways"
	netNATs        = "nat_gateways"
	netLBs         = "load_balancers"
)

var netInputs = []string{netRouteTables, netNACLs, netSubnets, netENIs, netIGWs, netNATs, netLBs}

type netInv struct {
	routeTables []regional[ec2types.RouteTable]
	nacls       []regional[ec2types.NetworkAcl]
	subnets     []regional[ec2types.Subnet]
	enis        []regional[ec2types.NetworkInterface]
	igws        []regional[ec2types.InternetGateway]
	nats        []regional[ec2types.NatGateway]
	lbs         []lbRec
	// status: input -> collected | access_denied | error | not_collected (worst over regions).
	status map[string]string
}

type lbRec struct {
	Region    string
	LB        ELBLoadBalancer
	Listeners []ELBListener
	TGs       []ELBTargetGroup
	Targets   map[string][]ELBTarget // target group ARN -> targets
}

// setNetStatus records an input's collection status; a failure in any region wins.
func (inv *inventory) setNetStatus(input, status string) {
	inv.lock(func() {
		if inv.net.status == nil {
			inv.net.status = map[string]string{}
		}
		if cur, ok := inv.net.status[input]; ok && cur != "collected" {
			return
		}
		inv.net.status[input] = status
	})
}

func netFail(acc *core.Acc, inv *inventory, region, input, api string, err error) {
	acc.Error(region+":"+api, err)
	inv.setNetStatus(input, core.ClassifyReason(err))
}

// fetchNetwork reads the region's route tables, NACLs, subnets, ENIs and gateways. Each failed
// call is its own coverage row (region:ec2:<Operation>) and marks its input in reach_coverage.
func fetchNetwork(ctx context.Context, c EC2API, region string, inv *inventory, acc *core.Acc) error {
	{
		var all []ec2types.RouteTable
		p := ec2.NewDescribeRouteTablesPaginator(c, &ec2.DescribeRouteTablesInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeRouteTablesOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.RouteTables...)
		}
		if err != nil {
			netFail(acc, inv, region, netRouteTables, "ec2:DescribeRouteTables", err)
		} else {
			inv.setNetStatus(netRouteTables, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.routeTables = append(inv.net.routeTables, regional[ec2types.RouteTable]{region, x})
				}
			})
		}
	}
	{
		var all []ec2types.NetworkAcl
		p := ec2.NewDescribeNetworkAclsPaginator(c, &ec2.DescribeNetworkAclsInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeNetworkAclsOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.NetworkAcls...)
		}
		if err != nil {
			netFail(acc, inv, region, netNACLs, "ec2:DescribeNetworkAcls", err)
		} else {
			inv.setNetStatus(netNACLs, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.nacls = append(inv.net.nacls, regional[ec2types.NetworkAcl]{region, x})
				}
			})
		}
	}
	{
		var all []ec2types.Subnet
		p := ec2.NewDescribeSubnetsPaginator(c, &ec2.DescribeSubnetsInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeSubnetsOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.Subnets...)
		}
		if err != nil {
			netFail(acc, inv, region, netSubnets, "ec2:DescribeSubnets", err)
		} else {
			inv.setNetStatus(netSubnets, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.subnets = append(inv.net.subnets, regional[ec2types.Subnet]{region, x})
				}
			})
		}
	}
	{
		var all []ec2types.NetworkInterface
		p := ec2.NewDescribeNetworkInterfacesPaginator(c, &ec2.DescribeNetworkInterfacesInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeNetworkInterfacesOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.NetworkInterfaces...)
		}
		if err != nil {
			netFail(acc, inv, region, netENIs, "ec2:DescribeNetworkInterfaces", err)
		} else {
			inv.setNetStatus(netENIs, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.enis = append(inv.net.enis, regional[ec2types.NetworkInterface]{region, x})
				}
			})
		}
	}
	{
		var all []ec2types.InternetGateway
		p := ec2.NewDescribeInternetGatewaysPaginator(c, &ec2.DescribeInternetGatewaysInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeInternetGatewaysOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.InternetGateways...)
		}
		if err != nil {
			netFail(acc, inv, region, netIGWs, "ec2:DescribeInternetGateways", err)
		} else {
			inv.setNetStatus(netIGWs, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.igws = append(inv.net.igws, regional[ec2types.InternetGateway]{region, x})
				}
			})
		}
	}
	{
		var all []ec2types.NatGateway
		p := ec2.NewDescribeNatGatewaysPaginator(c, &ec2.DescribeNatGatewaysInput{})
		var err error
		for p.HasMorePages() {
			var out *ec2.DescribeNatGatewaysOutput
			if out, err = p.NextPage(ctx); err != nil {
				break
			}
			all = append(all, out.NatGateways...)
		}
		if err != nil {
			netFail(acc, inv, region, netNATs, "ec2:DescribeNatGateways", err)
		} else {
			inv.setNetStatus(netNATs, "collected")
			inv.lock(func() {
				for _, x := range all {
					inv.net.nats = append(inv.net.nats, regional[ec2types.NatGateway]{region, x})
				}
			})
		}
	}
	return nil
}

// fetchELB reads the region's ELBv2 load balancers with their listeners, target groups and
// registered targets.
func fetchELB(ctx context.Context, c ELBv2API, region string, inv *inventory, acc *core.Acc) error {
	if c == nil {
		inv.setNetStatus(netLBs, "not_collected")
		return nil
	}
	lbs, err := c.DescribeLoadBalancers(ctx)
	if err != nil {
		netFail(acc, inv, region, netLBs, "elasticloadbalancing:DescribeLoadBalancers", err)
		return nil
	}
	ok := true
	for _, lb := range lbs {
		rec := lbRec{Region: region, LB: lb, Targets: map[string][]ELBTarget{}}
		if rec.Listeners, err = c.DescribeListeners(ctx, lb.ARN); err != nil {
			ok = false
			netFail(acc, inv, region, netLBs, "elasticloadbalancing:DescribeListeners "+lb.Name, err)
		}
		if rec.TGs, err = c.DescribeTargetGroups(ctx, lb.ARN); err != nil {
			ok = false
			netFail(acc, inv, region, netLBs, "elasticloadbalancing:DescribeTargetGroups "+lb.Name, err)
		}
		for _, tg := range rec.TGs {
			ts, err := c.DescribeTargetHealth(ctx, tg.ARN)
			if err != nil {
				ok = false
				netFail(acc, inv, region, netLBs, "elasticloadbalancing:DescribeTargetHealth "+tg.Name, err)
				continue
			}
			rec.Targets[tg.ARN] = ts
		}
		inv.lock(func() { inv.net.lbs = append(inv.net.lbs, rec) })
	}
	if ok {
		inv.setNetStatus(netLBs, "collected")
	}
	return nil
}

// ---------------------------------------------------------------- analysis

// network writes subnet / NACL nodes and the account's reach_coverage. It returns, per
// instance id, the public IPs of its ENIs (DescribeNetworkInterfaces associations).
func (a *analyzer) network() map[string][]string {
	n := &a.inv.net
	cov := map[string]any{}
	for _, in := range netInputs {
		st := n.status[in]
		if st == "" {
			st = "not_collected"
		}
		cov[in] = st
	}
	a.g.AddNode(&graph.Node{ID: a.acctN, Type: "aws_account", Class: graph.ClassAccount, Attributes: map[string]any{graph.AttrReachCoverage: cov}})

	// Internet gateways attached per VPC (a route to a detached gateway carries nothing).
	igwVPCs := map[string]map[string]bool{}
	igwKnown := n.status[netIGWs] == "collected"
	for _, ig := range n.igws {
		id := awssdk.ToString(ig.Item.InternetGatewayId)
		igwVPCs[id] = map[string]bool{}
		for _, at := range ig.Item.Attachments {
			if at.State == ec2types.AttachmentStatusAttached || string(at.State) == "available" {
				igwVPCs[id][awssdk.ToString(at.VpcId)] = true
			}
		}
	}
	// Effective route table per subnet: explicit association, else the VPC's main table.
	explicit := map[string]ec2types.RouteTable{}
	mainRT := map[string]ec2types.RouteTable{}
	for _, rt := range n.routeTables {
		for _, as := range rt.Item.Associations {
			if awssdk.ToBool(as.Main) {
				mainRT[awssdk.ToString(rt.Item.VpcId)] = rt.Item
			}
			if s := awssdk.ToString(as.SubnetId); s != "" {
				explicit[s] = rt.Item
			}
		}
	}
	naclOf := map[string]string{}
	for _, acl := range n.nacls {
		for _, as := range acl.Item.Associations {
			naclOf[awssdk.ToString(as.SubnetId)] = awssdk.ToString(acl.Item.NetworkAclId)
		}
	}
	natsBySubnet := map[string][]string{}
	for _, ng := range n.nats {
		if ng.Item.State == ec2types.NatGatewayStateDeleted {
			continue
		}
		s := awssdk.ToString(ng.Item.SubnetId)
		natsBySubnet[s] = append(natsBySubnet[s], awssdk.ToString(ng.Item.NatGatewayId))
	}
	subs := append([]regional[ec2types.Subnet](nil), n.subnets...)
	sort.Slice(subs, func(i, j int) bool {
		return awssdk.ToString(subs[i].Item.SubnetId) < awssdk.ToString(subs[j].Item.SubnetId)
	})
	for _, rs := range subs {
		s := rs.Item
		sid := awssdk.ToString(s.SubnetId)
		vpc := awssdk.ToString(s.VpcId)
		attrs := map[string]any{"subnet_id": sid, "vpc_id": vpc, "cidr": awssdk.ToString(s.CidrBlock), "availability_zone": awssdk.ToString(s.AvailabilityZone),
			"map_public_ip_on_launch": awssdk.ToBool(s.MapPublicIpOnLaunch)}
		rt, ok := explicit[sid]
		assoc := "explicit"
		if !ok {
			rt, ok = mainRT[vpc]
			assoc = "main"
		}
		if ok {
			routes, igw := routeFacts(rt, vpc, igwVPCs, igwKnown)
			attrs["route_table"] = map[string]any{"id": awssdk.ToString(rt.RouteTableId), "routes": routes}
			attrs["route_table_association"] = assoc
			attrs["internet_gateway_route"] = igw
		}
		if acl := naclOf[sid]; acl != "" {
			attrs["network_acl_id"] = acl
		}
		if ns := natsBySubnet[sid]; len(ns) > 0 {
			attrs["nat_gateways"] = ns
		}
		name := tagsEC2(s.Tags)["Name"]
		if name == "" {
			name = sid
		}
		a.add(rs.Region, model.Resource{ID: arnEC2(rs.Region, a.acct, "subnet", sid), Type: "aws_subnet", Name: name, Attributes: attrs}, tagsEC2(s.Tags), time.Time{}, false)
	}
	for _, ra := range n.nacls {
		acl := ra.Item
		id := awssdk.ToString(acl.NetworkAclId)
		var subnets []string
		for _, as := range acl.Associations {
			subnets = append(subnets, awssdk.ToString(as.SubnetId))
		}
		sort.Strings(subnets)
		ingress, egress := []any{}, []any{}
		entries := append([]ec2types.NetworkAclEntry(nil), acl.Entries...)
		sort.SliceStable(entries, func(i, j int) bool {
			return awssdk.ToInt32(entries[i].RuleNumber) < awssdk.ToInt32(entries[j].RuleNumber)
		})
		for _, e := range entries {
			cidr := awssdk.ToString(e.CidrBlock)
			if cidr == "" {
				cidr = awssdk.ToString(e.Ipv6CidrBlock)
			}
			r := map[string]any{"rule_number": int(awssdk.ToInt32(e.RuleNumber)), "protocol": awssdk.ToString(e.Protocol), "cidr": cidr, "action": string(e.RuleAction)}
			if e.PortRange != nil {
				r["from_port"], r["to_port"] = int(awssdk.ToInt32(e.PortRange.From)), int(awssdk.ToInt32(e.PortRange.To))
			}
			if awssdk.ToBool(e.Egress) {
				egress = append(egress, r)
			} else {
				ingress = append(ingress, r)
			}
		}
		name := tagsEC2(acl.Tags)["Name"]
		if name == "" {
			name = id
		}
		a.add(ra.Region, model.Resource{ID: arnEC2(ra.Region, a.acct, "network-acl", id), Type: "aws_network_acl", Name: name, Attributes: map[string]any{
			"network_acl_id": id, "vpc_id": awssdk.ToString(acl.VpcId), "default": awssdk.ToBool(acl.IsDefault), "subnet_ids": subnets, "ingress": ingress, "egress": egress,
		}}, tagsEC2(acl.Tags), time.Time{}, false)
	}
	pubByInstance := map[string][]string{}
	for _, e := range n.enis {
		if e.Item.Attachment == nil || e.Item.Association == nil {
			continue
		}
		if iid := awssdk.ToString(e.Item.Attachment.InstanceId); iid != "" {
			if ip := awssdk.ToString(e.Item.Association.PublicIp); ip != "" {
				pubByInstance[iid] = append(pubByInstance[iid], ip)
			}
		}
	}
	return pubByInstance
}

// routeFacts renders a route table's routes ({destination, target, state}) and whether an
// active route sends the internet (0.0.0.0/0 or ::/0) to an internet gateway attached to vpc.
func routeFacts(rt ec2types.RouteTable, vpc string, igwVPCs map[string]map[string]bool, igwKnown bool) ([]any, bool) {
	var out []any
	igw := false
	for _, r := range rt.Routes {
		dest := awssdk.ToString(r.DestinationCidrBlock)
		if dest == "" {
			dest = awssdk.ToString(r.DestinationIpv6CidrBlock)
		}
		if dest == "" {
			dest = awssdk.ToString(r.DestinationPrefixListId)
		}
		target := ""
		for _, t := range []*string{r.GatewayId, r.NatGatewayId, r.TransitGatewayId, r.VpcPeeringConnectionId, r.EgressOnlyInternetGatewayId,
			r.NetworkInterfaceId, r.InstanceId, r.CarrierGatewayId, r.LocalGatewayId, r.CoreNetworkArn} {
			if v := awssdk.ToString(t); v != "" {
				target = v
				break
			}
		}
		state := string(r.State)
		if strings.HasPrefix(target, "igw-") && igwKnown && !igwVPCs[target][vpc] {
			state = "blackhole" // the gateway is not attached to this VPC
		}
		out = append(out, map[string]any{"destination": dest, "target": target, "state": state})
		if strings.HasPrefix(target, "igw-") && state != "blackhole" && (dest == "0.0.0.0/0" || dest == "::/0") {
			igw = true
		}
	}
	return out, igw
}

// loadBalancers writes aws_lb nodes, their security-group exposure, and lb -allows_traffic_to->
// target edges for every registered target (listener / target group / port on the edge).
func (a *analyzer) loadBalancers() {
	lbs := append([]lbRec(nil), a.inv.net.lbs...)
	sort.Slice(lbs, func(i, j int) bool { return lbs[i].LB.ARN < lbs[j].LB.ARN })
	for _, rec := range lbs {
		lb := rec.LB
		var listeners []any
		ls := append([]ELBListener(nil), rec.Listeners...)
		sort.Slice(ls, func(i, j int) bool { return ls[i].Port < ls[j].Port })
		var portSpecs []string
		for _, l := range ls {
			listeners = append(listeners, map[string]any{"arn": l.ARN, "protocol": l.Protocol, "port": l.Port, "target_groups": l.TargetGroups})
			proto := "tcp"
			if strings.Contains(strings.ToUpper(l.Protocol), "UDP") {
				proto = "udp"
			}
			portSpecs = append(portSpecs, fmt.Sprintf("%s/%d", proto, l.Port))
		}
		attrs := map[string]any{"name": lb.Name, "dns_name": lb.DNSName, "scheme": lb.Scheme, "lb_type": lb.Type, "vpc_id": lb.VPCID,
			"subnet_ids": lb.Subnets, "security_groups": lb.SecurityGroups, "listeners": listeners}
		a.add(rec.Region, model.Resource{ID: lb.ARN, Type: "aws_lb", Name: lb.Name, Attributes: attrs}, nil, time.Time{}, false)
		public := strings.EqualFold(lb.Scheme, "internet-facing")
		if len(lb.SecurityGroups) > 0 {
			a.attachSGs(lb.ARN, rec.Region, lb.SecurityGroups, public, "elbv2_internet_facing")
		} else if public && len(ls) > 0 {
			// A network load balancer without security groups passes every listener port.
			core.Expose(a.g, lb.ARN, map[string]any{"via": "nlb_internet_facing", "ports": portSpecs}, nil, a.spec.TrustedCIDRs)
		}
		tgs := append([]ELBTargetGroup(nil), rec.TGs...)
		sort.Slice(tgs, func(i, j int) bool { return tgs[i].ARN < tgs[j].ARN })
		for _, tg := range tgs {
			// Listeners whose default action forwards to this group; a group reached only
			// through listener rules (DescribeRules is not read in v1) is tied to every listener.
			var via []ELBListener
			for _, l := range ls {
				for _, t := range l.TargetGroups {
					if t == tg.ARN {
						via = append(via, l)
					}
				}
			}
			ruleOnly := len(via) == 0
			if ruleOnly {
				via = ls
			}
			targets := append([]ELBTarget(nil), rec.Targets[tg.ARN]...)
			sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
			for _, t := range targets {
				to := ""
				switch strings.ToLower(tg.TargetType) {
				case "instance", "":
					to = arnEC2(rec.Region, a.acct, "instance", t.ID)
				case "lambda", "alb":
					to = t.ID
				default:
					continue // ip targets: no node to attach to in v1
				}
				port := t.Port
				if port == 0 {
					port = tg.Port
				}
				for _, l := range via {
					a.g.AddEdge(lb.ARN, to, graph.EdgeAllowsTrafficTo, map[string]any{
						"via": "elbv2_listener", "listener_arn": l.ARN, "listener_port": l.Port, "listener_protocol": l.Protocol,
						"target_group": tg.ARN, "target_group_protocol": tg.Protocol, "target_port": port, "target_type": tg.TargetType,
						"preserve_client_ip":       strings.EqualFold(lb.Type, "network") && strings.EqualFold(tg.TargetType, "instance"),
						"listener_rule_unverified": ruleOnly,
						"because":                  fmt.Sprintf("listener %s (%d/%s) of %s forwards to target group %s, target %s port %d", l.ARN, l.Port, l.Protocol, lb.Name, tg.Name, t.ID, port),
					})
				}
			}
		}
	}
}

// sgIngressRules renders a group's ingress as rules with their sources (the reachability
// model needs which source admits which port; "ingress" keeps the port specs only).
func sgIngressRules(sg ec2types.SecurityGroup) []any {
	out := []any{}
	for _, p := range sg.IpPermissions {
		r := map[string]any{"protocol": awssdk.ToString(p.IpProtocol)}
		if p.FromPort != nil {
			r["from_port"] = int(awssdk.ToInt32(p.FromPort))
		}
		if p.ToPort != nil {
			r["to_port"] = int(awssdk.ToInt32(p.ToPort))
		}
		cidrs := []string{}
		for _, x := range p.IpRanges {
			cidrs = append(cidrs, awssdk.ToString(x.CidrIp))
		}
		for _, x := range p.Ipv6Ranges {
			cidrs = append(cidrs, awssdk.ToString(x.CidrIpv6))
		}
		r["cidrs"] = cidrs
		var groups []string
		for _, g := range p.UserIdGroupPairs {
			if id := awssdk.ToString(g.GroupId); id != "" {
				groups = append(groups, id)
			}
		}
		if len(groups) > 0 {
			r["groups"] = groups
		}
		var pls []string
		for _, pl := range p.PrefixListIds {
			pls = append(pls, awssdk.ToString(pl.PrefixListId))
		}
		if len(pls) > 0 {
			r["prefix_lists"] = pls
		}
		out = append(out, r)
	}
	return out
}
