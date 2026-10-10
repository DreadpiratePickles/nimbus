package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/reach"
)

// Effective internet reachability (P2-REACH v1, docs/reachability.md). AnnotateReachability runs
// the internal/reach model over every internet edge and exposed node and writes:
//
//	reachability      reachable | blocked | unknown
//	reach_width       wide | narrow | trusted | private (sources that survive every layer)
//	reach_cidrs       []string  those sources
//	reach_port        "22/tcp"  the port the verdict is for
//	reach_path        []{kind,id,because}  hops that let traffic through
//	reach_blocker     string    joined because of the blockers (blocked only)
//	reach_blocked_by  []{kind,id,because}  the blocking controls (blocked only)
//	reach_unknown     string    why it could not be decided (unknown only)
//	reach_confidence  verified | inferred | hint
//	reach_via         (nodes only) "direct" or the load balancer the verdict goes through
//
// An edge carries the verdict of its own (direct) exposure; a node carries the best verdict over
// the direct path and every load-balancer listener that forwards to it. Missing data is
// "unknown" with the reason, never "reachable". Trusted CIDRs are not applied here (width is
// computed without them); attackpath applies trusted_cidrs at analysis time.
const (
	AttrReachability    = "reachability"
	AttrReachWidth      = "reach_width"
	AttrReachCIDRs      = "reach_cidrs"
	AttrReachPort       = "reach_port"
	AttrReachPath       = "reach_path"
	AttrReachBlocker    = "reach_blocker"
	AttrReachBlockedBy  = "reach_blocked_by"
	AttrReachUnknown    = "reach_unknown"
	AttrReachConfidence = "reach_confidence"
	AttrReachVia        = "reach_via"

	// AttrReachCoverage on an account node: network collection status per input
	// ({"route_tables": "collected" | "access_denied" | ...}); unknown verdicts cite it.
	AttrReachCoverage = "reach_coverage"
)

var reachKeys = []string{AttrReachability, AttrReachWidth, AttrReachCIDRs, AttrReachPort, AttrReachPath, AttrReachBlocker,
	AttrReachBlockedBy, AttrReachUnknown, AttrReachConfidence, AttrReachVia}

// Reachability is the parsed verdict on a node or edge.
type Reachability struct {
	Status     string      `json:"reachability"`
	Width      string      `json:"reach_width,omitempty"`
	Sources    []string    `json:"reach_cidrs,omitempty"`
	Port       string      `json:"reach_port,omitempty"`
	Path       []reach.Hop `json:"reach_path,omitempty"`
	Blocker    string      `json:"reach_blocker,omitempty"`
	BlockedBy  []reach.Hop `json:"reach_blocked_by,omitempty"`
	Unknown    string      `json:"reach_unknown,omitempty"`
	Confidence string      `json:"reach_confidence,omitempty"`
	Via        string      `json:"reach_via,omitempty"`
}

func parseReachability(attrs map[string]any) (Reachability, bool) {
	if attrs == nil {
		return Reachability{}, false
	}
	if s, _ := attrs[AttrReachability].(string); s == "" {
		return Reachability{}, false
	}
	sub := map[string]any{}
	for _, k := range reachKeys {
		if v, ok := attrs[k]; ok && v != nil {
			sub[k] = v
		}
	}
	b, err := json.Marshal(sub)
	if err != nil {
		return Reachability{}, false
	}
	var r Reachability
	if err := json.Unmarshal(b, &r); err != nil {
		return Reachability{}, false
	}
	return r, true
}

// ReachabilityOf returns the reachability verdict recorded on a node (ok=false when the node
// does not exist or was never annotated).
func (g *Graph) ReachabilityOf(nodeID string) (Reachability, bool) {
	n, ok := g.Node(nodeID)
	if !ok {
		return Reachability{}, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return parseReachability(n.Attributes)
}

// Reachability returns the verdict recorded on an internet edge.
func (e *Edge) Reachability() (Reachability, bool) { return parseReachability(e.Attr) }

func hopMaps(hs []reach.Hop) []any {
	out := make([]any, 0, len(hs))
	for _, h := range hs {
		m := map[string]any{"kind": h.Kind, "because": h.Because}
		if h.ID != "" {
			m["id"] = h.ID
		}
		out = append(out, m)
	}
	return out
}

func reachAttrs(r reach.Result) map[string]any {
	m := map[string]any{
		AttrReachability:    string(r.Status),
		AttrReachConfidence: r.Confidence,
		AttrReachPort:       r.Port.String(),
	}
	if r.Width != "" {
		m[AttrReachWidth] = r.Width
	}
	if len(r.Sources) > 0 {
		m[AttrReachCIDRs] = append([]string(nil), r.Sources...)
	}
	if len(r.Path) > 0 {
		m[AttrReachPath] = hopMaps(r.Path)
	}
	switch r.Status {
	case reach.StatusBlocked:
		m[AttrReachBlocker] = r.Blocker()
		m[AttrReachBlockedBy] = hopMaps(r.Blockers)
	case reach.StatusUnknown:
		m[AttrReachUnknown] = r.UnknownReason()
	}
	return m
}

// AnnotateReachability evaluates every internet edge (exposes / allows_traffic_to from the
// internet node) and every exposed node, including nodes reachable only through an
// internet-facing load balancer. It is idempotent; graph.AttachFindings runs it last.
func (g *Graph) AnnotateReachability() {
	idx := g.netIndex()
	exposed := map[string]*Edge{}
	for _, e := range g.Out(InternetNodeID) {
		if e.Kind != EdgeExposes && e.Kind != EdgeAllowsTrafficTo {
			continue
		}
		n, ok := g.Node(e.To)
		if !ok {
			continue
		}
		r := idx.evaluate(n, e, false)
		m := e.cowAttr()
		for _, k := range reachKeys {
			delete(m, k)
		}
		for k, v := range reachAttrs(r) {
			m[k] = v
		}
		if prev, ok := exposed[n.ID]; !ok || prev == nil || prev.Kind != EdgeExposes {
			exposed[n.ID] = e
		}
	}
	// Targets behind an exposed load balancer are exposed through it.
	for id := range exposed {
		n, _ := g.Node(id)
		if n == nil || idx.kindOf(n, nil) != reach.KindLoadBalancer {
			continue
		}
		for _, e := range g.Out(id) {
			if e.Kind == EdgeAllowsTrafficTo && e.Attr["listener_port"] != nil {
				if _, ok := exposed[e.To]; !ok {
					exposed[e.To] = nil
				}
			}
		}
	}
	ids := make([]string, 0, len(exposed))
	for id := range exposed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n, ok := g.Node(id)
		if !ok {
			continue
		}
		r := idx.evaluate(n, exposed[id], true)
		attrs := reachAttrs(r)
		attrs[AttrReachVia] = "direct"
		for _, h := range r.Path {
			if h.Kind == reach.HopListener {
				for _, h2 := range r.Path {
					if h2.Kind == reach.HopLoadBalancer {
						attrs[AttrReachVia] = h2.ID
					}
				}
			}
		}
		g.mu.Lock()
		cp := make(map[string]any, len(n.Attributes)+len(attrs))
		for k, v := range n.Attributes {
			cp[k] = v
		}
		for _, k := range reachKeys {
			delete(cp, k)
		}
		for k, v := range attrs {
			cp[k] = v
		}
		n.Attributes = cp
		g.mu.Unlock()
	}
}

// evaluate is the verdict for one node: the reach model over its facts, or, for a security
// group / NSG / firewall, the best verdict over the resources it admits traffic to.
func (idx *netIndex) evaluate(n *Node, e *Edge, withFrontends bool) reach.Result {
	if !isNetworkControl(n) {
		return idx.withCoverage(n, reach.Reachable(idx.target(n, e, withFrontends), reach.Internet(), reach.Port{}))
	}
	g := idx.g
	var results []reach.Result
	seen := map[string]bool{}
	for _, out := range g.Out(n.ID) {
		if out.Kind != EdgeAllowsTrafficTo || seen[out.To] {
			continue
		}
		seen[out.To] = true
		tn, ok := g.Node(out.To)
		if !ok || isNetworkControl(tn) {
			continue
		}
		var te *Edge
		for _, ie := range g.In(tn.ID) {
			if ie.From == InternetNodeID && ie.Kind == EdgeExposes {
				te = ie
			}
		}
		r := idx.withCoverage(tn, reach.Reachable(idx.target(tn, te, false), reach.Internet(), reach.Port{}))
		hop := reach.Hop{Kind: reach.HopSecurityGroup, ID: lastSegment(n.ID), Because: fmt.Sprintf("%s admits traffic to %s", n.Name, tn.Name)}
		r.Path = append([]reach.Hop{hop}, r.Path...)
		results = append(results, r)
	}
	if len(results) == 0 {
		return reach.Result{Status: reach.StatusUnknown, Confidence: "hint",
			Unknown: []reach.Hop{{Kind: reach.HopModel, ID: n.ID, Because: fmt.Sprintf("no resource behind %s is known (the rule alone is not a reachable host)", n.Name)}}}
	}
	var unknown *reach.Result
	blocked := reach.Result{Status: reach.StatusBlocked, Port: results[0].Port, Confidence: "verified"}
	for i := range results {
		r := results[i]
		switch r.Status {
		case reach.StatusReachable:
			return r
		case reach.StatusUnknown:
			if unknown == nil {
				unknown = &results[i]
			}
		default:
			blocked.Blockers = append(blocked.Blockers, r.Blockers...)
			blocked.Path = append(blocked.Path, r.Path...)
		}
	}
	if unknown != nil {
		return *unknown
	}
	return blocked
}

// ---------------------------------------------------------------- graph -> reach.Target

type netIndex struct {
	g            *Graph
	subnets      map[string]*Node       // bare subnet id -> aws_subnet node
	nacls        map[string]*reach.NACL // bare acl id -> NACL
	naclBySubnet map[string]*reach.NACL
}

func (g *Graph) netIndex() *netIndex {
	idx := &netIndex{g: g, subnets: map[string]*Node{}, nacls: map[string]*reach.NACL{}, naclBySubnet: map[string]*reach.NACL{}}
	for _, n := range g.Nodes() {
		t := strings.ToLower(n.Type)
		switch {
		case t == "aws_subnet":
			id, _ := n.Attributes["subnet_id"].(string)
			if id == "" {
				id = lastSegment(n.ID)
			}
			idx.subnets[id] = n
		case t == "aws_network_acl":
			acl := parseNACL(n)
			idx.nacls[acl.ID] = acl
			for _, s := range toStringList(n.Attributes["subnet_ids"]) {
				idx.naclBySubnet[s] = acl
			}
		}
	}
	return idx
}

func parseNACL(n *Node) *reach.NACL {
	a := n.Attributes
	id, _ := a["network_acl_id"].(string)
	if id == "" {
		id = lastSegment(n.ID)
	}
	acl := &reach.NACL{ID: id, Inbound: []reach.NACLRule{}}
	for _, k := range []string{"ingress", "inbound"} {
		if v, ok := a[k]; ok {
			acl.Inbound = parseNACLRules(v)
		}
	}
	for _, k := range []string{"egress", "outbound"} {
		if v, ok := a[k]; ok {
			acl.Outbound = parseNACLRules(v)
		}
	}
	return acl
}

func parseNACLRules(v any) []reach.NACLRule {
	out := []reach.NACLRule{}
	for _, m := range toMapList(v) {
		r := reach.NACLRule{
			Number:   firstInt(m, "rule_number", "rule", "number"),
			Protocol: firstStr(m, "protocol"),
			FromPort: firstInt(m, "from_port", "from"),
			ToPort:   firstInt(m, "to_port", "to"),
			CIDR:     firstStr(m, "cidr", "cidr_block", "ipv6_cidr_block", "ipv6_cidr"),
			Action:   strings.ToLower(firstStr(m, "action", "rule_action")),
		}
		out = append(out, r)
	}
	return out
}

// providerOf is the node's provider, inferred from its id / type when the finding left it empty.
func providerOf(n *Node) string {
	if p := strings.ToLower(n.Provider); p != "" && p != "any" {
		return p
	}
	t, id := strings.ToLower(n.Type), strings.ToLower(n.ID)
	switch {
	case strings.HasPrefix(id, "arn:aws:") || strings.HasPrefix(t, "aws_"):
		return "aws"
	case strings.HasPrefix(id, "//") && strings.Contains(id, "googleapis.com") || strings.HasPrefix(t, "gcp_") || strings.HasPrefix(t, "google_"):
		return "gcp"
	case strings.HasPrefix(id, "/subscriptions/") || strings.HasPrefix(t, "azure_") || strings.HasPrefix(t, "azurerm_"):
		return "azure"
	case strings.HasPrefix(t, "k8s_") || strings.HasPrefix(t, "kubernetes_"):
		return "kubernetes"
	}
	return ""
}

// isNetworkControl: a security group / NSG / firewall rule. Its own exposure edge (a scanner
// finding on the rule) is decided by the resources it admits traffic to.
func isNetworkControl(n *Node) bool {
	t := strings.ToLower(n.Type)
	return strings.Contains(t, "security_group") || strings.Contains(t, "firewall") || strings.Contains(t, "network_security_group")
}

func (idx *netIndex) kindOf(n *Node, e *Edge) reach.Kind {
	t := strings.ToLower(n.Type)
	prov := providerOf(n)
	a := n.Attributes
	via := ""
	if e != nil {
		via, _ = e.Attr["via"].(string)
	}
	switch {
	case t == "aws_instance" || t == "aws_ec2_instance":
		return reach.KindInstance
	case t == "aws_network_interface":
		return reach.KindNetworkIface
	case strings.Contains(t, "db_instance") || t == "aws_rds_cluster":
		return reach.KindDBInstance
	case t == "aws_lb" || t == "aws_alb" || t == "aws_elb" || (prov == "aws" && strings.Contains(t, "load_balancer")):
		return reach.KindLoadBalancer
	case t == "aws_lambda_function":
		u, _ := a["function_url"].(string)
		if u != "" || via == "lambda_function_url" || firstStr(a, "function_url_auth_type", "url_auth_type") != "" {
			return reach.KindFunctionURL
		}
		return ""
	case strings.Contains(t, "api_gateway") || strings.Contains(t, "apigateway"):
		return reach.KindAPIGateway
	case t == "aws_eks_cluster":
		return reach.KindEKSEndpoint
	case prov == "aws":
		if ClassFor(n.Type) == ClassDataStore && !strings.Contains(t, "redshift") && !strings.Contains(t, "elasticache") &&
			!strings.Contains(t, "docdb") && !strings.Contains(t, "opensearch") && !strings.Contains(t, "elasticsearch") && !strings.Contains(t, "neptune") {
			return reach.KindServiceEndpoint
		}
		return ""
	case prov == "azure" || prov == "gcp" || prov == "kubernetes" || prov == "oci":
		switch ClassFor(n.Type) {
		case ClassCompute:
			return reach.KindVM
		case ClassDataStore:
			return reach.KindServiceEndpoint
		}
	}
	return ""
}

func boolPtr(v any) *bool {
	switch b := v.(type) {
	case bool:
		return &b
	case string:
		switch strings.ToLower(b) {
		case "true", "yes":
			t := true
			return &t
		case "false", "no":
			f := false
			return &f
		}
	}
	return nil
}

// publicIP reads the address layer: public_ip (string or bool), public_ips (list; empty = none),
// external / NAT IPs on other clouds.
func publicIP(a map[string]any) (*bool, string) {
	t, f := true, false
	for _, k := range []string{"public_ip", "public_ip_address", "external_ip", "nat_ip"} {
		v, ok := a[k]
		if !ok {
			continue
		}
		switch x := v.(type) {
		case string:
			if x != "" {
				return &t, x
			}
			return &f, ""
		case bool:
			return &x, ""
		case nil:
			return &f, ""
		}
	}
	if v, ok := a["public_ips"]; ok {
		if l := toStringList(v); len(l) > 0 {
			return &t, l[0]
		}
		return &f, ""
	}
	if b := boolPtr(a["associate_public_ip_address"]); b != nil {
		return b, ""
	}
	return nil, ""
}

func (idx *netIndex) target(n *Node, e *Edge, withFrontends bool) reach.Target {
	a := n.Attributes
	if a == nil {
		a = map[string]any{}
	}
	t := reach.Target{ID: n.ID, Kind: idx.kindOf(n, e), Provider: providerOf(n)}
	if t.Kind == "" {
		t.Kind = reach.Kind("unmodelled:" + n.Type)
	}
	switch t.Kind {
	case reach.KindInstance, reach.KindNetworkIface, reach.KindVM:
		t.PublicIP, t.PublicAddress = publicIP(a)
		t.IPv6Addresses = ipv6Addrs(a)
	case reach.KindDBInstance:
		t.PubliclyAccessible = boolPtr(a["publicly_accessible"])
	case reach.KindLoadBalancer:
		t.Scheme = firstStr(a, "scheme")
		if t.Scheme == "" {
			if b := boolPtr(a["internal"]); b != nil {
				t.Scheme = map[bool]string{true: "internal", false: "internet-facing"}[*b]
			}
		}
		t.LBType = firstStr(a, "lb_type", "load_balancer_type", "type")
	case reach.KindFunctionURL:
		t.AuthType = firstStr(a, "url_auth_type", "function_url_auth_type", "auth_type")
	case reach.KindAPIGateway:
		t.EndpointType = firstStr(a, "endpoint_type")
	case reach.KindEKSEndpoint:
		t.EndpointPublic = boolPtr(a["endpoint_public_access"])
		if v, ok := a["public_access_cidrs"]; ok {
			t.PublicAccessCIDRs = toStringList(v)
		}
	}
	switch t.Kind {
	case reach.KindInstance, reach.KindNetworkIface, reach.KindDBInstance, reach.KindLoadBalancer:
		t.Subnets = idx.subnetsFor(n)
		t.SecurityGroups = idx.securityGroups(n)
	}
	if e != nil {
		if v, ok := e.Attr["exposure_cidrs"]; ok {
			t.Sources = toStringList(v)
			if t.Sources == nil {
				t.Sources = []string{}
			}
		}
		for _, p := range toStringList(e.Attr["ports"]) {
			if pp, ok := parsePortSpec(p); ok {
				t.Ports = append(t.Ports, pp)
			}
		}
	}
	if t.Kind == reach.KindLoadBalancer && t.SecurityGroups == nil && strings.EqualFold(t.LBType, "network") {
		if v, ok := a["security_groups"]; ok && len(toStringList(v)) == 0 {
			t.SecurityGroups = []reach.SecurityGroup{}
		}
	}
	if withFrontends {
		t.FrontedBy = idx.frontends(n)
	}
	return t
}

func parsePortSpec(s string) (reach.Port, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	proto, ports := "tcp", s
	if i := strings.Index(s, "/"); i >= 0 {
		proto, ports = s[:i], s[i+1:]
	}
	if ports == "all" || s == "all" {
		return reach.Port{}, false
	}
	if i := strings.Index(ports, "-"); i > 0 {
		ports = ports[:i]
	}
	n, err := strconv.Atoi(ports)
	if err != nil || n <= 0 {
		return reach.Port{}, false
	}
	return reach.Port{Protocol: proto, Number: n}, true
}

// subnetsFor resolves the target's subnets: subnet_id / subnet_ids against aws_subnet nodes
// (route table, IGW summary) and NACLs (by association or the target's network_acl), or the
// native-ingest summary keys subnet_route_tables / internet_gateway_route.
func (idx *netIndex) subnetsFor(n *Node) []reach.Subnet {
	a := n.Attributes
	var ids []string
	if s, _ := a["subnet_id"].(string); s != "" {
		ids = append(ids, s)
	}
	for _, k := range []string{"subnet_ids", "subnets"} {
		ids = append(ids, toStringList(a[k])...)
	}
	igw := boolPtr(a["internet_gateway_route"])
	var targetACL *reach.NACL
	if s, _ := a["network_acl"].(string); s != "" {
		targetACL = idx.nacls[lastSegment(s)]
	}
	var out []reach.Subnet
	seen := map[string]bool{}
	for _, id := range ids {
		id = lastSegment(id)
		if seen[id] {
			continue
		}
		seen[id] = true
		sn := reach.Subnet{ID: id, NACL: idx.naclBySubnet[id]}
		if sn.NACL == nil && targetACL != nil {
			sn.NACL = targetACL
		}
		if node := idx.subnets[id]; node != nil {
			sn.CIDR, _ = node.Attributes["cidr"].(string)
			sn.RouteTable = parseRouteTable(node.Attributes["route_table"])
			sn.IGWRoute = boolPtr(node.Attributes["internet_gateway_route"])
			if aclID, _ := node.Attributes["network_acl_id"].(string); sn.NACL == nil && aclID != "" {
				sn.NACL = idx.nacls[aclID]
			}
		}
		if sn.RouteTable == nil && sn.IGWRoute == nil {
			sn.IGWRoute = igw
		}
		out = append(out, sn)
	}
	if len(out) > 0 {
		return out
	}
	group, _ := a["db_subnet_group"].(string)
	for i, m := range toMapList(a["subnet_route_tables"]) {
		rt := parseRouteTable(m)
		id := group
		if id == "" || i > 0 {
			id = fmt.Sprintf("%s#%d", n.ID, i)
			if rt != nil {
				id = "subnet of " + rt.ID
			}
		}
		out = append(out, reach.Subnet{ID: id, RouteTable: rt, IGWRoute: igw, NACL: targetACL})
	}
	if len(out) > 0 {
		return out
	}
	if igw != nil || targetACL != nil {
		return []reach.Subnet{{ID: "subnet of " + lastSegment(n.ID), IGWRoute: igw, NACL: targetACL}}
	}
	return nil
}

func parseRouteTable(v any) *reach.RouteTable {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	rt := &reach.RouteTable{ID: firstStr(m, "id", "route_table", "route_table_id")}
	for _, r := range toMapList(m["routes"]) {
		rt.Routes = append(rt.Routes, reach.Route{
			Destination: firstStr(r, "destination", "destination_cidr_block", "cidr", "destination_ipv6_cidr_block", "destination_prefix_list_id"),
			Target:      firstStr(r, "target", "gateway_id", "nat_gateway_id", "transit_gateway_id"),
			State:       firstStr(r, "state"),
		})
	}
	return rt
}

// securityGroups parses every attached group's rules; nil when any group's rules are not in a
// parseable form (the exposure edge's sources are used instead).
func (idx *netIndex) securityGroups(n *Node) []reach.SecurityGroup {
	g := idx.g
	seen := map[string]bool{}
	var ids []string
	for _, e := range g.Out(n.ID) {
		if e.Kind == EdgeAttachedTo {
			ids = append(ids, e.To)
		}
	}
	for _, e := range g.In(n.ID) {
		if e.Kind == EdgeAllowsTrafficTo && e.Attr["listener_port"] == nil {
			ids = append(ids, e.From)
		}
	}
	var out []reach.SecurityGroup
	for _, id := range ids {
		if seen[id] || id == InternetNodeID {
			continue
		}
		seen[id] = true
		sgN, ok := g.Node(id)
		if !ok || !strings.Contains(strings.ToLower(sgN.Type), "security_group") {
			continue
		}
		sg, ok := parseSG(sgN)
		if !ok {
			return nil
		}
		out = append(out, sg)
	}
	return out
}

func parseSG(n *Node) (reach.SecurityGroup, bool) {
	a := n.Attributes
	id, _ := a["group_id"].(string)
	if id == "" {
		id = lastSegment(n.ID)
	}
	sg := reach.SecurityGroup{ID: id, Ingress: []reach.SGRule{}}
	raw, ok := a["ingress_rules"]
	if !ok {
		raw, ok = a["ingress"]
	}
	if !ok {
		return sg, false
	}
	list, isList := raw.([]any)
	if ms, ok := raw.([]map[string]any); ok {
		for _, m := range ms {
			list = append(list, m)
		}
		isList = true
	}
	if !isList {
		return sg, false
	}
	for _, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			return sg, false // ["tcp/22", ...]: port specs without sources
		}
		r := reach.SGRule{Protocol: firstStr(m, "protocol", "ip_protocol"), FromPort: firstInt(m, "from_port", "from"), ToPort: firstInt(m, "to_port", "to")}
		for _, k := range []string{"cidrs", "sources", "cidr_blocks", "ipv6_cidr_blocks"} {
			r.Sources = append(r.Sources, toStringList(m[k])...)
		}
		for _, k := range []string{"cidr", "cidr_ipv4", "cidr_ipv6"} {
			if s, _ := m[k].(string); s != "" {
				r.Sources = append(r.Sources, s)
			}
		}
		for _, k := range []string{"groups", "security_groups", "source_security_group_ids"} {
			for _, gid := range toStringList(m[k]) {
				r.Groups = append(r.Groups, lastSegment(gid))
			}
		}
		// Managed prefix-list sources (collector "prefix_lists"; Terraform prefix_list_ids):
		// not expanded, so the verdict for them is unknown, never blocked (verify-4 R15).
		for _, k := range []string{"prefix_lists", "prefix_list_ids", "source_prefix_list_id"} {
			r.PrefixLists = append(r.PrefixLists, toStringList(m[k])...)
		}
		sg.Ingress = append(sg.Ingress, r)
	}
	return sg, true
}

func (idx *netIndex) frontends(n *Node) []reach.Frontend {
	g := idx.g
	var out []reach.Frontend
	for _, e := range g.In(n.ID) {
		if e.Kind != EdgeAllowsTrafficTo || e.Attr["listener_port"] == nil {
			continue
		}
		lbN, ok := g.Node(e.From)
		if !ok || idx.kindOf(lbN, nil) != reach.KindLoadBalancer {
			continue
		}
		var lbEdge *Edge
		for _, ie := range g.In(lbN.ID) {
			if ie.From == InternetNodeID && ie.Kind == EdgeExposes {
				lbEdge = ie
			}
		}
		lbT := idx.target(lbN, lbEdge, false)
		tp := firstInt(e.Attr, "target_port")
		pres := false
		if b := boolPtr(e.Attr["preserve_client_ip"]); b != nil {
			pres = *b
		}
		out = append(out, reach.Frontend{
			LB:          &lbT,
			Listener:    reach.Listener{ID: firstStr(e.Attr, "listener_arn", "listener"), Protocol: firstStr(e.Attr, "listener_protocol"), Port: firstInt(e.Attr, "listener_port")},
			TargetGroup: reach.TargetGroup{ID: firstStr(e.Attr, "target_group"), Protocol: firstStr(e.Attr, "target_group_protocol"), Port: tp, PreserveClientIP: pres},
			TargetPort:  tp,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LB.ID != out[j].LB.ID {
			return out[i].LB.ID < out[j].LB.ID
		}
		return out[i].Listener.Port < out[j].Listener.Port
	})
	return out
}

// withCoverage appends the account's network-collection gaps to an unknown verdict.
func (idx *netIndex) withCoverage(n *Node, r reach.Result) reach.Result {
	if r.Status != reach.StatusUnknown || n.Account == "" {
		return r
	}
	acct, ok := idx.g.Node(accountNodeID(n.Provider, n.Account))
	if !ok {
		return r
	}
	cov, _ := acct.Attributes[AttrReachCoverage].(map[string]any)
	var gaps []string
	for _, k := range sortedMapKeys(cov) {
		if s, _ := cov[k].(string); s != "" && s != "collected" {
			gaps = append(gaps, k+"="+s)
		}
	}
	if len(gaps) > 0 {
		r.Unknown = append(r.Unknown, reach.Hop{Kind: reach.HopModel, ID: acct.ID, Because: "network collection incomplete: " + strings.Join(gaps, ", ")})
	}
	return r
}

// ---------------------------------------------------------------- attribute decoding

func toMapList(v any) []map[string]any {
	switch x := v.(type) {
	case []map[string]any:
		return x
	case []any:
		var out []map[string]any
		for _, i := range x {
			if m, ok := i.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64, int, int32, int64:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func firstInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := m[k].(type) {
		case int:
			return v
		case int32:
			return int(v)
		case int64:
			return int(v)
		case float64:
			return int(v)
		case json.Number:
			n, _ := v.Int64()
			return int(n)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 0
}

// ipv6Addrs reads the target's IPv6 addresses (ipv6_addresses list or ipv6_address string);
// nil when the attribute is absent (not collected).
func ipv6Addrs(a map[string]any) []string {
	for _, k := range []string{"ipv6_addresses", "ipv6_address"} {
		v, ok := a[k]
		if !ok {
			continue
		}
		if s, isStr := v.(string); isStr {
			if s == "" {
				return []string{}
			}
			return []string{s}
		}
		l := toStringList(v)
		if l == nil {
			l = []string{}
		}
		return l
	}
	return nil
}
