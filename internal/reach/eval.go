package reach

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Reachable evaluates whether a host on the internet can open a connection to t on port.
// port.Number 0 evaluates every candidate port (security-group rules, listener target ports,
// the exposure's ports) and returns the best verdict: reachable (widest first), then unknown,
// then blocked with the blockers of every port.
func Reachable(t Target, from Endpoint, port Port) Result {
	if port.Number != 0 {
		return evaluate(t, from, port)
	}
	cands := candidatePorts(t)
	if len(cands) == 0 {
		return evaluate(t, from, port)
	}
	results := make([]Result, 0, len(cands))
	for _, p := range cands {
		results = append(results, evaluate(t, from, p))
	}
	return best(results)
}

// ---------------------------------------------------------------- port helpers

func normProto(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "-1", "all", "any", "*":
		return "-1"
	case "6", "tcp", "http", "https", "tls":
		return "tcp"
	case "17", "udp", "tcp_udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "58", "icmpv6":
		return "icmpv6"
	}
	return strings.ToLower(p)
}

// reqProto is the requested protocol ("tcp" when not given).
func reqProto(p Port) string {
	if pr := normProto(p.Protocol); pr != "-1" {
		return pr
	}
	return "tcp"
}

func hasPorts(proto string) bool { return proto == "tcp" || proto == "udp" }

// ruleMatches reports whether a rule (protocol, from, to) applies to port p. An unknown port
// (Number 0) matches only rules that cover every port.
func ruleMatches(proto string, from, to int, p Port) bool {
	rp := normProto(proto)
	if rp == "-1" {
		return true
	}
	if rp != reqProto(p) {
		return false
	}
	if !hasPorts(rp) {
		return true
	}
	// Only protocol -1, from -1 or a 0-65535 range covers every port: tcp 0-0 is port 0
	// literally (verify-4 R28).
	allPorts := from == -1 || (from <= 0 && to >= 65535)
	if p.Number == 0 {
		return allPorts
	}
	return allPorts || (p.Number >= from && p.Number <= to)
}

func portSpec(proto string, from, to int) string {
	rp := normProto(proto)
	switch {
	case rp == "-1":
		return "all traffic"
	case !hasPorts(rp):
		return rp
	case from == -1 || (from <= 0 && to >= 65535):
		return "all/" + rp
	case from == to:
		return fmt.Sprintf("%d/%s", from, rp)
	}
	return fmt.Sprintf("%d-%d/%s", from, to, rp)
}

// candidatePorts lists the ports worth evaluating when the caller did not name one.
func candidatePorts(t Target) []Port {
	var out []Port
	seen := map[Port]bool{}
	add := func(p Port) {
		p.Protocol = reqProto(p)
		if p.Number > 0 && p.Number <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	switch t.Kind {
	case KindFunctionURL, KindAPIGateway, KindEKSEndpoint:
		add(Port{"tcp", 443})
		return out
	case KindServiceEndpoint:
		add(Port{"tcp", 443})
		return out
	}
	pub := publicSpace()
	for _, sg := range t.SecurityGroups {
		for _, r := range sg.Ingress {
			if pub.intersect(setOf(r.Sources...)).empty() && len(prefixListsOf(r)) == 0 {
				continue
			}
			rp := normProto(r.Protocol)
			full := rp == "-1" || (hasPorts(rp) && (r.FromPort == -1 || (r.FromPort <= 0 && r.ToPort >= 65535)))
			if full {
				proto := rp
				if proto == "-1" {
					proto = "tcp"
				}
				for _, n := range []int{22, 3389, 443, 80} {
					add(Port{proto, n})
				}
			} else if hasPorts(rp) {
				add(Port{rp, r.FromPort})
			} else {
				continue
			}
			// Ports a NACL allow rule opens inside the SG range.
			for _, sn := range t.Subnets {
				if sn.NACL == nil {
					continue
				}
				for _, nr := range sortedRules(sn.NACL.Inbound) {
					if !strings.EqualFold(nr.Action, "allow") || !hasPorts(normProto(nr.Protocol)) {
						continue
					}
					lo, hi := r.FromPort, r.ToPort
					if full {
						lo, hi = 0, 65535
					}
					if nr.ToPort >= lo && nr.FromPort <= hi {
						n := nr.FromPort
						if n < lo {
							n = lo
						}
						add(Port{normProto(nr.Protocol), n})
					}
				}
			}
		}
	}
	for _, f := range t.FrontedBy {
		add(Port{"tcp", f.TargetPort})
	}
	for _, p := range t.Ports {
		add(p)
	}
	return out
}

// ---------------------------------------------------------------- combining

var widthRank = map[string]int{"wide": 3, "narrow": 2, "trusted": 1}

func best(rs []Result) Result {
	var bestR *Result
	for i := range rs {
		r := &rs[i]
		if r.Status != StatusReachable {
			continue
		}
		if bestR == nil || widthRank[r.Width] > widthRank[bestR.Width] {
			bestR = r
		}
	}
	if bestR != nil {
		return *bestR
	}
	for i := range rs {
		if rs[i].Status == StatusUnknown {
			return rs[i]
		}
	}
	out := rs[0]
	for _, r := range rs[1:] {
		out.Blockers = dedupe(append(out.Blockers, r.Blockers...))
		out.Unknown = dedupe(append(out.Unknown, r.Unknown...))
	}
	return out
}

func dedupe(hs []Hop) []Hop {
	seen := map[string]bool{}
	var out []Hop
	for _, h := range hs {
		k := h.Kind + "\x00" + h.ID + "\x00" + h.Because
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	return out
}

// evaluate is one port: the direct path and every load-balancer front end for that port.
func evaluate(t Target, from Endpoint, p Port) Result {
	direct := evalDirect(t, from, p)
	var paths []Result
	for _, f := range t.FrontedBy {
		if f.LB == nil || (p.Number != 0 && f.TargetPort != p.Number) {
			continue
		}
		paths = append(paths, evalFrontend(t, f, from, p))
	}
	if len(paths) == 0 {
		return direct
	}
	all := append([]Result{direct}, paths...)
	if direct.Status == StatusReachable {
		return direct
	}
	var bestR *Result
	for i := range paths {
		if paths[i].Status == StatusReachable && (bestR == nil || widthRank[paths[i].Width] > widthRank[bestR.Width]) {
			bestR = &paths[i]
		}
	}
	if bestR != nil {
		return *bestR
	}
	out := Result{Status: StatusBlocked, Port: direct.Port, Confidence: confVerified, Width: direct.Width}
	for _, r := range all {
		out.Blockers = dedupe(append(out.Blockers, r.Blockers...))
		out.Unknown = dedupe(append(out.Unknown, r.Unknown...))
		if r.Status == StatusUnknown {
			out.Status = StatusUnknown
		}
	}
	if out.Status == StatusUnknown {
		out.Confidence = confHint
	} else {
		out.Confidence = blockerConfidence(out.Blockers)
	}
	return out
}

func blockerConfidence(bs []Hop) string {
	for _, b := range bs {
		if !b.inferred {
			return confVerified
		}
	}
	if len(bs) == 0 {
		return confHint
	}
	return confInferred
}

func pathConfidence(hs []Hop) string {
	for _, h := range hs {
		if h.inferred {
			return confInferred
		}
	}
	return confVerified
}

// ---------------------------------------------------------------- layers

// layer is one filter over the source set.
type layer struct {
	allow    ipset // sources it definitely lets through
	maybe    ipset // sources whose fate depends on something not modelled / not collected
	whole    bool  // the layer was not evaluated at all (data missing)
	path     []Hop
	blockers []Hop // stated when the layer lets nothing through
	unknown  []Hop
}

func (l layer) pass(s ipset) (def, maybe ipset) {
	if l.whole {
		return s, s
	}
	return s.intersect(l.allow), s.intersect(l.allow.union(l.maybe))
}

func unknownLayer(kind, id, because string) layer {
	return layer{whole: true, unknown: []Hop{{Kind: kind, ID: id, Because: because}}}
}

// sgLayer computes the internet sources the security groups (or the exposure's sources) admit.
func sgLayer(t Target, p Port) (layer, string) {
	pub := publicSpace()
	if t.SecurityGroups != nil {
		if len(t.SecurityGroups) == 0 && t.Kind == KindLoadBalancer && strings.EqualFold(t.LBType, "network") {
			return layer{allow: pub, path: []Hop{{Kind: HopSecurityGroup, ID: t.ID, Because: fmt.Sprintf("network load balancer %s has no security groups (all listener traffic passes)", t.ID)}}}, ""
		}
		l := layer{}
		var ids, private []string
		for _, sg := range t.SecurityGroups {
			ids = append(ids, sg.ID)
			for _, r := range sg.Ingress {
				if !ruleMatches(r.Protocol, r.FromPort, r.ToPort, p) {
					continue
				}
				if pls := prefixListsOf(r); len(pls) > 0 {
					// A managed prefix list can hold public CIDRs (the CloudFront origin-facing
					// list does); v1 does not expand it, so its sources are possible, not definite.
					l.maybe = l.maybe.union(pub)
					l.unknown = append(l.unknown, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from prefix list %s (prefix-list entries are not expanded in v1)", sg.ID, portSpec(r.Protocol, r.FromPort, r.ToPort), strings.Join(pls, ", "))})
				}
				s := setOf(r.Sources...)
				ps := pub.intersect(s)
				if ps.empty() {
					for _, src := range r.Sources {
						if _, ok := parseCIDR(src); ok {
							private = append(private, src)
						}
					}
					continue
				}
				l.allow = l.allow.union(ps)
				var shown []string
				for _, src := range r.Sources {
					if !pub.intersect(setOf(src)).empty() {
						shown = append(shown, src)
					}
				}
				l.path = append(l.path, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from %s", sg.ID, portSpec(r.Protocol, r.FromPort, r.ToPort), strings.Join(shown, ", "))})
			}
		}
		if l.allow.empty() && l.maybe.empty() {
			why := fmt.Sprintf("security groups %s admit no internet source on %s", strings.Join(ids, ", "), p)
			width := ""
			if len(private) > 0 {
				why += " (only private sources: " + strings.Join(uniq(private), ", ") + ")"
				width = "private"
			}
			if len(ids) == 0 {
				why = fmt.Sprintf("no security group of %s admits %s", t.ID, p)
			}
			l.blockers = []Hop{{Kind: HopSecurityGroup, ID: strings.Join(ids, ","), Because: why}}
			return l, width
		}
		return l, ""
	}
	if t.Sources != nil {
		s := setOf(t.Sources...)
		ps := pub.intersect(s)
		if ps.empty() {
			return layer{blockers: []Hop{{Kind: HopSecurityGroup, ID: t.ID, inferred: true,
				Because: fmt.Sprintf("exposure sources %s are private or non-routable (no internet source)", strings.Join(t.Sources, ", "))}}}, "private"
		}
		return layer{allow: ps, path: []Hop{{Kind: HopSecurityGroup, ID: t.ID, inferred: true,
			Because: fmt.Sprintf("exposure sources %s (security group rules not collected; from the exposure edge)", strings.Join(t.Sources, ", "))}}}, ""
	}
	l := unknownLayer(HopSecurityGroup, t.ID, fmt.Sprintf("security group rules for %s not collected", t.ID))
	l.allow = pub
	return l, ""
}

type parsedRoute struct {
	r    Route
	pfx  netip.Prefix
	set  ipset
	idx  int
	bits int
}

// routeLayer: longest-prefix match of the sources against the route table; only an active
// internet-gateway route carries inbound internet traffic.
func routeLayer(sn Subnet, src ipset) layer {
	if sn.RouteTable == nil {
		if sn.IGWRoute != nil {
			if *sn.IGWRoute {
				return layer{allow: allAddrs, path: []Hop{{Kind: HopRoute, ID: sn.ID, inferred: true, Because: fmt.Sprintf("subnet %s has an internet-gateway route (internet_gateway_route=true)", sn.ID)}}}
			}
			return layer{blockers: []Hop{{Kind: HopRoute, ID: sn.ID, inferred: true, Because: fmt.Sprintf("subnet %s has no internet-gateway route (internet_gateway_route=false)", sn.ID)}}}
		}
		return unknownLayer(HopRoute, sn.ID, fmt.Sprintf("route table for %s not collected", sn.ID))
	}
	rt := sn.RouteTable
	var prs []parsedRoute
	var plIGW []Route
	for i, r := range rt.Routes {
		p, ok := parseCIDR(r.Destination)
		if !ok {
			// Prefix-list destinations are not expanded in v1. One that sends traffic to an
			// internet gateway may cover any source the CIDR routes do not carry to an IGW, so
			// those sources become unknown (verify-4 R14). Gateway-endpoint lists (→ vpce-)
			// carry AWS service ranges only and other targets do not open an inbound path.
			if strings.HasPrefix(strings.ToLower(r.Destination), "pl-") && strings.HasPrefix(strings.ToLower(r.Target), "igw-") && !strings.EqualFold(r.State, "blackhole") {
				plIGW = append(plIGW, r)
			}
			continue
		}
		prs = append(prs, parsedRoute{r: r, pfx: p, set: setOf(p.String()), idx: i, bits: p.Bits()})
	}
	sort.SliceStable(prs, func(i, j int) bool { return prs[i].bits > prs[j].bits })
	l := layer{}
	remaining := src
	if remaining.empty() {
		remaining = publicSpace()
	}
	var denies []Hop
	for _, pr := range prs {
		m := remaining.intersect(pr.set)
		if m.empty() {
			continue
		}
		remaining = remaining.subtract(m)
		tgt := pr.r.Target
		lt := strings.ToLower(tgt)
		switch {
		case strings.EqualFold(pr.r.State, "blackhole"):
			denies = append(denies, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s route %s → %s is a blackhole", rt.ID, pr.r.Destination, tgt)})
		case strings.HasPrefix(lt, "igw-"):
			l.allow = l.allow.union(m)
			l.path = append(l.path, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s sends %s to internet gateway %s", rt.ID, pr.r.Destination, tgt)})
		case strings.HasPrefix(lt, "nat-"):
			denies = append(denies, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s sends %s to NAT gateway %s (outbound only: no inbound internet path)", rt.ID, pr.r.Destination, tgt)})
		case strings.HasPrefix(lt, "eigw-"):
			denies = append(denies, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s sends %s to egress-only internet gateway %s (outbound only: no inbound internet path)", rt.ID, pr.r.Destination, tgt)})
		case lt == "local":
			denies = append(denies, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s keeps %s local to the VPC", rt.ID, pr.r.Destination)})
		default:
			l.maybe = l.maybe.union(m)
			l.unknown = append(l.unknown, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s sends %s to %s (transit gateway, peering, VPN and PrivateLink are not modelled in v1)", rt.ID, pr.r.Destination, tgt)})
		}
	}
	if len(plIGW) > 0 {
		// Every source not already carried to an IGW by a CIDR route may match the list.
		undecided := src
		if undecided.empty() {
			undecided = publicSpace()
		}
		undecided = undecided.subtract(l.allow)
		if !undecided.empty() {
			l.maybe = l.maybe.union(undecided)
			for _, r := range plIGW {
				l.unknown = append(l.unknown, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s sends prefix list %s to internet gateway %s (prefix-list entries are not expanded in v1)", rt.ID, r.Destination, r.Target)})
			}
			// The blockers stay as evidence only if the list turns out not to cover the source.
			denies = nil
			remaining = ipset{}
		}
	}
	if !remaining.empty() {
		var rs []string
		for _, r := range rt.Routes {
			rs = append(rs, r.Destination+" → "+r.Target)
		}
		denies = append(denies, Hop{Kind: HopRoute, ID: rt.ID, Because: fmt.Sprintf("route table %s has no route to an internet gateway (routes: %s)", rt.ID, strings.Join(rs, ", "))})
	}
	l.blockers = denies
	return l
}

func sortedRules(rs []NACLRule) []NACLRule {
	out := append([]NACLRule(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

// naclFirstMatch applies ordered rules to set for port p: lowest number first, first match wins,
// the implicit "*" rule denies the rest. It returns the allowed subset and the hops.
func naclFirstMatch(rules []NACLRule, set ipset, p Port) (allowed ipset, allows, denies []Hop, matched []NACLRule) {
	remaining := set
	for _, r := range sortedRules(rules) {
		if r.Number >= 32767 {
			continue // the "*" rule: the implicit deny below
		}
		if !ruleMatches(r.Protocol, r.FromPort, r.ToPort, p) {
			continue
		}
		m := remaining.intersect(setOf(r.CIDR))
		if m.empty() {
			continue
		}
		remaining = remaining.subtract(m)
		matched = append(matched, r)
		if strings.EqualFold(r.Action, "allow") {
			allowed = allowed.union(m)
			allows = append(allows, Hop{Kind: HopNACLInbound, Because: fmt.Sprintf("rule %d allows %s from %s", r.Number, p, r.CIDR)})
		} else {
			denies = append(denies, Hop{Kind: HopNACLInbound, Because: fmt.Sprintf("rule %d denies %s from %s", r.Number, p, r.CIDR)})
		}
		if remaining.empty() {
			break
		}
	}
	return allowed, allows, denies, matched
}

func naclInLayer(sn Subnet, p Port) layer {
	if sn.NACL == nil {
		return unknownLayer(HopNACLInbound, sn.ID, fmt.Sprintf("network ACL for %s not collected", sn.ID))
	}
	n := sn.NACL
	allowed, allows, denies, _ := naclFirstMatch(n.Inbound, allAddrs, p)
	l := layer{allow: allowed}
	for _, h := range allows {
		l.path = append(l.path, Hop{Kind: HopNACLInbound, ID: n.ID, Because: "NACL " + n.ID + " " + h.Because})
	}
	for _, h := range denies {
		l.blockers = append(l.blockers, Hop{Kind: HopNACLInbound, ID: n.ID, Because: "NACL " + n.ID + " " + h.Because})
	}
	if len(denies) == 0 {
		l.blockers = append(l.blockers, Hop{Kind: HopNACLInbound, ID: n.ID, Because: fmt.Sprintf("NACL %s has no rule allowing %s (default rule * denies)", n.ID, p)})
	}
	return l
}

// naclOutLayer checks the stateless return path: outbound rules must allow the reply to the
// client's ephemeral port (1024-65535) for the surviving sources.
func naclOutLayer(sn Subnet, p Port) layer {
	if sn.NACL == nil {
		return layer{whole: true} // already reported by the inbound layer
	}
	n := sn.NACL
	if n.Outbound == nil {
		return unknownLayer(HopNACLOutbound, n.ID, fmt.Sprintf("outbound rules of NACL %s not collected (return traffic not evaluated)", n.ID))
	}
	proto := reqProto(p)
	l := layer{}
	addAllow := func(r NACLRule) {
		var why string
		if normProto(r.Protocol) == "-1" {
			why = fmt.Sprintf("NACL %s outbound rule %d allows return traffic (all traffic to %s)", n.ID, r.Number, r.CIDR)
		} else {
			why = fmt.Sprintf("NACL %s outbound rule %d allows return traffic to %s", n.ID, r.Number, portSpec(r.Protocol, r.FromPort, r.ToPort))
		}
		l.path = append(l.path, Hop{Kind: HopNACLOutbound, ID: n.ID, Because: why})
	}
	if !hasPorts(proto) {
		allowed, _, _, matched := naclFirstMatch(n.Outbound, allAddrs, Port{Protocol: proto})
		l.allow = allowed
		for _, r := range matched {
			if strings.EqualFold(r.Action, "allow") {
				addAllow(r)
			}
		}
	} else {
		samples := map[int]bool{1024: true, 65535: true}
		for _, r := range n.Outbound {
			for _, q := range []int{r.FromPort, r.ToPort, r.FromPort - 1, r.ToPort + 1} {
				if q >= 1024 && q <= 65535 {
					samples[q] = true
				}
			}
		}
		var qs []int
		for q := range samples {
			qs = append(qs, q)
		}
		sort.Ints(qs)
		seen := map[int]bool{}
		for _, q := range qs {
			allowed, _, _, matched := naclFirstMatch(n.Outbound, allAddrs, Port{Protocol: proto, Number: q})
			l.allow = l.allow.union(allowed)
			for _, r := range matched {
				if strings.EqualFold(r.Action, "allow") && !seen[r.Number] && !allowed.empty() {
					seen[r.Number] = true
					addAllow(r)
				}
			}
		}
	}
	l.blockers = []Hop{{Kind: HopNACLOutbound, ID: n.ID, Because: fmt.Sprintf("NACL %s outbound rules deny return traffic to ephemeral ports 1024-65535/%s", n.ID, proto)}}
	return l
}

// ---------------------------------------------------------------- direct path

type subnetEval struct {
	status   Status
	def      ipset
	maybe    ipset
	path     []Hop
	blockers []Hop
	unknown  []Hop
}

// evalSubnet runs route -> NACL in -> (SG, already applied in s) -> NACL out over s.
func evalSubnet(sn Subnet, s ipset, p Port) subnetEval {
	layers := []layer{routeLayer(sn, s), naclInLayer(sn, p), naclOutLayer(sn, p)}
	def, maybe := s, s
	whole := false
	out := subnetEval{}
	// base is what a layer is judged against on its own: when the security groups admit no
	// internet source (s empty), an open route / NACL is not a blocker (verify-4 evidence).
	base := s
	if base.empty() {
		base = publicSpace()
	}
	for _, l := range layers {
		prevMaybe := maybe
		def, _ = l.pass(def)
		_, maybe = l.pass(maybe)
		if l.whole {
			whole = true
		}
		out.path = append(out.path, l.path...)
		out.unknown = append(out.unknown, l.unknown...)
		alone := base.intersect(l.allow.union(l.maybe))
		if !l.whole && alone.empty() {
			out.blockers = append(out.blockers, l.blockers...)
		} else if !l.whole && maybe.empty() && !prevMaybe.empty() {
			out.blockers = append(out.blockers, l.blockers...)
		}
	}
	out.def, out.maybe = def, maybe
	switch {
	case maybe.empty():
		out.status = StatusBlocked
	case !def.empty() && !whole:
		// Sources through an unmodelled route (tgw-, pcx-) only widen the verdict; they are
		// evidence only when they decide it.
		out.status, out.unknown = StatusReachable, nil
	default:
		out.status = StatusUnknown
	}
	return out
}

func evalDirect(t Target, from Endpoint, p Port) Result {
	switch t.Kind {
	case KindFunctionURL, KindAPIGateway, KindEKSEndpoint, KindServiceEndpoint:
		return evalManaged(t, from, p)
	case KindInstance, KindNetworkIface, KindDBInstance, KindLoadBalancer, KindVM:
	default:
		return Result{Status: StatusUnknown, Port: p, Confidence: confHint,
			Unknown: []Hop{{Kind: HopModel, ID: t.ID, Because: fmt.Sprintf("no reachability model for kind %q (%s)", t.Kind, t.ID)}}}
	}
	if p.Protocol == "" {
		p.Protocol = "tcp"
	}
	r := Result{Port: p}
	var addrHops, addrBlock, addrUnknown []Hop
	var noIPv4 *Hop // set when the target has no public IPv4: only IPv6 sources can reach it
	switch t.Kind {
	case KindDBInstance:
		switch {
		case t.PubliclyAccessible == nil:
			addrUnknown = append(addrUnknown, Hop{Kind: HopRDSPublic, ID: t.ID, Because: fmt.Sprintf("PubliclyAccessible of %s not known", t.ID)})
		case !*t.PubliclyAccessible:
			addrBlock = append(addrBlock, Hop{Kind: HopRDSPublic, ID: t.ID, Because: "RDS PubliclyAccessible=false (the endpoint resolves to a private IP only)"})
		default:
			addrHops = append(addrHops, Hop{Kind: HopRDSPublic, ID: t.ID, Because: "RDS PubliclyAccessible=true (the endpoint resolves to a public IP)"})
		}
	case KindLoadBalancer:
		switch strings.ToLower(t.Scheme) {
		case "internet-facing":
			addrHops = append(addrHops, Hop{Kind: HopLoadBalancer, ID: t.ID, Because: fmt.Sprintf("load balancer %s is internet-facing", t.ID)})
		case "internal":
			addrBlock = append(addrBlock, Hop{Kind: HopLoadBalancer, ID: t.ID, Because: fmt.Sprintf("load balancer %s scheme is internal (private IPs only)", t.ID)})
		default:
			addrUnknown = append(addrUnknown, Hop{Kind: HopLoadBalancer, ID: t.ID, Because: fmt.Sprintf("scheme of load balancer %s not known", t.ID)})
		}
	default:
		switch {
		case t.PublicIP == nil:
			addrUnknown = append(addrUnknown, Hop{Kind: HopPublicIP, ID: t.ID, Because: fmt.Sprintf("public address of %s not known", t.ID)})
		case !*t.PublicIP:
			noIPv4 = &Hop{Kind: HopPublicIP, ID: t.ID, Because: fmt.Sprintf("%s has no public IPv4 address or Elastic IP association", t.ID)}
		case t.PublicAddress != "":
			addrHops = append(addrHops, Hop{Kind: HopPublicIP, ID: t.ID, Because: fmt.Sprintf("public IPv4 %s is associated", t.PublicAddress)})
		default:
			addrHops = append(addrHops, Hop{Kind: HopPublicIP, ID: t.ID, Because: "a public IPv4 address (public IP or Elastic IP) is associated"})
		}
	}

	sg, sgWidth := sgLayer(t, p)
	// sDef are the sources the security groups definitely admit; s adds the possible ones
	// (prefix-list sources, not expanded in v1).
	sDef := sg.allow
	s := sg.allow.union(sg.maybe)
	if noIPv4 != nil {
		// No public IPv4: an IPv6 address is globally routable, so IPv6 sources may still
		// reach the target through an IGW ::/0 route (verify-4 R24).
		v6 := s.intersect(ipv6Space)
		switch {
		case v6.empty() || (t.IPv6Addresses != nil && len(t.IPv6Addresses) == 0):
			addrBlock = append(addrBlock, *noIPv4)
		case len(t.IPv6Addresses) > 0:
			s, sDef = v6, sDef.intersect(ipv6Space)
			addrHops = append(addrHops, Hop{Kind: HopPublicIP, ID: t.ID, Because: fmt.Sprintf("no public IPv4, but IPv6 address %s is assigned (globally routable)", t.IPv6Addresses[0])})
		default:
			s, sDef = v6, sDef.intersect(ipv6Space)
			addrUnknown = append(addrUnknown, Hop{Kind: HopPublicIP, ID: t.ID, Because: fmt.Sprintf("%s has no public IPv4 address; its IPv6 addresses were not collected and the security groups admit IPv6 internet sources", t.ID)})
		}
	}
	sgBlocked := !sg.whole && s.empty()

	var sub subnetEval
	switch {
	case t.Kind == KindVM:
		prov := t.Provider
		if prov == "" {
			prov = "this provider"
		}
		sub = subnetEval{status: StatusUnknown, def: s, maybe: s,
			unknown: []Hop{{Kind: HopRoute, ID: t.ID, Because: fmt.Sprintf("routes are not modelled for %s in v1 (NSG/firewall only)", prov)}}}
		if s.empty() {
			sub.status = StatusBlocked
		}
	case t.Subnets == nil:
		sub = subnetEval{status: StatusUnknown, def: s, maybe: s,
			unknown: []Hop{{Kind: HopSubnet, ID: t.ID, Because: fmt.Sprintf("subnet of %s not known: route table and network ACL not evaluated", t.ID)}}}
		if s.empty() {
			sub.status = StatusBlocked
		}
	default:
		sub = combineSubnets(t, s, p)
	}
	// Sources only a prefix list admits are never definite.
	if !sg.whole {
		sub.def = sub.def.intersect(sDef)
		if sub.status == StatusReachable && sub.def.empty() {
			sub.status = StatusUnknown
		}
	}

	// Assemble evidence in network order: address, route, NACL in, SG, NACL out.
	var routeHops, naclIn, naclOut []Hop
	for _, h := range sub.path {
		switch h.Kind {
		case HopNACLInbound:
			naclIn = append(naclIn, h)
		case HopNACLOutbound:
			naclOut = append(naclOut, h)
		default:
			routeHops = append(routeHops, h)
		}
	}
	r.Path = dedupe(concat(addrHops, routeHops, naclIn, sg.path, naclOut))
	r.Unknown = dedupe(concat(addrUnknown, sg.unknown, sub.unknown))
	blocked := len(addrBlock) > 0 || sgBlocked || sub.status == StatusBlocked
	if blocked {
		r.Status = StatusBlocked
		r.Blockers = dedupe(concat(addrBlock, sg.blockers, sub.blockers))
		if noIPv4 != nil && len(addrBlock) == 0 {
			r.Blockers = dedupe(concat([]Hop{*noIPv4}, r.Blockers))
		}
		if len(r.Blockers) == 0 {
			r.Blockers = []Hop{{Kind: HopModel, ID: t.ID, Because: "no internet source survives every layer"}}
		}
		r.Confidence = blockerConfidence(r.Blockers)
		r.Width = sgWidth
		return r
	}
	if len(addrUnknown) > 0 || sg.whole || sub.status == StatusUnknown {
		r.Status = StatusUnknown
		r.Confidence = confHint
		if len(r.Unknown) == 0 {
			r.Unknown = []Hop{{Kind: HopModel, ID: t.ID, Because: "a layer could not be evaluated"}}
		}
		r.Width, r.Sources = widthOf(sub.maybe, from.TrustedCIDRs, sourceStrings(t))
		return r
	}
	r.Status, r.Reachable = StatusReachable, true
	r.Unknown = nil
	r.Width, r.Sources = widthOf(sub.def, from.TrustedCIDRs, sourceStrings(t))
	r.Confidence = pathConfidence(r.Path)
	return r
}

// combineSubnets: an instance / ENI uses its subnet; a load balancer is reachable through any
// enabled subnet (one node per zone); an RDS instance sits in one subnet of its group, so the
// group decides only when every subnet agrees.
func combineSubnets(t Target, s ipset, p Port) subnetEval {
	subnets := t.Subnets
	if t.Kind == KindInstance || t.Kind == KindNetworkIface {
		subnets = subnets[:1]
	}
	if len(subnets) == 0 {
		return subnetEval{status: StatusUnknown, def: s, maybe: s,
			unknown: []Hop{{Kind: HopSubnet, ID: t.ID, Because: fmt.Sprintf("subnet of %s not known: route table and network ACL not evaluated", t.ID)}}}
	}
	var evs []subnetEval
	for _, sn := range subnets {
		evs = append(evs, evalSubnet(sn, s, p))
	}
	if len(evs) == 1 {
		return evs[0]
	}
	out := subnetEval{}
	nReach, nBlock := 0, 0
	for _, e := range evs {
		switch e.status {
		case StatusReachable:
			nReach++
			out.def = out.def.union(e.def)
			out.path = append(out.path, e.path...)
		case StatusBlocked:
			nBlock++
			out.blockers = append(out.blockers, e.blockers...)
		}
		out.maybe = out.maybe.union(e.maybe)
		out.unknown = append(out.unknown, e.unknown...)
	}
	switch {
	case t.Kind == KindLoadBalancer && nReach > 0:
		out.status, out.unknown, out.blockers = StatusReachable, nil, nil
	case t.Kind == KindLoadBalancer && nBlock == len(evs):
		out.status = StatusBlocked
	case nReach == len(evs):
		out.status, out.unknown = StatusReachable, nil
	case nBlock == len(evs):
		out.status = StatusBlocked
	case nReach > 0 && nBlock > 0:
		out.status = StatusUnknown
		out.def = ipset{}
		out.unknown = append(out.unknown, Hop{Kind: HopSubnet, ID: t.ID, Because: "DB subnet group mixes subnets with and without an internet path; the instance's subnet decides"})
		out.blockers = nil
	default:
		out.status = StatusUnknown
		out.blockers = nil
	}
	return out
}

func concat(hs ...[]Hop) []Hop {
	var out []Hop
	for _, h := range hs {
		out = append(out, h...)
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sourceStrings are the public sources as the rules / edge spell them (for Result.Sources).
func sourceStrings(t Target) []string {
	var out []string
	pub := publicSpace()
	for _, sg := range t.SecurityGroups {
		for _, r := range sg.Ingress {
			for _, s := range r.Sources {
				if !pub.intersect(setOf(s)).empty() {
					out = append(out, s)
				}
			}
		}
	}
	if t.SecurityGroups == nil {
		for _, s := range t.Sources {
			if !pub.intersect(setOf(s)).empty() {
				out = append(out, s)
			}
		}
	}
	return out
}

// widthOf classifies the surviving sources: wide when they cover at least half of the IPv4
// space (or an IPv6 /8 or larger), trusted when every one lies inside the trusted CIDRs,
// narrow otherwise.
func widthOf(def ipset, trusted, spelled []string) (string, []string) {
	if def.empty() {
		return "", nil
	}
	srcs := def.cidrs()
	// Report the rules' own spelling when nothing narrowed them (0.0.0.0/0, not 30 CIDRs).
	if len(spelled) > 0 {
		var cands []string
		for _, s := range spelled {
			if !def.intersect(setOf(s)).empty() {
				cands = append(cands, s)
			}
		}
		if len(cands) > 0 && publicSpace().intersect(setOf(cands...)).equal(def) {
			srcs = uniq(cands)
			sort.Strings(srcs)
		}
	}
	if len(srcs) > 32 {
		srcs = append(srcs[:32], fmt.Sprintf("…(+%d more)", len(srcs)-32))
	}
	wide := def.v4size() >= 1<<31
	for _, c := range def.cidrs() {
		if p, ok := parseCIDR(c); ok && p.Addr().Is6() && p.Bits() <= 8 {
			wide = true
		}
	}
	switch {
	case wide:
		return "wide", srcs
	case len(trusted) > 0 && def.subtract(setOf(trusted...)).empty():
		return "trusted", srcs
	}
	return "narrow", srcs
}

// ---------------------------------------------------------------- load-balancer path

var vpcPrivate = setOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")

func evalFrontend(t Target, f Frontend, from Endpoint, p Port) Result {
	lb := *f.LB
	lb.Kind = KindLoadBalancer
	lb.FrontedBy = nil
	lp := Port{Protocol: "tcp", Number: f.Listener.Port}
	if normProto(f.Listener.Protocol) == "udp" {
		lp.Protocol = "udp"
	}
	lr := evalDirect(lb, from, lp)
	lr.Port = p
	listenerHop := Hop{Kind: HopListener, ID: f.Listener.ID, Because: fmt.Sprintf("listener %s accepts %d/%s and forwards to target group %s on port %d",
		f.Listener.ID, f.Listener.Port, strings.ToUpper(f.Listener.Protocol), f.TargetGroup.ID, f.TargetPort)}
	if lr.Status != StatusReachable {
		return lr
	}
	def := setOf(lr.Sources...)
	if len(lr.Sources) == 0 || strings.HasPrefix(lr.Sources[len(lr.Sources)-1], "…") {
		def = publicSpace()
	}
	def = def.intersect(publicSpace())
	r := Result{Port: p}
	var hops []Hop
	preserve := strings.EqualFold(lb.LBType, "network") && f.TargetGroup.PreserveClientIP
	if t.SecurityGroups == nil {
		r.Status, r.Confidence = StatusUnknown, confHint
		r.Path = append(lr.Path, listenerHop)
		r.Unknown = []Hop{{Kind: HopSecurityGroup, ID: t.ID, Because: fmt.Sprintf("security group rules for %s not collected (load balancer → target hop)", t.ID)}}
		return r
	}
	lbSGs := map[string]bool{}
	for _, sg := range lb.SecurityGroups {
		lbSGs[sg.ID] = true
	}
	admitted := ipset{}
	ok := false
	var plHops []Hop
	for _, sg := range t.SecurityGroups {
		for _, rule := range sg.Ingress {
			if !ruleMatches(rule.Protocol, rule.FromPort, rule.ToPort, p) {
				continue
			}
			if pls := prefixListsOf(rule); len(pls) > 0 {
				plHops = append(plHops, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from prefix list %s (prefix-list entries are not expanded in v1)", sg.ID, p, strings.Join(pls, ", "))})
			}
			if preserve {
				m := def.intersect(setOf(rule.Sources...))
				if !m.empty() {
					admitted = admitted.union(m)
					hops = append(hops, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from %s (client IP preserved by network load balancer %s)", sg.ID, p, strings.Join(rule.Sources, ", "), lb.ID)})
				}
				continue
			}
			for _, g := range rule.Groups {
				if lbSGs[g] {
					ok = true
					hops = append(hops, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from the load balancer (%s)", sg.ID, p, g)})
				}
			}
			if !setOf(rule.Sources...).intersect(vpcPrivate).empty() {
				ok = true
				hops = append(hops, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from %s (covers the load balancer's VPC addresses)", sg.ID, p, strings.Join(rule.Sources, ", "))})
			} else if !setOf(rule.Sources...).empty() && setOf(rule.Sources...).intersect(publicSpace()).equal(publicSpace()) {
				ok = true
				hops = append(hops, Hop{Kind: HopSecurityGroup, ID: sg.ID, Because: fmt.Sprintf("security group %s allows %s from %s", sg.ID, p, strings.Join(rule.Sources, ", "))})
			}
		}
	}
	if preserve {
		ok = !admitted.empty()
		def = admitted
	}
	if !ok && len(plHops) > 0 {
		r.Status, r.Confidence = StatusUnknown, confHint
		r.Path = append(lr.Path, listenerHop)
		r.Unknown = plHops
		return r
	}
	if !ok {
		r.Status = StatusBlocked
		r.Path = append(lr.Path, listenerHop)
		r.Blockers = []Hop{{Kind: HopSecurityGroup, ID: t.ID, Because: fmt.Sprintf("security groups of %s admit nothing on %s from load balancer %s", t.ID, p, lb.ID)}}
		r.Confidence = confVerified
		return r
	}
	// Target subnet NACL: traffic arrives from the load balancer's private addresses (or the
	// client's, when an NLB preserves it).
	src := vpcPrivate
	if preserve {
		src = def
	}
	var naclHops, unknown []Hop
	if len(t.Subnets) > 0 {
		sn := t.Subnets[0]
		in, out := naclInLayer(sn, p), naclOutLayer(sn, p)
		d1, _ := in.pass(src)
		d2, _ := out.pass(d1)
		if in.whole || out.whole {
			unknown = append(unknown, in.unknown...)
			unknown = append(unknown, out.unknown...)
		} else if d2.empty() {
			r.Status = StatusBlocked
			r.Path = append(lr.Path, listenerHop)
			r.Blockers = append(in.blockers, out.blockers...)
			if d1.empty() {
				r.Blockers = in.blockers
			} else {
				r.Blockers = out.blockers
			}
			r.Confidence = confVerified
			return r
		}
		naclHops = append(append(naclHops, in.path...), out.path...)
	} else {
		unknown = append(unknown, Hop{Kind: HopSubnet, ID: t.ID, Because: fmt.Sprintf("subnet of %s not known: network ACL on the load balancer → target hop not evaluated", t.ID)})
	}
	r.Path = dedupe(concat(lr.Path, []Hop{listenerHop, {Kind: HopTargetGroup, ID: f.TargetGroup.ID, Because: fmt.Sprintf("target group %s forwards to %s on port %d", f.TargetGroup.ID, t.ID, f.TargetPort)}}, hops, naclHops))
	if len(unknown) > 0 {
		r.Status, r.Confidence, r.Unknown = StatusUnknown, confHint, unknown
		return r
	}
	r.Status, r.Reachable = StatusReachable, true
	spelled := lr.Sources
	if preserve {
		spelled = sourceStrings(t)
	}
	r.Width, r.Sources = widthOf(def, from.TrustedCIDRs, spelled)
	r.Confidence = pathConfidence(r.Path)
	return r
}

// ---------------------------------------------------------------- managed endpoints

func evalManaged(t Target, from Endpoint, p Port) Result {
	if p.Number == 0 {
		p = Port{"tcp", 443}
	}
	if p.Protocol == "" {
		p.Protocol = "tcp"
	}
	r := Result{Port: p}
	block := func(kind, why string) Result {
		r.Status, r.Confidence = StatusBlocked, confVerified
		r.Blockers = []Hop{{Kind: kind, ID: t.ID, Because: why}}
		return r
	}
	reach := func(hop Hop, sources []string) Result {
		def := publicSpace()
		spelled := []string{"0.0.0.0/0"}
		if sources != nil {
			def = def.intersect(setOf(sources...))
			spelled = sources
		}
		if def.empty() {
			r.Width = "private"
			return block(hop.Kind, fmt.Sprintf("%s admits only private sources (%s)", t.ID, strings.Join(sources, ", ")))
		}
		r.Status, r.Reachable = StatusReachable, true
		r.Path = []Hop{hop}
		r.Width, r.Sources = widthOf(def, from.TrustedCIDRs, spelled)
		r.Confidence = pathConfidence(r.Path)
		return r
	}
	switch t.Kind {
	case KindFunctionURL:
		if p.Number != 443 {
			return block(HopManagedEndpoint, fmt.Sprintf("Lambda function URLs listen on 443/tcp only, not %s", p))
		}
		auth := t.AuthType
		if auth == "" {
			auth = "unknown"
		}
		return reach(Hop{Kind: HopManagedEndpoint, ID: t.ID, Because: fmt.Sprintf("Lambda function URL is an AWS-managed public HTTPS endpoint (no VPC network layer; AuthType %s)", strings.ToUpper(auth))}, t.Sources)
	case KindAPIGateway:
		if strings.EqualFold(t.EndpointType, "PRIVATE") {
			return block(HopManagedEndpoint, "API Gateway endpoint type PRIVATE is reachable only through an interface VPC endpoint (execute-api); PrivateLink is not modelled in v1")
		}
		et := strings.ToUpper(t.EndpointType)
		if et == "" {
			et = "public"
		}
		return reach(Hop{Kind: HopManagedEndpoint, ID: t.ID, Because: fmt.Sprintf("API Gateway %s endpoint is an AWS-managed public HTTPS endpoint (no VPC network layer)", et)}, t.Sources)
	case KindEKSEndpoint:
		switch {
		case t.EndpointPublic == nil:
			r.Status, r.Confidence = StatusUnknown, confHint
			r.Unknown = []Hop{{Kind: HopEKSEndpoint, ID: t.ID, Because: fmt.Sprintf("endpoint public access of %s not known", t.ID)}}
			return r
		case !*t.EndpointPublic:
			return block(HopEKSEndpoint, "EKS cluster endpoint public access is disabled (private endpoint only)")
		}
		cidrs := t.PublicAccessCIDRs
		if len(cidrs) == 0 {
			cidrs = []string{"0.0.0.0/0"}
		}
		return reach(Hop{Kind: HopEKSEndpoint, ID: t.ID, Because: fmt.Sprintf("EKS public endpoint allows %s", strings.Join(cidrs, ", "))}, cidrs)
	}
	who := "AWS"
	if t.Provider != "" && !strings.EqualFold(t.Provider, "aws") {
		who = t.Provider
	}
	return reach(Hop{Kind: HopManagedEndpoint, ID: t.ID, Because: who + "-managed public service endpoint (no VPC network layer)"}, t.Sources)
}

// prefixListsOf is a rule's managed prefix-list sources: the PrefixLists field plus any
// "pl-…" spelled among Sources.
func prefixListsOf(r SGRule) []string {
	out := append([]string(nil), r.PrefixLists...)
	for _, s := range r.Sources {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "pl-") {
			out = append(out, s)
		}
	}
	return out
}
