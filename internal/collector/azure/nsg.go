package azure

import (
	"math/bits"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// internetSource reports whether an NSG source prefix means "anywhere on the internet".
// Service tag Internet, '*', Any and the all-zero CIDRs qualify.
func internetSource(prefix string) bool {
	return core.IsOpenCIDR(prefix)
}

func ruleFromInternet(p *armnetwork.SecurityRulePropertiesFormat) bool {
	if p == nil {
		return false
	}
	if p.SourceAddressPrefix != nil && internetSource(*p.SourceAddressPrefix) {
		return true
	}
	for _, s := range p.SourceAddressPrefixes {
		if s != nil && internetSource(*s) {
			return true
		}
	}
	return false
}

func tcpCapable(p *armnetwork.SecurityRulePropertiesFormat) bool {
	if p.Protocol == nil {
		return true
	}
	switch strings.ToLower(string(*p.Protocol)) {
	case "*", "tcp", "any":
		return true
	}
	return false
}

// portSpecs returns the destination port specs of a rule ("*", "22", "1000-2000").
func portSpecs(p *armnetwork.SecurityRulePropertiesFormat) []string {
	var out []string
	if p.DestinationPortRange != nil && *p.DestinationPortRange != "" {
		out = append(out, *p.DestinationPortRange)
	}
	for _, r := range p.DestinationPortRanges {
		if r != nil && *r != "" {
			out = append(out, *r)
		}
	}
	if len(out) == 0 {
		out = []string{"*"}
	}
	return out
}

// specCovers reports whether one port spec includes port.
func specCovers(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "*" || strings.EqualFold(spec, "any") {
		return true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		return err1 == nil && err2 == nil && port >= l && port <= h
	}
	n, err := strconv.Atoi(spec)
	return err == nil && n == port
}

func coversPort(p *armnetwork.SecurityRulePropertiesFormat, port int) bool {
	for _, s := range portSpecs(p) {
		if specCovers(s, port) {
			return true
		}
	}
	return false
}

// inboundRules returns custom + default inbound rules ordered by priority (Azure evaluates
// lowest priority number first; the first match wins).
func inboundRules(nsg *armnetwork.SecurityGroup) []*armnetwork.SecurityRulePropertiesFormat {
	if nsg == nil || nsg.Properties == nil {
		return nil
	}
	var out []*armnetwork.SecurityRulePropertiesFormat
	for _, list := range [][]*armnetwork.SecurityRule{nsg.Properties.SecurityRules, nsg.Properties.DefaultSecurityRules} {
		for _, r := range list {
			if r == nil || r.Properties == nil || r.Properties.Direction == nil || *r.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
				continue
			}
			out = append(out, r.Properties)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return i32(out[i].Priority) < i32(out[j].Priority) })
	return out
}

// InternetAllowsPort evaluates the NSG for TCP traffic from the internet to port: the first
// inbound rule (by priority) whose source covers the internet and whose ports cover the port
// decides. No matching rule means the implicit DenyAllInBound.
func InternetAllowsPort(nsg *armnetwork.SecurityGroup, port int) bool {
	for _, r := range inboundRules(nsg) {
		if !ruleFromInternet(r) || !tcpCapable(r) || !coversPort(r, port) {
			continue
		}
		return r.Access != nil && *r.Access == armnetwork.SecurityRuleAccessAllow
	}
	return false
}

// InternetOpenPorts lists the port specs of inbound Allow rules from the internet that are
// effective (not shadowed by a higher-priority internet Deny for their first port).
func InternetOpenPorts(nsg *armnetwork.SecurityGroup) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range inboundRules(nsg) {
		if !ruleFromInternet(r) || r.Access == nil || *r.Access != armnetwork.SecurityRuleAccessAllow {
			continue
		}
		for _, s := range portSpecs(r) {
			if seen[s] || !specEffective(nsg, r, s) {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// specEffective reports whether some port of spec reaches rule r (or another
// internet Allow) first in priority order, i.e. is not shadowed by an internet Deny.
func specEffective(nsg *armnetwork.SecurityGroup, r *armnetwork.SecurityRulePropertiesFormat, spec string) bool {
	for _, port := range candidatePorts(spec, nsg) {
		for _, x := range inboundRules(nsg) {
			if !ruleFromInternet(x) || !coversPort(x, port) {
				continue
			}
			if x == r || (x.Access != nil && *x.Access == armnetwork.SecurityRuleAccessAllow) {
				return true
			}
			break
		}
	}
	return false
}

// specBounds parses a port spec ("*" = 0-65535, "22", "20-30").
func specBounds(spec string) (int, int, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "*" || strings.EqualFold(spec, "any") {
		return 0, 65535, true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, e1 := strconv.Atoi(strings.TrimSpace(lo))
		h, e2 := strconv.Atoi(strings.TrimSpace(hi))
		return l, h, e1 == nil && e2 == nil && l <= h
	}
	n, err := strconv.Atoi(spec)
	return n, n, err == nil
}

// candidatePorts returns the ports of spec at which an NSG decision can change: its
// lowest port plus each inbound rule's range start and end+1 inside it (over every
// layer). Decisions are constant between consecutive candidates, so checking them
// finds any admitted port in the range, not only its lowest.
func candidatePorts(spec string, layers ...*armnetwork.SecurityGroup) []int {
	lo, hi, ok := specBounds(spec)
	if !ok {
		return nil
	}
	seen := map[int]bool{lo: true}
	out := []int{lo}
	add := func(p int) {
		if p > lo && p <= hi && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, nsg := range layers {
		for _, r := range inboundRules(nsg) {
			for _, s := range portSpecs(r) {
				if l, h, ok := specBounds(s); ok {
					add(l)
					add(h + 1)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

// AllowedInboundPorts lists port specs of every custom inbound Allow rule (any source),
// used as the ports attribute of NSG→VM allows_traffic_to edges.
func AllowedInboundPorts(nsg *armnetwork.SecurityGroup) []string {
	if nsg == nil || nsg.Properties == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range nsg.Properties.SecurityRules {
		if r == nil || r.Properties == nil || r.Properties.Direction == nil || *r.Properties.Direction != armnetwork.SecurityRuleDirectionInbound {
			continue
		}
		if r.Properties.Access == nil || *r.Properties.Access != armnetwork.SecurityRuleAccessAllow {
			continue
		}
		for _, s := range portSpecs(r.Properties) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ruleSources lists a rule's source prefixes (single + plural forms).
func ruleSources(p *armnetwork.SecurityRulePropertiesFormat) []string {
	var out []string
	if p.SourceAddressPrefix != nil && *p.SourceAddressPrefix != "" {
		out = append(out, *p.SourceAddressPrefix)
	}
	for _, s := range p.SourceAddressPrefixes {
		if s != nil && *s != "" {
			out = append(out, *s)
		}
	}
	return out
}

// sourceCovers reports whether a rule source prefix includes every address of cand
// (a public CIDR / IP). Wildcards (*, Internet, Any, 0.0.0.0/0) cover everything;
// other service tags (VirtualNetwork, AzureLoadBalancer, …) never cover internet sources.
func sourceCovers(ruleSrc, cand string) bool {
	if internetSource(ruleSrc) {
		return true
	}
	rp, ok := core.ParseSource(ruleSrc)
	if !ok {
		return false
	}
	cp, ok := core.ParseSource(cand)
	if !ok {
		return false
	}
	return rp.Addr().Is4() == cp.Addr().Is4() && rp.Bits() <= cp.Bits() && rp.Contains(cp.Addr())
}

// nsgAllows evaluates one NSG for TCP from src to port: the first inbound rule by
// priority whose source covers src and whose ports cover port decides; no match is
// the implicit deny. A nil NSG (referenced but not collected) denies.
func nsgAllows(nsg *armnetwork.SecurityGroup, src string, port int) bool {
	for _, r := range inboundRules(nsg) {
		if !tcpCapable(r) || !coversPort(r, port) {
			continue
		}
		covered := false
		for _, s := range ruleSources(r) {
			if sourceCovers(s, src) {
				covered = true
				break
			}
		}
		if !covered {
			continue
		}
		return r.Access != nil && *r.Access == armnetwork.SecurityRuleAccessAllow
	}
	return false
}

// LayeredInternetExposure evaluates traffic from the internet through every NSG in
// layers (subnet NSG and NIC NSG): a (source, port) pair is exposed only if EVERY
// layer allows it. Candidates are the public sources × port specs of each layer's
// inbound Allow rules. It returns the exposed port specs and the public sources
// (wildcards normalised to 0.0.0.0/0) that reach them.
func LayeredInternetExposure(layers []*armnetwork.SecurityGroup) (ports, sources []string) {
	if len(layers) == 0 {
		return nil, nil
	}
	type cand struct{ src, spec string }
	var cands []cand
	for _, nsg := range layers {
		for _, r := range inboundRules(nsg) {
			if r.Access == nil || *r.Access != armnetwork.SecurityRuleAccessAllow || !tcpCapable(r) {
				continue
			}
			for _, s := range ruleSources(r) {
				if !core.IsPublicSource(s) {
					continue
				}
				if internetSource(s) {
					s = "0.0.0.0/0"
				}
				for _, spec := range portSpecs(r) {
					cands = append(cands, cand{s, spec})
				}
			}
		}
	}
	seenP, seenS := map[string]bool{}, map[string]bool{}
	for _, c := range cands {
		ok := false
		for _, port := range candidatePorts(c.spec, layers...) {
			all := true
			for _, nsg := range layers {
				if !nsgAllows(nsg, c.src, port) {
					all = false
					break
				}
			}
			if all {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		spec := c.spec
		if spec == "*" || strings.EqualFold(spec, "any") {
			spec = "*"
		}
		if !seenP[spec] {
			seenP[spec] = true
			ports = append(ports, spec)
		}
		if !seenS[c.src] {
			seenS[c.src] = true
			sources = append(sources, c.src)
		}
	}
	sort.Strings(ports)
	sort.Strings(sources)
	return ports, sources
}

// rangeToCIDRs converts an inclusive IPv4 range (Azure SQL firewall rules) to the
// minimal list of CIDRs; invalid or reversed ranges yield nil.
func rangeToCIDRs(start, end string) []string {
	a, err1 := netip.ParseAddr(strings.TrimSpace(start))
	b, err2 := netip.ParseAddr(strings.TrimSpace(end))
	if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
		return nil
	}
	as, bs := a.As4(), b.As4()
	lo := uint64(as[0])<<24 | uint64(as[1])<<16 | uint64(as[2])<<8 | uint64(as[3])
	hi := uint64(bs[0])<<24 | uint64(bs[1])<<16 | uint64(bs[2])<<8 | uint64(bs[3])
	if lo > hi {
		return nil
	}
	var out []string
	for lo <= hi {
		// Largest block aligned at lo that does not pass hi.
		size := 32
		if lo != 0 {
			size = bits.TrailingZeros64(lo)
			if size > 32 {
				size = 32
			}
		}
		for size > 0 && lo+(uint64(1)<<size)-1 > hi {
			size--
		}
		ip := netip.AddrFrom4([4]byte{byte(lo >> 24), byte(lo >> 16), byte(lo >> 8), byte(lo)})
		out = append(out, netip.PrefixFrom(ip, 32-size).String())
		lo += uint64(1) << size
	}
	return out
}
