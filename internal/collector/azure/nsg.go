package azure

import (
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

// specEffective checks the lowest port of spec reaches rule r first in priority order.
func specEffective(nsg *armnetwork.SecurityGroup, r *armnetwork.SecurityRulePropertiesFormat, spec string) bool {
	port := lowPort(spec)
	for _, x := range inboundRules(nsg) {
		if !ruleFromInternet(x) || !coversPort(x, port) {
			continue
		}
		return x == r || (x.Access != nil && *x.Access == armnetwork.SecurityRuleAccessAllow)
	}
	return false
}

func lowPort(spec string) int {
	if spec == "*" {
		return 0
	}
	lo, _, _ := strings.Cut(spec, "-")
	n, _ := strconv.Atoi(strings.TrimSpace(lo))
	return n
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
