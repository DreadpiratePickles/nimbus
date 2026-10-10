package core

import (
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Exposure width (O10, after Microsoft Defender's wide/narrow exposure + trusted IPs).
// Every internet "exposes" edge a collector creates — and the exposed node — carries
//
//	exposure:        "wide" | "narrow" | "trusted"
//	exposure_cidrs:  []string  the public sources that allow the traffic
//	exposure_reason: string    (only when trusted) why the exposure is trusted
//
// wide    = a source is 0.0.0.0/0, ::/0 or a cloud "any/Internet" tag (or the
//
//	exposure has no source restriction at all: public bucket, auth-less URL)
//
// narrow  = every source is a specific public CIDR, at least one outside trusted_cidrs
// trusted = every source is inside the configured trusted_cidrs
const (
	ExposureWide    = "wide"
	ExposureNarrow  = "narrow"
	ExposureTrusted = "trusted"

	AttrExposure       = "exposure"
	AttrExposureCIDRs  = "exposure_cidrs"
	AttrExposureReason = "exposure_reason"
)

// WideSources is the source list for exposure with no network restriction.
var WideSources = []string{"0.0.0.0/0"}

var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// ParseSource parses a CIDR or bare IP (as a host prefix). Cloud wildcard tags
// ("*", "Internet", "any") become 0.0.0.0/0.
func ParseSource(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if IsOpenCIDR(s) {
		return netip.MustParsePrefix("0.0.0.0/0"), true
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// IsPublicSource reports a source address range reachable from the internet: the
// open wildcards or any CIDR/IP that is not private, loopback, link-local, CGNAT,
// ULA or multicast. Service tags (VirtualNetwork, sg-…) are not public.
func IsPublicSource(s string) bool {
	if IsOpenCIDR(s) {
		return true
	}
	p, ok := ParseSource(s)
	if !ok {
		return false
	}
	if p.Bits() == 0 {
		return true
	}
	for _, np := range nonPublic {
		if np.Addr().Is4() == p.Addr().Is4() && np.Contains(p.Addr()) && np.Bits() <= p.Bits() {
			return false
		}
	}
	return true
}

// PublicSources filters a source list to the internet-reachable entries.
func PublicSources(sources []string) []string {
	var out []string
	for _, s := range sources {
		if IsPublicSource(s) {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func isWide(s string) bool {
	if IsOpenCIDR(s) {
		return true
	}
	p, ok := ParseSource(s)
	return ok && p.Bits() == 0
}

func parseTrusted(trusted []string) []netip.Prefix {
	var out []netip.Prefix
	for _, t := range trusted {
		if p, err := netip.ParsePrefix(strings.TrimSpace(t)); err == nil && p.Bits() > 0 {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(strings.TrimSpace(t)); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// CoveredBy reports whether every address in source lies inside one trusted prefix.
func CoveredBy(source string, trusted []string) bool {
	p, ok := ParseSource(source)
	if !ok {
		return false
	}
	for _, t := range parseTrusted(trusted) {
		if t.Addr().Is4() == p.Addr().Is4() && t.Bits() <= p.Bits() && t.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// ExposureWidth classifies a set of public sources. An empty set means the
// exposure has no network restriction and is wide.
func ExposureWidth(sources, trusted []string) string {
	if len(sources) == 0 {
		return ExposureWide
	}
	if unionCoversHalf(sources) {
		return ExposureWide
	}
	allTrusted := len(trusted) > 0
	for _, s := range sources {
		if isWide(s) {
			return ExposureWide
		}
		if !CoveredBy(s, trusted) {
			allTrusted = false
		}
	}
	if allTrusted {
		return ExposureTrusted
	}
	return ExposureNarrow
}

// WideFraction is the share of an address family a source set must cover to count as wide
// (defect 10c, verify-4 D8: 0.0.0.0/1 + 128.0.0.0/1 is the whole IPv4 internet, not "narrow").
const WideFraction = 0.5

// unionCoversHalf reports whether the union of the sources covers at least WideFraction of
// IPv4 or of IPv6. CIDR prefixes either nest or are disjoint, so the union is the sum over the
// prefixes not contained in a shorter one.
func unionCoversHalf(sources []string) bool {
	var ps []netip.Prefix
	for _, s := range sources {
		if p, ok := ParseSource(s); ok {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Bits() < ps[j].Bits() })
	var kept []netip.Prefix
	cover := map[bool]float64{}
	for _, p := range ps {
		inside := false
		for _, k := range kept {
			if k.Addr().Is4() == p.Addr().Is4() && k.Contains(p.Addr()) {
				inside = true
				break
			}
		}
		if inside {
			continue
		}
		kept = append(kept, p)
		cover[p.Addr().Is4()] += math.Ldexp(1, -p.Bits())
	}
	return cover[true] >= WideFraction || cover[false] >= WideFraction
}

// ExposureAttrs sets exposure, exposure_cidrs and (when trusted) exposure_reason on
// attr and returns it (allocating when nil).
func ExposureAttrs(attr map[string]any, sources, trusted []string) map[string]any {
	if attr == nil {
		attr = map[string]any{}
	}
	if len(sources) == 0 {
		sources = WideSources
	}
	srcs := uniqSorted(sources)
	width := ExposureWidth(srcs, trusted)
	attr[AttrExposure] = width
	attr[AttrExposureCIDRs] = srcs
	if width == ExposureTrusted {
		attr[AttrExposureReason] = "every source (" + strings.Join(srcs, ", ") + ") is inside trusted_cidrs"
	} else {
		delete(attr, AttrExposureReason)
	}
	return attr
}

// Expose adds (or widens) the internet -[exposes]-> to edge labelled with exposure
// width, and mirrors the aggregate exposure onto the target node. Repeated calls for
// the same target union their sources, so the widest rule wins. sources nil means
// unrestricted (wide). Collectors build their graph single-threaded per account.
func Expose(g *graph.Graph, to string, attr map[string]any, sources, trusted []string) {
	if to == "" {
		return
	}
	if len(sources) == 0 {
		sources = WideSources
	}
	var existing *graph.Edge
	for _, e := range g.Out(graph.InternetNodeID) {
		if e.To == to && e.Kind == graph.EdgeExposes {
			existing = e
			break
		}
	}
	if existing != nil {
		if existing.Attr == nil {
			existing.Attr = map[string]any{}
		}
		prev, _ := existing.Attr[AttrExposureCIDRs].([]string)
		ExposureAttrs(existing.Attr, append(append([]string(nil), prev...), sources...), trusted)
		for k, v := range attr {
			if _, ok := existing.Attr[k]; !ok {
				existing.Attr[k] = v
			}
		}
		attr = existing.Attr
	} else {
		a := map[string]any{}
		for k, v := range attr {
			a[k] = v
		}
		attr = ExposureAttrs(a, sources, trusted)
		g.AddEdge(graph.InternetNodeID, to, graph.EdgeExposes, attr)
	}
	nodeAttrs := map[string]any{AttrExposure: attr[AttrExposure], AttrExposureCIDRs: attr[AttrExposureCIDRs]}
	if r, ok := attr[AttrExposureReason]; ok {
		nodeAttrs[AttrExposureReason] = r
	}
	n, ok := g.Node(to)
	if ok && n.Attributes != nil {
		if _, had := n.Attributes[AttrExposureReason]; had && attr[AttrExposure] != ExposureTrusted {
			delete(n.Attributes, AttrExposureReason)
		}
	}
	g.AddNode(&graph.Node{ID: to, Attributes: nodeAttrs})
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
