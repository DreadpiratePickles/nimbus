package reach

import (
	"net/netip"
	"sort"
	"strings"
)

// ipset is a set of IP addresses held as sorted, non-overlapping, non-adjacent closed ranges.
// IPv4 and IPv6 ranges never merge (netip.Addr orders every IPv4 address before IPv6).
type ipset struct{ rs []iprange }

type iprange struct{ lo, hi netip.Addr }

// parseCIDR reads a CIDR, a bare IP, or a wildcard ("*", "any", "internet" = 0.0.0.0/0).
func parseCIDR(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "*", "any", "internet", "0.0.0.0":
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

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}

func prefixRange(p netip.Prefix) iprange { return iprange{p.Masked().Addr(), lastAddr(p)} }

// setOf builds a set from CIDR strings (unparseable entries are ignored).
func setOf(cidrs ...string) ipset {
	var rs []iprange
	for _, c := range cidrs {
		if p, ok := parseCIDR(c); ok {
			rs = append(rs, prefixRange(p))
		}
	}
	return normalize(rs)
}

func normalize(rs []iprange) ipset {
	if len(rs) == 0 {
		return ipset{}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.Less(rs[j].lo) })
	out := []iprange{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if last.hi.BitLen() == r.lo.BitLen() && (r.lo.Compare(last.hi) <= 0 || (last.hi.Next().IsValid() && last.hi.Next() == r.lo)) {
			if r.hi.Compare(last.hi) > 0 {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return ipset{rs: out}
}

func (s ipset) empty() bool { return len(s.rs) == 0 }

func (s ipset) union(o ipset) ipset {
	return normalize(append(append([]iprange{}, s.rs...), o.rs...))
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) <= 0 {
		return a
	}
	return b
}

func (s ipset) intersect(o ipset) ipset {
	var out []iprange
	i, j := 0, 0
	for i < len(s.rs) && j < len(o.rs) {
		a, b := s.rs[i], o.rs[j]
		lo, hi := maxAddr(a.lo, b.lo), minAddr(a.hi, b.hi)
		if lo.Compare(hi) <= 0 {
			out = append(out, iprange{lo, hi})
		}
		if a.hi.Compare(b.hi) < 0 {
			i++
		} else {
			j++
		}
	}
	return ipset{rs: out}
}

func (s ipset) subtract(o ipset) ipset {
	var out []iprange
	for _, r := range s.rs {
		cur := []iprange{r}
		for _, c := range o.rs {
			var next []iprange
			for _, x := range cur {
				if c.hi.Compare(x.lo) < 0 || c.lo.Compare(x.hi) > 0 {
					next = append(next, x)
					continue
				}
				if c.lo.Compare(x.lo) > 0 {
					next = append(next, iprange{x.lo, c.lo.Prev()})
				}
				if c.hi.Compare(x.hi) < 0 {
					next = append(next, iprange{c.hi.Next(), x.hi})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return normalize(out)
}

func (s ipset) equal(o ipset) bool {
	if len(s.rs) != len(o.rs) {
		return false
	}
	for i := range s.rs {
		if s.rs[i] != o.rs[i] {
			return false
		}
	}
	return true
}

// cidrs is the minimal CIDR cover of the set, in address order.
func (s ipset) cidrs() []string {
	var out []string
	for _, r := range s.rs {
		lo := r.lo
		for {
			bits := lo.BitLen()
			for b := 0; b <= bits; b++ {
				p := netip.PrefixFrom(lo, b)
				if p.Masked().Addr() != lo || lastAddr(p).Compare(r.hi) > 0 {
					continue
				}
				out = append(out, p.String())
				lo = lastAddr(p)
				break
			}
			if lo.Compare(r.hi) >= 0 || !lo.Next().IsValid() {
				break
			}
			lo = lo.Next()
		}
	}
	return out
}

// v4size is the number of IPv4 addresses in the set.
func (s ipset) v4size() uint64 {
	var n uint64
	for _, r := range s.rs {
		if !r.lo.Is4() {
			continue
		}
		lo, hi := r.lo.As4(), r.hi.As4()
		l := uint64(lo[0])<<24 | uint64(lo[1])<<16 | uint64(lo[2])<<8 | uint64(lo[3])
		h := uint64(hi[0])<<24 | uint64(hi[1])<<16 | uint64(hi[2])<<8 | uint64(hi[3])
		n += h - l + 1
	}
	return n
}

// nonPublic are the ranges that are not reachable from the internet (RFC 6890 special
// purpose, the same list as core.IsPublicSource).
var nonPublic = setOf("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

var allAddrs = setOf("0.0.0.0/0", "::/0")

// ipv6Space is every IPv6 address.
var ipv6Space = setOf("::/0")

// publicSpace is every internet-routable address.
func publicSpace() ipset { return allAddrs.subtract(nonPublic) }
