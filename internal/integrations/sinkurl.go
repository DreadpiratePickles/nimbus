package integrations

// Outbound policy for every sink request (verify-4 defect 4).
//
//   - URL: https only; plain http only to a loopback address (local relays, tests). No userinfo
//     tricks change that: the host is what is checked.
//   - Address: never link-local (169.254.0.0/16, fe80::/10, which hold the cloud metadata
//     services; also the AWS IPv6 metadata address fd00:ec2::254), unspecified, multicast or
//     broadcast; private ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) only with
//     SetAllowPrivateSinks(true) (`--allow-private-sinks`, or NIMBUS_ALLOW_PRIVATE_SINKS=1).
//     Literal IPs are checked before the request; names are checked after resolution, at
//     connect time (dialer Control), so DNS rebinding cannot reach a forbidden address.
//   - Cloud metadata endpoints are refused always, even with --allow-private-sinks (verify-5 S2):
//     link-local, fd00:ec2::254, Alibaba 100.100.100.200, Azure WireServer 168.63.129.16, Oracle
//     192.0.0.192. IPv6 literals with a zone suffix are refused (S1), and IPv4 addresses embedded
//     in NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16) and Teredo (2001::/32) forms are
//     checked as the IPv4 address they carry (S4), as are the IPv4-compatible (::a.b.c.d) and
//     IPv4-translated (::ffff:0:a.b.c.d) forms, and numeric host spellings a libc resolver reads
//     as an IPv4 address (decimal 2852039166, hex 0xa9fea9fe, octal 0251.0376.0251.0376, short
//     169.254.43518) — at validate time, not only at dial (W7-POLISH).
//   - Redirects: at most 5; https -> http is refused; every hop's URL is validated; when the
//     scheme, host or port changes from the original request, every header outside a small
//     non-credential allowlist is removed (Authorization, DD-API-KEY, X-Api-Key, custom
//     headers...), and a redirect that would replay a request body there (307/308 keep the
//     method and body) is refused (S3: a PagerDuty routing_key lives in the body).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var allowPrivateSinks atomic.Bool

func init() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NIMBUS_ALLOW_PRIVATE_SINKS"))) {
	case "1", "true", "yes", "on":
		allowPrivateSinks.Store(true)
	}
}

// SetAllowPrivateSinks permits sink URLs on private (RFC 1918 / ULA / CGNAT) addresses
// (`--allow-private-sinks`). Link-local and metadata addresses stay refused.
func SetAllowPrivateSinks(v bool) { allowPrivateSinks.Store(v) }

// ErrSinkURL is matched (errors.Is) by every sink URL refusal.
var ErrSinkURL = errors.New("sink URL refused")

func sinkErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSinkURL, fmt.Sprintf(format, a...))
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// metadataAddrs are cloud metadata / host-agent endpoints outside link-local: refused even with
// --allow-private-sinks (verify-5 S2).
var metadataAddrs = map[netip.Addr]string{
	netip.MustParseAddr("fd00:ec2::254"):   "AWS IMDS (IPv6)",
	netip.MustParseAddr("100.100.100.200"): "Alibaba Cloud metadata",
	netip.MustParseAddr("168.63.129.16"):   "Azure WireServer",
	netip.MustParseAddr("192.0.0.192"):     "Oracle Cloud metadata",
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	nat64Locl = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour = netip.MustParsePrefix("2002::/16")
	teredo    = netip.MustParsePrefix("2001::/32")
	v4Compat  = netip.MustParsePrefix("::/96")           // deprecated IPv4-compatible ::a.b.c.d
	v4Transl  = netip.MustParsePrefix("::ffff:0:0:0/96") // IPv4-translated (RFC 2765)
)

// embeddedV4 is the IPv4 address an IPv6 transition form carries (NAT64, 6to4, Teredo client).
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	switch {
	case nat64.Contains(ip), nat64Locl.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case teredo.Contains(ip):
		return netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}), true
	case v4Transl.Contains(ip):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case v4Compat.Contains(ip) && !ip.IsUnspecified() && !ip.IsLoopback():
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// checkIP applies the address policy.
func checkIP(ip netip.Addr) error {
	if ip.Zone() != "" {
		return sinkErr("%s: IPv6 zone suffixes are not allowed in sink addresses", ip)
	}
	ip = ip.Unmap()
	if v4, ok := embeddedV4(ip); ok {
		if err := checkIP(v4); err != nil {
			return sinkErr("%s embeds %s: %v", ip, v4, err)
		}
	}
	switch {
	case metadataAddrs[ip] != "":
		return sinkErr("%s is a cloud metadata address (%s)", ip, metadataAddrs[ip])
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return sinkErr("%s is link-local (cloud metadata range)", ip)
	case ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return sinkErr("%s is not a unicast address", ip)
	case ip.IsLoopback():
		return nil
	case ip.IsPrivate() || cgnat.Contains(ip):
		if allowPrivateSinks.Load() {
			return nil
		}
		return sinkErr("%s is a private address (use --allow-private-sinks to permit it)", ip)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

// ValidateSinkURL checks a sink URL against the outbound policy (scheme and literal address;
// names are checked again at connect time).
func ValidateSinkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return sinkErr("unparseable URL %s", redactURL(raw))
	}
	return validateURL(u)
}

func validateURL(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return sinkErr("URL has no host")
	}
	if strings.Contains(host, "%") {
		return sinkErr("IPv6 zone suffixes are not allowed in sink URLs")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return sinkErr("plain http to %s: sinks must use https (http is allowed only to loopback)", host)
		}
	default:
		return sinkErr("scheme %q is not allowed (https only)", u.Scheme)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return checkIP(ip)
	}
	if ip, ok := numericIPv4Host(host); ok {
		if err := checkIP(ip); err != nil {
			return sinkErr("host %s is the numeric form of %s: %v", host, ip, err)
		}
	}
	return nil
}

// numericIPv4Host reads host the way inet_aton does (1-4 dot-separated parts, each decimal, 0x
// hex or 0-leading octal; the last part fills the remaining bytes), so "2852039166",
// "0xa9fea9fe" and "169.254.43518" are checked as the address a libc resolver would dial.
func numericIPv4Host(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		base, digits := 10, p
		switch {
		case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
			base, digits = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, digits = 8, p[1:]
		}
		if digits == "" {
			return netip.Addr{}, false
		}
		var v uint64
		for _, c := range strings.ToLower(digits) {
			var d uint64
			switch {
			case c >= '0' && c <= '9':
				d = uint64(c - '0')
			case c >= 'a' && c <= 'f':
				d = uint64(c-'a') + 10
			default:
				return netip.Addr{}, false
			}
			if d >= uint64(base) {
				return netip.Addr{}, false
			}
			v = v*uint64(base) + d
			if v > 0xffffffff {
				return netip.Addr{}, false
			}
		}
		vals[i] = v
	}
	var n uint64
	for i, v := range vals {
		if i < len(vals)-1 {
			if v > 0xff {
				return netip.Addr{}, false
			}
			n |= v << (8 * uint(3-i))
			continue
		}
		if rest := uint(4 - i); v >= 1<<(8*rest) {
			return netip.Addr{}, false
		}
		n |= v
	}
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

// checkDialAddr is the connect-time check on the resolved address (host:port).
func checkDialAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return sinkErr("bad address %q", addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return sinkErr("unresolved address %q", host)
	}
	return checkIP(ip)
}

// guardedDialer refuses connections to forbidden addresses after DNS resolution.
var guardedDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control: func(_, address string, _ syscall.RawConn) error {
		return checkDialAddr(address)
	},
}

func newSinkHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // a proxy would make the dial check see the proxy, not the sink
	tr.DialContext = guardedDialer.DialContext
	return &http.Client{Timeout: 20 * time.Second, Transport: tr, CheckRedirect: checkRedirect}
}

// safeRedirectHeaders survive a cross-origin redirect; everything else (credentials, API keys,
// custom configured headers) is dropped.
var safeRedirectHeaders = map[string]bool{
	"Accept": true, "Accept-Encoding": true, "Content-Type": true, "Content-Length": true, "User-Agent": true,
	"X-Github-Api-Version": true,
}

func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return sinkErr("stopped after 5 redirects")
	}
	prev := via[len(via)-1]
	if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return sinkErr("refusing redirect from https to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	if err := validateURL(req.URL); err != nil {
		return err
	}
	if origin(req.URL) != origin(via[0].URL) {
		// 307/308 replay the method and body; the body can carry a credential (PagerDuty
		// routing_key) or the finding itself: never send it to another origin (verify-5 S3).
		if req.GetBody != nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) {
			return sinkErr("refusing a %s redirect that would replay the request body to %s", req.Method, origin(req.URL))
		}
		for k := range req.Header {
			if !safeRedirectHeaders[http.CanonicalHeaderKey(k)] {
				req.Header.Del(k)
			}
		}
	}
	return nil
}

// dialSyslog connects to a syslog/CEF target under the same address policy.
func dialSyslog(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, sinkErr("syslog address must be host:port")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if err := checkIP(ip); err != nil {
			return nil, err
		}
	}
	d := *guardedDialer
	d.Timeout = 5 * time.Second
	return d.DialContext(ctx, network, addr)
}
