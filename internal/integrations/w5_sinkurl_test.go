package integrations

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// Verify-5 S1: an IPv6 zone suffix must not hide a forbidden address (fd00:ec2::254%lo0 was
// not equal to the metadata address); zoned literals are refused outright, before and at dial.
func TestSinkRefusesIPv6Zones(t *testing.T) {
	for _, u := range []string{"https://[fd00:ec2::254%25lo0]/latest/meta-data/", "https://[fd00:ec2::254%25en0]/x",
		"https://[fe80::1%25lo0]/x", "https://[2001:db8::1%25eth0]/x", "http://[::1%25lo0]:9/x"} {
		if ValidateSinkURL(u) == nil {
			t.Errorf("zoned sink URL %s accepted", u)
		}
	}
	for _, a := range []string{"[fd00:ec2::254%lo0]:80", "[2001:db8::1%eth0]:443"} {
		if checkDialAddr(a) == nil {
			t.Errorf("dial to zoned %s allowed", a)
		}
	}
}

// Verify-5 S2: cloud metadata endpoints outside link-local (Alibaba 100.100.100.200 in CGNAT,
// Azure WireServer 168.63.129.16, Oracle 192.0.0.192, AWS fd00:ec2::254) are refused even with
// --allow-private-sinks, as are the same addresses embedded in NAT64 / 6to4 / Teredo forms (S4).
func TestSinkAlwaysRefusesMetadataEvenWithPrivateOptIn(t *testing.T) {
	SetAllowPrivateSinks(true)
	defer SetAllowPrivateSinks(false)
	for _, u := range []string{"https://100.100.100.200/latest/meta-data/", "https://168.63.129.16/machine", "https://192.0.0.192/x",
		"https://[fd00:ec2::254]/", "https://[::ffff:100.100.100.200]/", "https://[64:ff9b::a9fe:a9fe]/", "https://[64:ff9b::6464:64c8]/",
		"https://[2002:a9fe:a9fe::1]/", "https://[2001:0:4136:e378:8000:63bf:5601:5601]/"} {
		if ValidateSinkURL(u) == nil {
			t.Errorf("metadata sink URL %s accepted with --allow-private-sinks", u)
		}
	}
	for _, a := range []string{"100.100.100.200:80", "168.63.129.16:80", "[64:ff9b::a9fe:a9fe]:80"} {
		if checkDialAddr(a) == nil {
			t.Errorf("dial to metadata %s allowed with --allow-private-sinks", a)
		}
	}
	// ordinary CGNAT / private addresses stay usable with the opt-in
	for _, u := range []string{"https://100.64.1.2/hook", "https://10.0.0.5/hook"} {
		if err := ValidateSinkURL(u); err != nil {
			t.Errorf("%s refused with --allow-private-sinks: %v", u, err)
		}
	}
	SetAllowPrivateSinks(false)
	// without the opt-in, a NAT64 / 6to4 form of a private address is private
	for _, u := range []string{"https://[64:ff9b::a00:5]/", "https://[2002:c0a8:10a::1]/"} {
		if ValidateSinkURL(u) == nil {
			t.Errorf("embedded private address %s accepted without --allow-private-sinks", u)
		}
	}
	if err := checkIP(netip.MustParseAddr("2606:4700::1111")); err != nil {
		t.Errorf("public IPv6 refused: %v", err)
	}
}

// Verify-5 S3: a cross-origin 307/308 would replay the request body (a PagerDuty routing_key, a
// webhook payload) to the new origin. The redirect is refused; the body never leaves.
func TestSinkNeverReplaysBodyCrossOrigin(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		ev := &catcher{}
		es := ev.srv()
		target := strings.Replace(es.URL, "127.0.0.1", "localhost", 1)
		red := redirectorCode(target, code)
		resp, err := newSinkHTTPClient().Post(red.URL+"/v2/enqueue", "application/json", bytes.NewReader([]byte(`{"routing_key":"PDSECRET"}`)))
		if resp != nil {
			resp.Body.Close()
		}
		ev.mu.Lock()
		got := strings.Join(ev.got, "\n")
		ev.mu.Unlock()
		if strings.Contains(got, "PDSECRET") || len(ev.got) > 0 {
			t.Errorf("%d: body replayed cross-origin: %s", code, got)
		}
		if err == nil {
			t.Errorf("%d: cross-origin body-replaying redirect not reported as an error", code)
		}
		red.Close()
		es.Close()
	}
	// same origin 307 keeps working (a sink that moves a path on its own host)
	ev := &catcher{}
	es := ev.srv()
	resp, err := newSinkHTTPClient().Post(es.URL+"/x", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || resp.StatusCode != 200 {
		t.Errorf("plain same-origin POST failed: %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	es.Close()
}

func redirectorCode(target string, code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+r.URL.RequestURI(), code)
	}))
}
