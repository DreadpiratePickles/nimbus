package integrations

import (
	"errors"
	"testing"
)

// W7-POLISH (verification 6 LOW): IPv4-compatible (::a.b.c.d, ::/96) and IPv4-translated
// (::ffff:0:a.b.c.d, RFC 2765) forms of a metadata address, and the numeric host spellings a
// libc resolver turns into one (decimal, hex, octal, short dotted), are refused at validate time
// — not only by the connect-time check — even with --allow-private-sinks.
func TestValidateSinkURLRefusesEmbeddedAndNumericMetadataForms(t *testing.T) {
	SetAllowPrivateSinks(true)
	defer SetAllowPrivateSinks(false)
	for _, raw := range []string{
		"https://[::a9fe:a9fe]/hook",           // IPv4-compatible 169.254.169.254
		"https://[::169.254.169.254]/hook",     // same, dotted
		"https://[::ffff:0:a9fe:a9fe]/hook",    // IPv4-translated
		"https://[::ffff:0:169.254.169.254]/x", // same, dotted
		"https://[::ffff:169.254.169.254]/x",   // IPv4-mapped (already refused; kept as a guard)
		"https://[::6464:64c8]/x",              // ::100.100.100.200 Alibaba
		"https://[::ffff:0:a83f:8110]/x",       // ::ffff:0:168.63.129.16 Azure WireServer
		"https://2852039166/x",                 // decimal 169.254.169.254
		"https://0xa9fea9fe/x",                 // hex
		"https://0251.0376.0251.0376/x",        // octal
		"https://169.254.43518/x",              // short dotted (a.b.c with c 16-bit)
		"https://0xA9.0xFE.0xA9.0xFE/x",        // hex per octet
	} {
		err := ValidateSinkURL(raw)
		if err == nil || !errors.Is(err, ErrSinkURL) {
			t.Errorf("%s accepted at validate time (err %v)", raw, err)
		}
	}
	// Ordinary names and public addresses still pass; :: and ::1 are not IPv4-compatible forms.
	for _, raw := range []string{"https://hooks.slack.com/services/x", "https://8.8.8.8/x", "https://[2606:4700::1111]/x", "http://[::1]:8080/x", "https://1password.example/x", "https://123.example.com/x"} {
		if err := ValidateSinkURL(raw); err != nil {
			t.Errorf("%s refused: %v", raw, err)
		}
	}
}
