package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Finding lifecycle states (store column findings.state, issues.state). A finding is
// "open" when first observed failing, "resolved" when a later scan of the same scope
// observes it passing or no longer reports it, and "reopened" when a resolved finding
// is observed failing again (first_seen is preserved across the whole history).
const (
	StateOpen     = "open"
	StateResolved = "resolved"
	StateReopened = "reopened"
)

// IsActive reports whether a lifecycle state counts as an open problem.
func IsActive(state string) bool { return state == StateOpen || state == StateReopened }

// FingerprintWith extends Fingerprint with discriminators the base key does not carry
// (for example a vulnerable package name and version, so one CVE in two packages of the
// same image stays two findings). With no extras it equals Fingerprint().
func (f *Finding) FingerprintWith(extra ...string) string {
	base := f.Fingerprint()
	if len(extra) == 0 {
		return base
	}
	sum := sha256.Sum256([]byte(base + "\x00" + strings.Join(extra, "\x00")))
	return hex.EncodeToString(sum[:16])
}
