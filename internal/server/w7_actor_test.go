package server

import (
	"net/http/httptest"
	"testing"
)

// Verification 7 (V7 / coordinator item 14): X-Nimbus-Actor accepted non-printable text (RLO,
// zero-width, C1 controls, invalid UTF-8) and stored it as the approver. Only printable,
// valid UTF-8 is accepted.
func TestSuppressApproverRejectsNonPrintable(t *testing.T) {
	for _, bad := range []string{"alice‮gnp.exe", "al​ice", "bob\u0085", "x\xff\xfe", "a b", "­soft"} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("X-Nimbus-Actor", bad)
		if got, err := suppressApprover(r); err == nil {
			t.Errorf("actor %q accepted as %q", bad, got)
		}
	}
	for _, ok := range []string{"alice@example.com", "Zoë Müller", "ops-bot (ci)"} {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("X-Nimbus-Actor", ok)
		if _, err := suppressApprover(r); err != nil {
			t.Errorf("actor %q refused: %v", ok, err)
		}
	}
}
