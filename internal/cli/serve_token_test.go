package cli

import "testing"

// V2 defect 12: a token with surrounding whitespace is trimmed (and then validated), so
// the operator is not locked out by "Bearer abc" never matching " abc ".
func TestServeTokenTrimmed(t *testing.T) {
	old := serveFlags.token
	t.Cleanup(func() { serveFlags.token = old })
	serveFlags.token = "  abc\t"
	if tok, err := serveToken(true); err != nil || tok != "abc" {
		t.Fatalf("--token: %q, %v; want abc", tok, err)
	}
	t.Setenv("CLOUD_POSTURE_TOKEN", " xyz \n")
	if tok, err := serveToken(false); err != nil || tok != "xyz" {
		t.Fatalf("env: %q, %v; want xyz", tok, err)
	}
	for _, bad := range []string{"   ", "\t", ""} {
		serveFlags.token = bad
		if _, err := serveToken(true); err == nil {
			t.Errorf("--token %q must be refused", bad)
		}
	}
}
