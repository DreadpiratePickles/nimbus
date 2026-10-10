package output

import (
	"strings"
	"testing"
)

// Verification 7 defect 10 / coordinator item 12: a NIMBUS_ID_KEY under 16 bytes was silently
// replaced by a random key (ids changed every run, no warning). It is now an error; empty still
// means "random per run".
func TestRunKeyerFromConfiguredKey(t *testing.T) {
	if _, err := RunKeyerFromKey("short"); err == nil || !strings.Contains(err.Error(), "16") {
		t.Fatalf("a 5-byte key must be an error naming the minimum: %v", err)
	}
	a, err := RunKeyerFromKey("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := RunKeyerFromKey("0123456789abcdef")
	if a.ID("x") != b.ID("x") {
		t.Errorf("a configured key must give stable ids")
	}
	r1, err := RunKeyerFromKey("")
	r2, _ := RunKeyerFromKey("")
	if err != nil || r1.ID("x") == r2.ID("x") {
		t.Errorf("empty key = random per run: %v", err)
	}
}
