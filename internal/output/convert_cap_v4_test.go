package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Verify-4 LOW: convert has an input cap (64 MiB) with a clear error, checked before parsing.
func TestConvertInputCap(t *testing.T) {
	big := make([]byte, MaxConvertInput+1)
	copy(big, `[{"id":"x"`)
	_, err := Convert(big, "json", "csv")
	if !errors.Is(err, ErrConvertTooLarge) || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("over-cap input: %v", err)
	}
	if _, err := ReadConvertInput(bytes.NewReader(big)); !errors.Is(err, ErrConvertTooLarge) {
		t.Fatalf("ReadConvertInput over cap: %v", err)
	}
	b, err := ReadConvertInput(strings.NewReader("[]"))
	if err != nil || string(b) != "[]" {
		t.Fatalf("ReadConvertInput: %q %v", b, err)
	}
	if _, err := Convert([]byte("[]"), "json", "csv"); err != nil {
		t.Fatalf("small input: %v", err)
	}
}
