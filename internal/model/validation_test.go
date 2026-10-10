package model

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// ValidationResult is the reserved probe-status contract (plan v3 G3 / AP9); not yet attached
// to edges or paths.
func TestValidationResultRoundTrip(t *testing.T) {
	v := ValidationResult{
		Status:    ValidationRefuted,
		ProbeKind: "tcp_connect",
		Evidence:  map[string]any{"port": float64(22), "response_hash": "sha256:ab"},
		At:        time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"status":"refuted","probe_kind":"tcp_connect","evidence":{"port":22,"response_hash":"sha256:ab"},"at":"2026-10-09T12:00:00Z"}`
	if string(b) != want {
		t.Fatalf("wire form:\n got %s\nwant %s", b, want)
	}
	var back ValidationResult
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, v) {
		t.Fatalf("round trip: %+v", back)
	}
	// The default (no probe run) is theoretical and marshals without probe fields.
	d := DefaultValidation()
	if d.Status != ValidationTheoretical {
		t.Fatalf("default status %q", d.Status)
	}
	if b, _ := json.Marshal(d); string(b) != `{"status":"theoretical"}` {
		t.Fatalf("default wire form %s", b)
	}
	for _, s := range []ValidationStatus{ValidationTheoretical, ValidationValidated, ValidationRefuted, ValidationUnverifiable} {
		if !s.Valid() {
			t.Errorf("%s invalid", s)
		}
	}
	for _, s := range []ValidationStatus{"", "verified", "unknown"} {
		if s.Valid() {
			t.Errorf("%q accepted", s)
		}
	}
	var bad ValidationResult
	if err := json.Unmarshal([]byte(`{"status":"verified"}`), &bad); err == nil {
		t.Error("unmarshal accepted a status outside the vocabulary")
	}
}
