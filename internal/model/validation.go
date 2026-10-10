package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// ValidationStatus is the reserved probe-status vocabulary (plan v3 G3 / AP9): whether an
// attack path or hop was validated against the live estate by an opt-in read-only probe.
// It is not an edge attribute; edge trust is Confidence (edge_attrs.go).
type ValidationStatus string

const (
	ValidationTheoretical  ValidationStatus = "theoretical"  // default: derived, never probed
	ValidationValidated    ValidationStatus = "validated"    // a probe confirmed it
	ValidationRefuted      ValidationStatus = "refuted"      // a probe showed it does not hold
	ValidationUnverifiable ValidationStatus = "unverifiable" // no probe can check it
)

var ValidationStatuses = []ValidationStatus{ValidationTheoretical, ValidationValidated, ValidationRefuted, ValidationUnverifiable}

func (s ValidationStatus) Valid() bool {
	return s == ValidationTheoretical || s == ValidationValidated || s == ValidationRefuted || s == ValidationUnverifiable
}

// UnmarshalJSON rejects a status outside the vocabulary.
func (s *ValidationStatus) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if !ValidationStatus(v).Valid() {
		return fmt.Errorf("validation status %q is not one of %v", v, ValidationStatuses)
	}
	*s = ValidationStatus(v)
	return nil
}

// ValidationResult is the reserved contract for one validation outcome (a probe result).
// Reserved for P1-GRAPH G3 / P2-REACH; not yet attached to edges, paths or Issues.
type ValidationResult struct {
	Status    ValidationStatus `json:"status"`
	ProbeKind string           `json:"probe_kind,omitempty"` // tcp_connect, s3_list_bucket, simulate_principal_policy, ...
	Evidence  map[string]any   `json:"evidence,omitempty"`   // request summary, response hash; never secret values
	At        time.Time        `json:"at,omitzero"`
}

// DefaultValidation is the status of anything no probe has examined.
func DefaultValidation() ValidationResult { return ValidationResult{Status: ValidationTheoretical} }
