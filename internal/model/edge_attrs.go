package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Edge attribute contract (plan v3 §4 "Shared contracts", P1-GRAPH G2).
//
// Graph edges carry a free-form attr map (graph.Edge.Attr, persisted as JSON text in
// graph_edges.attr). The keys below are the typed contract inside that map. The wire form is
// flat: the keys collectors already write (actions, statement, exposure, exposure_cidrs,
// exposure_reason, because) keep their names and shapes, and other keys (via, ports, hint,
// finding_id, ...) are left alone. docs/graph-schema.md lists every key.

// Contract keys on graph.Edge.Attr.
const (
	AttrActions            = "actions"
	AttrEffect             = "effect"
	AttrResources          = "resources"
	AttrConditions         = "conditions"
	AttrStatement          = "statement"
	AttrPolicyARN          = "policy_arn"
	AttrDeniedBy           = "denied_by"
	AttrRequiresConditions = "requires_conditions"
	AttrUnknownConditions  = "unknown_conditions"
	AttrBecause            = "because"
	AttrConfidence         = "confidence"
	AttrEvidence           = "evidence"
	AttrExposure           = "exposure"
	AttrExposureCIDRs      = "exposure_cidrs"
	AttrExposureReason     = "exposure_reason"
)

// EdgeAttrKeys is every contract key, in documentation order.
var EdgeAttrKeys = []string{AttrActions, AttrEffect, AttrResources, AttrConditions, AttrStatement, AttrPolicyARN,
	AttrDeniedBy, AttrRequiresConditions, AttrUnknownConditions, AttrBecause, AttrConfidence,
	AttrEvidence, AttrExposure, AttrExposureCIDRs, AttrExposureReason}

// Confidence is how the edge is known (one vocabulary for edges, paths and Issues; the only
// edge-level trust attribute; "validation" is reserved for the probe status, validation.go):
// verified = typed inventory relationship or probe/simulator evidence; inferred = derived by
// policy evaluation (possibly with conditions); hint = scanner hint or name/tag inference.
type Confidence string

const (
	ConfidenceVerified Confidence = "verified"
	ConfidenceInferred Confidence = "inferred"
	ConfidenceHint     Confidence = "hint"
)

// Confidences lists the vocabulary in rank order (strongest first).
var Confidences = []Confidence{ConfidenceVerified, ConfidenceInferred, ConfidenceHint}

func (c Confidence) Valid() bool {
	return c == ConfidenceVerified || c == ConfidenceInferred || c == ConfidenceHint
}

// Policy statement effects.
const (
	EffectAllow = "Allow"
	EffectDeny  = "Deny"
)

// Exposure widths (internal/collector/core and internal/attackpath use the same strings).
const (
	ExposureWide    = "wide"
	ExposureNarrow  = "narrow"
	ExposureTrusted = "trusted"
	ExposurePrivate = "private"
)

var ExposureWidths = []string{ExposureWide, ExposureNarrow, ExposureTrusted, ExposurePrivate}

// PermissionAttr is the permission a has_policy / grants_access_to / can_assume /
// can_perform edge carries: which statement allows (or denies) which actions on which
// resources. Statement is "<policy-arn>#<sid|index>".
type PermissionAttr struct {
	Actions            []string       `json:"actions,omitempty"`
	Effect             string         `json:"effect,omitempty"`
	Resources          []string       `json:"resources,omitempty"`
	Conditions         map[string]any `json:"conditions,omitempty"`
	Statement          string         `json:"statement,omitempty"`
	PolicyARN          string         `json:"policy_arn,omitempty"`
	DeniedBy           string         `json:"denied_by,omitempty"`
	RequiresConditions []string       `json:"requires_conditions,omitempty"`
	UnknownConditions  []string       `json:"unknown_conditions,omitempty"`
}

// Exposure is the width of an internet exposure: the public sources that reach the
// resource and, for trusted/private, why it is not used as an entry.
type Exposure struct {
	Width  string   `json:"exposure,omitempty"`
	CIDRs  []string `json:"exposure_cidrs,omitempty"`
	Reason string   `json:"exposure_reason,omitempty"`
}

// EdgeAttrs is the whole typed contract. The embedded pointers are nil when the edge carries
// no permission / exposure; their fields marshal inline (the flat wire form).
type EdgeAttrs struct {
	*PermissionAttr
	*Exposure
	Because    string         `json:"because,omitempty"`
	Confidence Confidence     `json:"confidence,omitempty"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

// Map is the flat attr-map form (only set fields; typed slices stay []string).
func (a EdgeAttrs) Map() map[string]any {
	m := map[string]any{}
	SetEdgeAttrs(m, a)
	return m
}

// SetEdgeAttrs writes every set field of a into attr, leaving other keys untouched. A nil
// PermissionAttr / Exposure leaves those keys alone; a non-nil one replaces all of its keys.
func SetEdgeAttrs(attr map[string]any, a EdgeAttrs) {
	if a.PermissionAttr != nil {
		SetPermission(attr, *a.PermissionAttr)
	}
	if a.Exposure != nil {
		SetExposure(attr, *a.Exposure)
	}
	setStr(attr, AttrBecause, a.Because)
	setStr(attr, AttrConfidence, string(a.Confidence))
	if len(a.Evidence) > 0 {
		attr[AttrEvidence] = a.Evidence
	}
}

// SetPermission replaces the permission keys of attr with p.
func SetPermission(attr map[string]any, p PermissionAttr) {
	for _, k := range []string{AttrActions, AttrEffect, AttrResources, AttrConditions, AttrStatement, AttrPolicyARN, AttrDeniedBy, AttrRequiresConditions, AttrUnknownConditions} {
		delete(attr, k)
	}
	setList(attr, AttrActions, p.Actions)
	setStr(attr, AttrEffect, p.Effect)
	setList(attr, AttrResources, p.Resources)
	if len(p.Conditions) > 0 {
		attr[AttrConditions] = p.Conditions
	}
	setStr(attr, AttrStatement, p.Statement)
	setStr(attr, AttrPolicyARN, p.PolicyARN)
	setStr(attr, AttrDeniedBy, p.DeniedBy)
	setList(attr, AttrRequiresConditions, p.RequiresConditions)
	setList(attr, AttrUnknownConditions, p.UnknownConditions)
}

// SetExposure replaces the exposure keys of attr with x.
func SetExposure(attr map[string]any, x Exposure) {
	for _, k := range []string{AttrExposure, AttrExposureCIDRs, AttrExposureReason} {
		delete(attr, k)
	}
	setStr(attr, AttrExposure, x.Width)
	setList(attr, AttrExposureCIDRs, x.CIDRs)
	setStr(attr, AttrExposureReason, x.Reason)
}

func setStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func setList(m map[string]any, k string, v []string) {
	if len(v) > 0 {
		m[k] = append([]string(nil), v...)
	}
}

var listKeys = []string{AttrActions, AttrResources, AttrRequiresConditions, AttrUnknownConditions, AttrExposureCIDRs}

// ParseEdgeAttrs reads the contract out of an attr map in any of its shapes: typed values
// set in memory, or generic JSON values loaded from graph_edges. A list key may also hold
// one comma-separated string (the legacy exposure_cidrs form). Values outside the contract
// vocabulary are an error; keys outside the contract are ignored.
func ParseEdgeAttrs(attr map[string]any) (EdgeAttrs, error) {
	sub := map[string]any{}
	for _, k := range EdgeAttrKeys {
		if v, ok := attr[k]; ok && v != nil {
			sub[k] = v
		}
	}
	for _, k := range listKeys {
		if s, ok := sub[k].(string); ok {
			var parts []string
			for _, p := range strings.Split(s, ",") {
				if p = strings.TrimSpace(p); p != "" {
					parts = append(parts, p)
				}
			}
			sub[k] = parts
		}
	}
	var a EdgeAttrs
	if len(sub) == 0 {
		return a, nil
	}
	b, err := json.Marshal(sub)
	if err != nil {
		return EdgeAttrs{}, fmt.Errorf("edge attrs: %w", err)
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return EdgeAttrs{}, fmt.Errorf("edge attrs: %w", err)
	}
	if a.PermissionAttr != nil && isZeroPermission(*a.PermissionAttr) {
		a.PermissionAttr = nil
	}
	if a.Exposure != nil && a.Exposure.Width == "" && len(a.Exposure.CIDRs) == 0 && a.Exposure.Reason == "" {
		a.Exposure = nil
	}
	return a, a.Validate()
}

func isZeroPermission(p PermissionAttr) bool {
	return len(p.Actions) == 0 && p.Effect == "" && len(p.Resources) == 0 && len(p.Conditions) == 0 && p.Statement == "" &&
		p.PolicyARN == "" && p.DeniedBy == "" && len(p.RequiresConditions) == 0 && len(p.UnknownConditions) == 0
}

// Validate checks the enumerated values.
func (a EdgeAttrs) Validate() error {
	if a.Confidence != "" && !a.Confidence.Valid() {
		return fmt.Errorf("edge attrs: confidence %q is not one of %v", a.Confidence, Confidences)
	}
	if p := a.PermissionAttr; p != nil && p.Effect != "" && p.Effect != EffectAllow && p.Effect != EffectDeny {
		return fmt.Errorf("edge attrs: effect %q is not Allow or Deny", p.Effect)
	}
	if x := a.Exposure; x != nil && x.Width != "" {
		ok := false
		for _, w := range ExposureWidths {
			ok = ok || x.Width == w
		}
		if !ok {
			return fmt.Errorf("edge attrs: exposure %q is not one of %v", x.Width, ExposureWidths)
		}
	}
	return nil
}
