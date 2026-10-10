package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func sampleEdgeAttrs() EdgeAttrs {
	return EdgeAttrs{
		PermissionAttr: &PermissionAttr{
			Actions:            []string{"s3:GetObject", "s3:ListBucket"},
			Effect:             EffectAllow,
			Resources:          []string{"arn:aws:s3:::lab-pii", "arn:aws:s3:::lab-pii/*"},
			Conditions:         map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}},
			Statement:          "arn:aws:iam::111111111111:policy/export#ExportRead",
			PolicyARN:          "arn:aws:iam::111111111111:policy/export",
			RequiresConditions: []string{"aws:SecureTransport"},
		},
		Exposure:   &Exposure{Width: ExposureWide, CIDRs: []string{"0.0.0.0/0"}, Reason: "security group sg-1 allows 0.0.0.0/0 on 443"},
		Because:    "export policy allows s3:GetObject on lab-pii",
		Confidence: ConfidenceInferred,
		Evidence:   map[string]any{"source": "iam"},
	}
}

// The wire form is flat: the same keys collectors already write (actions, statement,
// exposure, exposure_cidrs, because) plus the new contract keys.
const sampleEdgeAttrsJSON = `{"actions":["s3:GetObject","s3:ListBucket"],"because":"export policy allows s3:GetObject on lab-pii","conditions":{"Bool":{"aws:SecureTransport":"true"}},"confidence":"inferred","effect":"Allow","evidence":{"source":"iam"},"exposure":"wide","exposure_cidrs":["0.0.0.0/0"],"exposure_reason":"security group sg-1 allows 0.0.0.0/0 on 443","policy_arn":"arn:aws:iam::111111111111:policy/export","requires_conditions":["aws:SecureTransport"],"resources":["arn:aws:s3:::lab-pii","arn:aws:s3:::lab-pii/*"],"statement":"arn:aws:iam::111111111111:policy/export#ExportRead"}`

func TestEdgeAttrsJSONRoundTrip(t *testing.T) {
	a := sampleEdgeAttrs()
	m := a.Map()
	b, err := json.Marshal(m) // map keys marshal sorted: this is the stored attr text
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != sampleEdgeAttrsJSON {
		t.Fatalf("wire form changed:\n got %s\nwant %s", b, sampleEdgeAttrsJSON)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	back, err := ParseEdgeAttrs(generic)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, a)
	}
	// The struct marshals to the same object as the map.
	sb, _ := json.Marshal(a)
	var x, y map[string]any
	json.Unmarshal(sb, &x)
	json.Unmarshal(b, &y)
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("struct JSON %s != map JSON %s", sb, b)
	}
}

func TestEdgeAttrsEmptyAndPartial(t *testing.T) {
	if m := (EdgeAttrs{}).Map(); len(m) != 0 {
		t.Fatalf("empty attrs map = %v", m)
	}
	a, err := ParseEdgeAttrs(map[string]any{"because": "x", "hint": true, "via": "sg-1"})
	if err != nil || a.PermissionAttr != nil || a.Exposure != nil || a.Because != "x" {
		t.Fatalf("partial parse: %+v err=%v", a, err)
	}
	// Unknown keys stay on the map: SetEdgeAttrs merges, never drops.
	m := map[string]any{"via": "sg-1", "actions": "stale"}
	SetEdgeAttrs(m, EdgeAttrs{PermissionAttr: &PermissionAttr{Actions: []string{"s3:*"}}})
	if m["via"] != "sg-1" || !reflect.DeepEqual(m["actions"], []string{"s3:*"}) {
		t.Fatalf("merge: %v", m)
	}
}

func TestEdgeAttrsRejectBadVocabulary(t *testing.T) {
	for _, m := range []map[string]any{
		{"confidence": "probably"},
		{"effect": "Maybe"},
		{"exposure": "huge"},
		{"actions": 7},
	} {
		if _, err := ParseEdgeAttrs(m); err == nil {
			t.Errorf("ParseEdgeAttrs(%v) accepted a value outside the contract", m)
		}
	}
	for _, c := range []Confidence{ConfidenceVerified, ConfidenceInferred, ConfidenceHint} {
		if !c.Valid() {
			t.Errorf("%s invalid", c)
		}
	}
	// "validation" is not an edge key: the name is reserved for the probe status
	// (ValidationResult, validation.go). An edge that carries one is not read as the contract.
	for _, k := range EdgeAttrKeys {
		if k == "validation" {
			t.Fatal("validation must not be an edge attribute key")
		}
	}
	if a, err := ParseEdgeAttrs(map[string]any{"validation": "yes"}); err != nil || !reflect.DeepEqual(a, EdgeAttrs{}) {
		t.Fatalf("validation key leaked into the edge contract: %+v %v", a, err)
	}
}
