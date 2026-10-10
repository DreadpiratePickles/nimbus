package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Track B2 item 1: `related` entries may be legacy strings or typed objects {id, kind, attr}.
func TestResourceRelatedAcceptsStringsAndTypedObjects(t *testing.T) {
	in := `{"id":"arn:aws:iam::1:role/r","type":"aws_iam_role","related":[
		"arn:aws:ec2:us-east-1:1:instance/i-1",
		{"id":"arn:aws:s3:::pii","kind":"grants_access_to","attr":{"actions":"s3:GetObject","because":"inline policy export"}},
		{"id":"arn:aws:iam::999:root","kind":"trusts"}]}`
	var r Resource
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	wantRelated := []string{"arn:aws:ec2:us-east-1:1:instance/i-1", "arn:aws:s3:::pii", "arn:aws:iam::999:root"}
	if !reflect.DeepEqual(r.Related, wantRelated) {
		t.Errorf("Related = %v, want every id (legacy consumers keep working) %v", r.Related, wantRelated)
	}
	if len(r.Relations) != 2 || r.Relations[0].Kind != "grants_access_to" || r.Relations[0].ID != "arn:aws:s3:::pii" ||
		r.Relations[0].Attr["actions"] != "s3:GetObject" || r.Relations[1].Kind != "trusts" {
		t.Fatalf("Relations = %+v", r.Relations)
	}
	// Round trip: related stays a string list (Python SDK and the store read it as list[str]);
	// typed entries travel in `relations` and survive.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	json.Unmarshal(b, &raw)
	for _, x := range raw["related"].([]any) {
		if _, ok := x.(string); !ok {
			t.Errorf("marshalled related must be strings only: %s", b)
		}
	}
	var back Resource
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Related, r.Related) || !reflect.DeepEqual(back.Relations, r.Relations) {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", back, r)
	}
}

func TestResourceRelatedRejectsBadEntries(t *testing.T) {
	for _, in := range []string{
		`{"id":"x","related":[{"kind":"runs_as"}]}`, // object without id
		`{"id":"x","related":[{"id":"y"}]}`,         // object without kind
		`{"id":"x","related":[42]}`,                 // not a string or object
	} {
		var r Resource
		if err := json.Unmarshal([]byte(in), &r); err == nil {
			t.Errorf("%s: want an error", in)
		}
	}
	var r Resource
	if err := json.Unmarshal([]byte(`{"id":"x","related":null}`), &r); err != nil || r.Related != nil {
		t.Errorf("null related: %v %v", err, r.Related)
	}
}
