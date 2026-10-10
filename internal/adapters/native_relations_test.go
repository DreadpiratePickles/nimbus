package adapters

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Track B2 item 1: the native contract carries typed relationships. testdata/native.findings.json
// mixes a legacy string with typed {id, kind, attr} entries; both parse, and the typed ones keep
// their kind and attributes for the graph builder.
func TestNativeTypedRelations(t *testing.T) {
	fs := parse(t, "native.findings.json", "native")
	byRes := map[string]model.Finding{}
	for _, f := range fs {
		byRes[f.Resource.ID] = f
	}
	fn, ok := byRes["arn:aws:lambda:us-east-1:444455556666:function:report-export"]
	if !ok {
		t.Fatalf("typed-relation sample missing from testdata/native.findings.json (%d records)", len(fs))
	}
	if len(fn.Resource.Relations) != 1 || fn.Resource.Relations[0].Kind != "runs_as" ||
		fn.Resource.Relations[0].ID != "arn:aws:iam::444455556666:role/report-export-role" {
		t.Errorf("lambda relations: %+v", fn.Resource.Relations)
	}
	role := byRes["arn:aws:iam::444455556666:role/report-export-role"]
	if role.Status != model.Pass || len(role.Resource.Relations) != 1 || role.Resource.Relations[0].Kind != "grants_access_to" ||
		role.Resource.Relations[0].Attr["actions"] != "s3:GetObject" {
		t.Errorf("role relations: %+v", role.Resource.Relations)
	}
	if len(role.Resource.Related) != 2 {
		t.Errorf("legacy string + typed id must both be in Related: %v", role.Resource.Related)
	}
}

func TestNativeJSONLinesTypedRelations(t *testing.T) {
	data := []byte(`{"source":"p","check_id":"c","status":"FAIL","resource":{"id":"a","related":[{"id":"b","kind":"runs_as"}]}}
{"source":"p","check_id":"c","status":"FAIL","resource":{"id":"b","related":["c"]}}`)
	fs, err := Native{}.Parse(data, Options{})
	if err != nil || len(fs) != 2 || len(fs[0].Resource.Relations) != 1 || fs[1].Resource.Related[0] != "c" {
		t.Fatalf("jsonl: %v %+v", err, fs)
	}
	if _, err := (Native{}).Parse([]byte(`[{"source":"p","check_id":"c","resource":{"id":"a","related":[{"kind":"runs_as"}]}}]`), Options{}); err == nil {
		t.Error("a typed relation without id must be rejected")
	}
}
