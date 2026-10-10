package output

import (
	"strings"
	"testing"
)

// The vendored validator covers the draft-07 keywords used by the OCSF 1.6 class schema and
// docs/spec/finding-v1.schema.json. Each keyword gets a pass and a fail case.
func TestJSONSchemaKeywords(t *testing.T) {
	schema := []byte(`{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "type": "object", "additionalProperties": false,
	  "required": ["kind", "n"],
	  "properties": {
	    "kind": {"enum": ["a", "b"]},
	    "n": {"type": "integer", "minimum": 0},
	    "c": {"const": 2004},
	    "s": {"type": "string", "minLength": 2, "pattern": "^[a-z]+$"},
	    "list": {"type": "array", "items": {"$ref": "#/$defs/item"}},
	    "any": {"anyOf": [{"type": "string"}, {"$ref": "#/$defs/item"}]},
	    "one": {"oneOf": [{"required": ["x"], "not": {"required": ["y"]}}, {"required": ["y"], "not": {"required": ["x"]}}]},
	    "free": {"type": ["string", "null"]}
	  },
	  "$defs": {"item": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}}
	}`)
	s, err := CompileSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{
		`{"kind":"a","n":0}`,
		`{"kind":"b","n":3,"c":2004,"s":"ab","list":[{"id":"x"}],"any":"str","one":{"x":1},"free":null}`,
		`{"kind":"b","n":3,"any":{"id":"y"},"one":{"y":1},"free":"s"}`,
	}
	for _, doc := range ok {
		if errs := s.ValidateJSON([]byte(doc)); len(errs) > 0 {
			t.Errorf("%s: unexpected errors %v", doc, errs)
		}
	}
	bad := map[string]string{
		`{"n":1}`:                                "required",
		`{"kind":"z","n":1}`:                     "enum",
		`{"kind":"a","n":1.5}`:                   "integer",
		`{"kind":"a","n":-1}`:                    "minimum",
		`{"kind":"a","n":1,"c":2003}`:            "const",
		`{"kind":"a","n":1,"s":"a"}`:             "minLength",
		`{"kind":"a","n":1,"s":"AB"}`:            "pattern",
		`{"kind":"a","n":1,"list":[{}]}`:         "list[0]",
		`{"kind":"a","n":1,"any":5}`:             "anyOf",
		`{"kind":"a","n":1,"one":{"x":1,"y":1}}`: "oneOf",
		`{"kind":"a","n":1,"extra":true}`:        "additional",
		`{"kind":"a","n":1,"free":3}`:            "type",
	}
	for doc, want := range bad {
		errs := s.ValidateJSON([]byte(doc))
		if len(errs) == 0 {
			t.Errorf("%s: want error mentioning %q, got none", doc, want)
			continue
		}
		if !strings.Contains(strings.Join(errStrings(errs), "\n"), want) {
			t.Errorf("%s: errors %v do not mention %q", doc, errs, want)
		}
	}
}

func errStrings(errs []error) []string {
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Error()
	}
	return out
}
