package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

const specSchemaPath = "../../docs/spec/finding-v1.schema.json"

// The published schema is generated from internal/model; a model change without
// `go generate ./internal/output` (and a doc entry for any new field) fails here.
func TestFindingSchemaMatchesModel(t *testing.T) {
	want, err := FindingSchemaJSON()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(specSchemaPath)
	if err != nil {
		t.Fatalf("%v — run `go generate ./internal/output`", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("docs/spec/finding-v1.schema.json is stale — run `go generate ./internal/output`:\n%s", firstDiff(string(want), string(got)))
	}
	doc, _ := os.ReadFile("../../docs/spec/finding-v1.md")
	for key := range fieldDocs {
		_, field, _ := strings.Cut(key, ".")
		if !bytes.Contains(doc, []byte("`"+field+"`")) {
			t.Errorf("docs/spec/finding-v1.md does not document field %s", key)
		}
	}
}

func specSchema(t *testing.T) *Schema {
	t.Helper()
	b, err := os.ReadFile(specSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := CompileSchema(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFindingSchemaValidatesNativeDocuments(t *testing.T) {
	s := specSchema(t)
	if errs := s.ValidateJSON(mustJSON(t, NativeDocument(loadInput(t)))); len(errs) > 0 {
		t.Errorf("envelope: %v", errs)
	}
	for _, path := range []string{"../../testdata/native.findings.json", goldenDir + "/input.findings.json"} {
		b, _ := os.ReadFile(path)
		var arr []any
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(&arr); err != nil {
			t.Fatal(err)
		}
		for i, f := range arr {
			if errs := s.ValidateAt("#/$defs/finding", f); len(errs) > 0 {
				t.Errorf("%s[%d]: %v", path, i, errs)
			}
		}
	}
	bad := map[string]string{
		`{"source":"x","check_id":"y","severity":"high"}`: "enum",
		`{"source":"x"}`:                      "anyOf",
		`{"canonical_id":"X","colour":"red"}`: "colour",
		`{"canonical_id":"X","resource":{"id":"a","related":[{"kind":"runs_as"}]}}`: "related[0]",
		`{"canonical_id":"X","line_start":-1}`:                                      "minimum",
	}
	for doc, want := range bad {
		var v any
		dec := json.NewDecoder(strings.NewReader(doc))
		dec.UseNumber()
		dec.Decode(&v)
		errs := s.ValidateAt("#/$defs/finding", v)
		if !strings.Contains(strings.Join(errStrings(errs), "\n"), want) {
			t.Errorf("%s: want error mentioning %q, got %v", doc, want, errs)
		}
	}
}

// Every documented relation kind is one the graph builder resolves.
func TestRelationKindsResolveInGraph(t *testing.T) {
	for _, k := range RelationKinds {
		if _, _, ok := graph.RelationEdge(k); !ok {
			t.Errorf("relation kind %q is documented but graph.RelationEdge does not know it", k)
		}
	}
}
