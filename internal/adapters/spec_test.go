package adapters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/output"
)

// Plan v3 RP6 acceptance: every adapter's golden output validates against the published
// finding contract (docs/spec/finding-v1.schema.json), and so does the output of every
// pre-existing adapter fixture.
func TestAdapterOutputMatchesFindingSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "spec", "finding-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := output.CompileSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	check := func(label string, findingsJSON []byte) {
		var arr []any
		dec := json.NewDecoder(bytes.NewReader(findingsJSON))
		dec.UseNumber()
		if err := dec.Decode(&arr); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if len(arr) == 0 {
			t.Errorf("%s: no findings", label)
		}
		for i, f := range arr {
			if errs := schema.ValidateAt("#/$defs/finding", f); len(errs) > 0 {
				t.Errorf("%s[%d]: %v", label, i, errs)
			}
		}
	}
	goldens, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "golden", "adapters", "*.golden.json"))
	if len(goldens) < 4 {
		t.Fatalf("expected the adapter goldens, found %v", goldens)
	}
	for _, g := range goldens {
		b, err := os.ReadFile(g)
		if err != nil {
			t.Fatal(err)
		}
		var sets []struct {
			Fixture  string          `json:"fixture"`
			Findings json.RawMessage `json:"findings"`
		}
		if err := json.Unmarshal(b, &sets); err != nil {
			t.Fatalf("%s: %v", g, err)
		}
		for _, s := range sets {
			check(filepath.Base(g)+":"+s.Fixture, s.Findings)
		}
	}
	for _, fx := range []string{"prowler.ocsf.json", "checkov.json", "trivy.json", "steampipe.json", "scoutsuite_results_azure.js", "native.findings.json"} {
		fs, _, err := ParseFile(filepath.Join("..", "..", "testdata", fx), "", Options{Now: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		b, _ := json.Marshal(fs)
		check(fx, b)
	}
}

// The versioned envelope nimbus writes ({"spec_version","findings"}) is native input too.
func TestNativeReadsVersionedEnvelope(t *testing.T) {
	doc := []byte(`{"spec_version":"1.0.0","findings":[{"source":"p","check_id":"c","status":"FAIL","resource":{"id":"a","related":[{"id":"b","kind":"runs_as"}]}}]}`)
	a, ok := Detect("out.json", doc)
	if !ok || a.Name() != "native" {
		t.Fatalf("envelope detected as %v", a)
	}
	fs, err := Native{}.Parse(doc, Options{})
	if err != nil || len(fs) != 1 || len(fs[0].Resource.Relations) != 1 {
		t.Fatalf("envelope parse: %v %+v", err, fs)
	}
	if _, err := (Native{}).Parse([]byte(`{"spec_version":"2.0.0","findings":[{"source":"p","check_id":"c"}]}`), Options{}); err == nil {
		t.Error("a 2.x document must be refused by a 1.x reader")
	}
}

func TestEveryAdapterDeclaresSupportedVersion(t *testing.T) {
	v := Versions()
	for _, a := range All() {
		if v[a.Name()] == "" {
			t.Errorf("adapter %s does not declare SupportedVersion()", a.Name())
		}
	}
}
