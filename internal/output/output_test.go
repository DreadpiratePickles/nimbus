package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// SARIF 2.1.0 requires runs[].results to be an array; a clean scan must emit [] (not null),
// or code-scanning upload rejects the file.
func TestSARIFCleanScanHasEmptyResultsArray(t *testing.T) {
	for name, fs := range map[string][]model.Finding{
		"nil":       nil,
		"only pass": {{CanonicalID: "X", Status: model.Pass, Severity: model.High}},
	} {
		var buf bytes.Buffer
		if err := JSON(&buf, SARIF(fs)); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []map[string]json.RawMessage `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || len(doc.Runs) != 1 {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.TrimSpace(string(doc.Runs[0]["results"])); got != "[]" {
			t.Errorf("%s: results = %s, want []", name, got)
		}
		var tool struct {
			Driver struct {
				Rules json.RawMessage `json:"rules"`
			} `json:"driver"`
		}
		json.Unmarshal(doc.Runs[0]["tool"], &tool)
		if got := strings.TrimSpace(string(tool.Driver.Rules)); got != "[]" {
			t.Errorf("%s: rules = %s, want []", name, got)
		}
	}
}
