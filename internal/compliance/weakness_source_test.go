package compliance

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

// TestWeaknessMappingsSingleSource: Go's weakness -> control mapping (extra.yaml) is the only
// source; the Python bundle's weakness_mappings is generated from it and must equal it exactly.
func TestWeaknessMappingsSingleSource(t *testing.T) {
	if _, err := os.Stat("python_weakness_mappings.yaml"); err == nil {
		t.Errorf("python_weakness_mappings.yaml still exists: Python must consume Go's mapping (extra.yaml), not a hand-kept copy")
	}
	data, err := os.ReadFile(pythonBundle)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		WeaknessMappings map[string]map[string][]string `json:"weakness_mappings"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	goWM := WeaknessMappings()
	if len(goWM) == 0 {
		t.Fatal("go has no weakness mappings")
	}
	if len(b.WeaknessMappings) != len(goWM) {
		t.Errorf("python bundle has %d weakness mappings, go %d", len(b.WeaknessMappings), len(goWM))
	}
	var diff []string
	for w, m := range goWM {
		if !reflect.DeepEqual(b.WeaknessMappings[w], m) {
			diff = append(diff, w)
		}
	}
	for w := range b.WeaknessMappings {
		if _, ok := goWM[w]; !ok {
			diff = append(diff, w+" (python only)")
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		t.Errorf("weakness mappings differ between go and the python bundle: %v", diff)
	}
}
