package catalog

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// IaC-track addendum (c): the IAC_PARSE_LIMIT ERROR finding (a file that exceeded the
// parser's size/nesting limits and was not scanned) has a catalog entry.
func TestIaCParseLimitEntry(t *testing.T) {
	c := Default()
	e, ok := c.Get("IAC_PARSE_LIMIT")
	if !ok {
		t.Fatal("IAC_PARSE_LIMIT missing from catalog.yaml")
	}
	if e.Provider != model.ProviderIaC || e.Severity != model.Info || e.ResourceType != "file" || e.Title == "" {
		t.Fatalf("entry: %+v", e)
	}
	if got, ok := c.Lookup("nimbus-iac", "IAC_PARSE_LIMIT"); !ok || got.ID != "IAC_PARSE_LIMIT" {
		t.Fatalf("lookup by the scanner's check id: %v %v", got, ok)
	}
	f := model.Finding{Source: "nimbus-iac", CheckID: "IAC_PARSE_LIMIT", Status: model.Error, Severity: model.Medium}
	c.Enrich(&f)
	if f.CanonicalID != "IAC_PARSE_LIMIT" || f.Status != model.Error || f.Severity != model.Medium || len(f.Weaknesses) != 0 {
		t.Fatalf("enrich must keep the ERROR status and the emitted severity, add no weakness: %+v", f)
	}
}
