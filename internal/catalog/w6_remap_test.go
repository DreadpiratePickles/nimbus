package catalog

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W6-ENGINE item 3: `catalog unmapped` should read the stored DB's findings. Stored findings were
// enriched at ingest time, so a check id an alias added later still carries its "<TOOL>:<check>"
// fallback; Remapped re-resolves canonical ids against the current catalog for coverage.
func TestRemappedUsesTheCurrentCatalog(t *testing.T) {
	in := []model.Finding{
		{ID: "a", Source: "checkov", CheckID: "CKV_AWS_260", CanonicalID: "CHECKOV:CKV_AWS_260", Status: model.Fail},
		{ID: "b", Source: "checkov", CheckID: "CKV_AWS_135", CanonicalID: "CHECKOV:CKV_AWS_135", Status: model.Fail},
		{ID: "c", Source: "trivy", CheckID: "AVD-AZU-0047", CanonicalID: "", Status: model.Fail},
	}
	out := Default().Remapped(in)
	want := map[string]string{"a": "EC2_SG_OPEN_HTTP", "b": "CHECKOV:CKV_AWS_135", "c": "AZ_NSG_UNRESTRICTED_SOURCE"}
	for _, f := range out {
		if f.CanonicalID != want[f.ID] {
			t.Errorf("%s: canonical %q, want %q", f.ID, f.CanonicalID, want[f.ID])
		}
	}
	if in[0].CanonicalID != "CHECKOV:CKV_AWS_260" {
		t.Error("Remapped modified its input")
	}
}
