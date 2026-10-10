package cli

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// One verdict everywhere (r2 #1/#8): `paths --exposures --format json` lists every exposure,
// blocked ones included, each with graph.Verdict of its node, so the copilot and other
// surfaces print the engine's wording instead of re-deriving it.
func TestPathsExposuresJSONCarriesVerdicts(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	cfg, err := filepath.Abs(filepath.Join("..", "..", "lab", "local", "cloud-posture.lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	flagConfig = cfg
	t.Cleanup(func() { flagConfig = "" })
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")

	out := run(t, "paths", "--exposures", "--format", "json")
	type row struct {
		NodeID  string        `json:"node_id"`
		Name    string        `json:"name"`
		Width   string        `json:"width"`
		Verdict graph.Verdict `json:"verdict"`
	}
	var doc struct {
		Exposures  []row `json:"exposures"`
		Suppressed []row `json:"suppressed"`
		Entries    []row `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not an exposures JSON object: %v\n%.300s", err, out)
	}
	by := map[string]row{}
	for _, r := range doc.Exposures {
		by[r.Name] = r
		if r.Verdict.NodeID != r.NodeID || r.Verdict.Label == "" && r.Verdict.Status != "" {
			t.Errorf("%s: verdict not for its node or unlabelled: %+v", r.Name, r.Verdict)
		}
		if (r.Width == "blocked") != (r.Verdict.Status == graph.VerdictBlocked) {
			t.Errorf("%s: width %s but verdict %q", r.Name, r.Width, r.Verdict.Status)
		}
	}
	led, ok := by["nimbus-lab-ledger"]
	if !ok {
		t.Fatalf("blocked ledger missing from exposures: %v", by)
	}
	if led.Verdict.Status != graph.VerdictBlocked || led.Verdict.Label == "" {
		t.Fatalf("ledger verdict = %+v", led.Verdict)
	}
	if len(doc.Suppressed) == 0 || len(doc.Entries) == 0 {
		t.Fatalf("suppressed (%d) / entries (%d) missing", len(doc.Suppressed), len(doc.Entries))
	}
	for _, r := range doc.Entries {
		if r.Verdict.Status == graph.VerdictBlocked {
			t.Errorf("path entry %s is blocked: %+v", r.Name, r.Verdict)
		}
	}
}
