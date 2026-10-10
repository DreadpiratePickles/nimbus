package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Coordinator item 18 (W6-VERIFY handoff, r4 #15): a redacted DB-less output (pr-comment SARIF
// and --diff-json on a public repository) never carries the raw path-Issue digest next to
// redacted names — ids are run-keyed (output.RunKeyer, NIMBUS_ID_KEY for stable ids) — and an
// unredacted one says its ids are unkeyed.
func TestPRCommentOutputsKeyOrLabelIDs(t *testing.T) {
	type sarifDoc struct {
		Runs []struct {
			Properties map[string]any `json:"properties"`
			Results    []struct {
				PF    map[string]string `json:"partialFingerprints"`
				Props map[string]any    `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	read := func(redact string) (sarifDoc, map[string]any) {
		dir := t.TempDir()
		sarif, js := filepath.Join(dir, "p.sarif"), filepath.Join(dir, "d.json")
		old := exitFn
		exitFn = func(int) {}
		defer func() { exitFn = old }()
		planComment(t, "--plan-json", fixturePlan("bad.plan.json"), "--sarif", sarif, "--diff-json", js, "--redact", redact)
		var d sarifDoc
		b, _ := os.ReadFile(sarif)
		if err := json.Unmarshal(b, &d); err != nil || len(d.Runs) != 1 || len(d.Runs[0].Results) != 1 {
			t.Fatalf("sarif: %v\n%s", err, b)
		}
		var m map[string]any
		b, _ = os.ReadFile(js)
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("diff json: %v", err)
		}
		return d, m
	}
	raw, rawJSON := read("off")
	rawID := raw.Runs[0].Results[0].PF["nimbusPathIssue/v1"]
	if raw.Runs[0].Properties["nimbus_id_scheme"] != "unkeyed" || rawJSON["id_scheme"] != "unkeyed" || len(rawID) != 32 {
		t.Errorf("unredacted outputs must be labelled unkeyed: %v / %v / %q", raw.Runs[0].Properties, rawJSON["id_scheme"], rawID)
	}
	t.Setenv("NIMBUS_ID_KEY", "")
	red, redJSON := read("on")
	r := red.Runs[0].Results[0]
	id := r.PF["nimbusPathIssue/v1"]
	if !strings.HasPrefix(id, "run-") || r.Props["issue_id"] != id || id == rawID || strings.Contains(id, rawID) {
		t.Errorf("redacted SARIF id %q (props %v), raw %q", id, r.Props["issue_id"], rawID)
	}
	if red.Runs[0].Properties["nimbus_id_scheme"] != "run-keyed" || redJSON["id_scheme"] != "run-keyed" {
		t.Errorf("redacted outputs must be labelled run-keyed: %v / %v", red.Runs[0].Properties, redJSON["id_scheme"])
	}
	b, _ := json.Marshal(redJSON)
	if strings.Contains(string(b), rawID) {
		t.Error("redacted --diff-json still carries the raw path Issue digest")
	}
	// A configured key makes run-keyed ids stable across runs (alert continuity).
	t.Setenv("NIMBUS_ID_KEY", "0123456789abcdef0123456789abcdef")
	a, _ := read("on")
	c, _ := read("on")
	if a.Runs[0].Results[0].PF["nimbusPathIssue/v1"] != c.Runs[0].Results[0].PF["nimbusPathIssue/v1"] {
		t.Error("NIMBUS_ID_KEY must make run-keyed ids stable")
	}
}
