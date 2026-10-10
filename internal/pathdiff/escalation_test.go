package pathdiff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Shortfall #7 (competitive delta 2026-10-09): a plan that keeps a path Issue but raises its band
// into High or Critical is an escalation. It is reported in Result.Escalated, and the
// --fail-on-opened gate (Result.GateCount / GateTripped) counts it like an opened path.
//
// Fixture: bad.plan.json with its before-side SG narrowed to a specific public range
// (198.51.100.0/24, not trusted): before, the SSH host → admin role path exists but is narrow
// (no toxic floor); after, the plan opens 22 to 0.0.0.0/0 and the same Issue is floored to ≥ 7.
func narrowBadPlan(t *testing.T) *iac.Plan {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "action-fixture", "plans", "bad.plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rc := range raw["resource_changes"].([]any) {
		m := rc.(map[string]any)
		if m["type"] != "aws_security_group" {
			continue
		}
		before := m["change"].(map[string]any)["before"].(map[string]any)
		for _, in := range before["ingress"].([]any) {
			in.(map[string]any)["cidr_blocks"] = []any{"198.51.100.0/24"}
			n++
		}
	}
	if n == 0 {
		t.Fatal("fixture has no SG ingress to narrow")
	}
	out, _ := json.Marshal(raw)
	p, err := iac.ParsePlanJSON(out, iac.PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEscalatedCountsAndGates(t *testing.T) {
	r := Diff(nil, nil, narrowBadPlan(t), opts())
	if len(r.Opened) != 0 || len(r.Closed) != 0 {
		t.Fatalf("narrow → wide should keep the Issue: opened %d closed %d", len(r.Opened), len(r.Closed))
	}
	if len(r.Escalated) != 1 {
		t.Fatalf("escalated %d, want 1 (changed: %+v)", len(r.Escalated), r.ChangedScore)
	}
	e := r.Escalated[0]
	t.Logf("escalated %s: %.2f %s → %.2f %s", e.Path.AnchorName, e.Before, e.BandBefore, e.After, e.BandAfter)
	if model.ScoreBand(e.Before) == "High" || model.ScoreBand(e.Before) == "Critical" || e.After < 7 {
		t.Errorf("escalation %.2f (%s) → %.2f (%s)", e.Before, model.ScoreBand(e.Before), e.After, model.ScoreBand(e.After))
	}
	if e.BandBefore != model.ScoreBand(e.Before) || e.BandAfter != model.ScoreBand(e.After) || e.Path.Band != e.BandAfter {
		t.Errorf("bands on the change: %+v", e)
	}
	if r.GateCount(false) != 1 || !r.GateTripped(false) {
		t.Errorf("--fail-on-opened must trip on an escalation: count %d", r.GateCount(false))
	}
	if r.GateTripped(true) {
		t.Error("--opened-only must ignore escalations")
	}
}

func TestEscalationRule(t *testing.T) {
	for _, c := range []struct {
		before, after float64
		want          bool
	}{
		{1.9, 7.0, true}, // Low → High (the delta review's bad.plan case)
		{5.2, 7.0, true}, // Medium → High
		{7.0, 9.1, true}, // High → Critical
		{1.9, 4.9, false},
		{1.9, 5.0, false}, // Low → Medium: a change, not an escalation
		{7.0, 8.9, false}, // same band
		{9.1, 7.0, false}, // de-escalation
	} {
		if got := Escalates(c.before, c.after); got != c.want {
			t.Errorf("Escalates(%.1f, %.1f) = %v, want %v", c.before, c.after, got, c.want)
		}
	}
}

func TestNoEscalationOnUnchangedPlans(t *testing.T) {
	r := Diff(nil, nil, plan(t, "bad.plan.json"), opts())
	if len(r.Escalated) != 0 || r.GateCount(false) != len(r.Opened) {
		t.Errorf("bad.plan (opens): escalated %d gate %d opened %d", len(r.Escalated), r.GateCount(false), len(r.Opened))
	}
}
