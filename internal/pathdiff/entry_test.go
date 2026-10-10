package pathdiff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
)

// Verifier defect D5 (verify-4): the path Issue key's entry is "internet" for every internet
// path, so a plan that puts a second public host in front of an anchor that is already reachable
// opened nothing. pathdiff keys paths by attackpath.EntryKey (internet:<exposed node>), so the
// new entry is OPENED and trips --fail-on-opened.

// fixtureRaw is bad.plan.json decoded, with edit applied to every resource change.
func fixtureRaw(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "action-fixture", "plans", "bad.plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func parseRaw(t *testing.T, raw map[string]any) *iac.Plan {
	t.Helper()
	out, _ := json.Marshal(raw)
	p, err := iac.ParsePlanJSON(out, iac.PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// secondHostPlan: base = one public SSH host (0.0.0.0/0 already) reaching the admin role; head
// = the same plus a second instance (create) with the same security group and instance profile.
func secondHostPlan(t *testing.T) *iac.Plan { return parseRaw(t, secondHostRaw(t, false)) }

// secondHostRaw builds the plan; removed=true is the reverse PR (base has both hosts, the plan
// deletes the second one).
func secondHostRaw(t *testing.T, removed bool) map[string]any {
	t.Helper()
	raw := fixtureRaw(t)
	rcs := raw["resource_changes"].([]any)
	var host map[string]any
	for _, rc := range rcs {
		m := rc.(map[string]any)
		ch := m["change"].(map[string]any)
		switch m["type"] {
		case "aws_security_group":
			ch["before"] = ch["after"]
			ch["actions"] = []any{"no-op"}
		case "aws_instance":
			host = m
		}
	}
	if host == nil {
		t.Fatal("fixture has no aws_instance")
	}
	b, _ := json.Marshal(host)
	var h2 map[string]any
	json.Unmarshal(b, &h2)
	h2["address"], h2["name"] = "module.web.aws_instance.host2", "host2"
	ch := h2["change"].(map[string]any)
	after := ch["after"].(map[string]any)
	after["arn"], after["id"] = nil, nil
	after["public_ip"] = "198.51.100.77"
	after["tags"] = map[string]any{"Name": "fixture-host-2"}
	ch["before"], ch["actions"] = nil, []any{"create"}
	if removed {
		after["arn"] = "arn:aws:ec2:us-east-1:123456789012:instance/i-0fixturehost2"
		after["id"] = "i-0fixturehost2"
		ch["before"], ch["after"], ch["actions"] = after, nil, []any{"delete"}
	}
	raw["resource_changes"] = append(rcs, h2)
	return raw
}

func TestSecondPublicHostOpensAPath(t *testing.T) {
	r := Diff(nil, nil, secondHostPlan(t), opts())
	if len(r.Opened) != 1 || len(r.Closed) != 0 {
		t.Fatalf("second public host: opened %d closed %d, want 1 / 0 (changed %+v)", len(r.Opened), len(r.Closed), r.ChangedScore)
	}
	o := r.Opened[0]
	if o.Entry != "internet" || !strings.Contains(o.EntryKey, "host2") || len(o.Hops) == 0 || !strings.Contains(o.Hops[0].ID, "host2") {
		t.Errorf("opened path enters at %q (key %q), hops %+v; want the new host", o.Entry, o.EntryKey, o.Hops)
	}
	if !r.GateTripped(false) || !r.GateTripped(true) {
		t.Error("a newly exposed entry must trip --fail-on-opened (also with --opened-only)")
	}
	// the reverse PR (the second host removed) closes that entry, and only it
	r = Diff(nil, nil, parseRaw(t, secondHostRaw(t, true)), opts())
	if len(r.Opened) != 0 || len(r.Closed) != 1 || !strings.Contains(r.Closed[0].EntryKey, "host2") {
		t.Fatalf("second host removed: opened %d closed %+v, want 0 / the host2 entry", len(r.Opened), r.Closed)
	}
	if r.GateTripped(false) {
		t.Error("removing an entry tripped the gate")
	}
}
