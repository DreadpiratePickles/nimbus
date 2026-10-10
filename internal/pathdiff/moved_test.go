package pathdiff

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// Verify-4/5 D6 (strict replacement of the old TestAnchorRenameDoesNotMultiply, which accepted
// opened 1 + closed 1): renaming the anchor of a path that is already open (the admin role is
// recreated under a new name and the instance profile / attachment follow it) is a MOVED path,
// not an opened one. It must not trip --fail-on-opened, with or without --opened-only, and it
// must not be counted as closed either.
func TestAnchorRenameIsMovedNotOpened(t *testing.T) {
	raw := fixtureRaw(t)
	for _, rc := range raw["resource_changes"].([]any) {
		m := rc.(map[string]any)
		ch := m["change"].(map[string]any)
		after, _ := ch["after"].(map[string]any)
		switch m["type"] {
		case "aws_security_group":
			ch["before"] = ch["after"]
			ch["actions"] = []any{"no-op"}
		case "aws_iam_role":
			after["arn"] = "arn:aws:iam::123456789012:role/fixture-host-role-v2"
			after["name"], after["id"] = "fixture-host-role-v2", "fixture-host-role-v2"
			ch["actions"] = []any{"delete", "create"}
		case "aws_iam_instance_profile", "aws_iam_role_policy_attachment":
			after["role"] = "fixture-host-role-v2"
			ch["actions"] = []any{"update"}
		}
	}
	r := Diff(nil, nil, parseRaw(t, raw), opts())
	// strict: exactly zero opened and zero closed (the old guard accepted 1 + 1)
	if len(r.Opened) != 0 || len(r.Closed) != 0 {
		t.Fatalf("anchor rename: opened %d closed %d, want 0 / 0", len(r.Opened), len(r.Closed))
	}
	if r.GateTripped(true) || r.GateTripped(false) {
		t.Error("a pure anchor rename tripped --fail-on-opened")
	}
}

// pairMoved directly: an opened and a closed path with the same entry whose anchor was
// replaced by a new resource of the same type is one moved path; a new anchor of another type,
// or an old anchor that still exists after, is not.
func TestPairMovedAnchorReplaced(t *testing.T) {
	before, after := graph.New(), graph.New()
	before.AddNode(&graph.Node{ID: "role-old", Type: "aws_iam_role"})
	before.AddNode(&graph.Node{ID: "host", Type: "aws_instance"})
	after.AddNode(&graph.Node{ID: "role-new", Type: "aws_iam_role"})
	after.AddNode(&graph.Node{ID: "host", Type: "aws_instance"})
	mk := func(anchor, typ string, score float64) PathRef {
		return PathRef{IssueID: "id-" + anchor, Entry: "internet", EntryKey: "internet:host", Anchor: anchor, AnchorType: typ, Rule: "GRAPH_TRAVERSAL", Score: score}
	}
	r := Result{Opened: []PathRef{mk("role-new", "aws_iam_role", 7)}, Closed: []PathRef{mk("role-old", "aws_iam_role", 7)}}
	pairMoved(&r, before, after)
	if len(r.Moved) != 1 || len(r.Opened) != 0 || len(r.Closed) != 0 || r.GateTripped(true) || r.GateTripped(false) {
		t.Fatalf("anchor replaced: moved %d opened %d closed %d", len(r.Moved), len(r.Opened), len(r.Closed))
	}
	// the move lands on a higher band: an escalation (gates without --opened-only)
	r = Result{Opened: []PathRef{mk("role-new", "aws_iam_role", 9.5)}, Closed: []PathRef{mk("role-old", "aws_iam_role", 4)}}
	pairMoved(&r, before, after)
	if len(r.Moved) != 1 || len(r.Escalated) != 1 || !r.GateTripped(false) || r.GateTripped(true) {
		t.Fatalf("escalating move: moved %d escalated %d", len(r.Moved), len(r.Escalated))
	}
	// the old anchor still exists after: two different paths, not a move
	after.AddNode(&graph.Node{ID: "role-old", Type: "aws_iam_role"})
	r = Result{Opened: []PathRef{mk("role-new", "aws_iam_role", 7)}, Closed: []PathRef{mk("role-old", "aws_iam_role", 7)}}
	pairMoved(&r, before, after)
	if len(r.Moved) != 0 || len(r.Opened) != 1 {
		t.Fatalf("old anchor kept: moved %d opened %d, want 0 / 1", len(r.Moved), len(r.Opened))
	}
}

// The blue/green host swap (verify-5 LOW): the public host is replaced by a new one with the
// same security group and role in the same plan. The path to the same anchor moves to a new
// entry; nothing new is reachable, so the gate stays green.
func TestHostSwapIsMovedNotOpened(t *testing.T) {
	raw := secondHostRaw(t, false)
	for _, rc := range raw["resource_changes"].([]any) {
		m := rc.(map[string]any)
		if m["type"] == "aws_instance" && m["name"] != "host2" {
			ch := m["change"].(map[string]any)
			ch["after"], ch["actions"] = nil, []any{"delete"}
		}
	}
	r := Diff(nil, nil, parseRaw(t, raw), opts())
	if len(r.Opened) != 0 || len(r.Closed) != 0 || len(r.Moved) != 1 {
		t.Fatalf("host swap: opened %d closed %d moved %d, want 0 / 0 / 1", len(r.Opened), len(r.Closed), len(r.Moved))
	}
	if r.GateTripped(true) {
		t.Error("a blue/green host swap tripped --opened-only")
	}
}

// Guards: a second host that is ADDED (the old one stays) is still opened (D5), and a moved
// path that lands on a higher band is an escalation, so it still gates without --opened-only.
func TestMovedDoesNotHideNewEntries(t *testing.T) {
	r := Diff(nil, nil, secondHostPlan(t), opts())
	if len(r.Opened) != 1 || len(r.Moved) != 0 {
		t.Fatalf("second host added: opened %d moved %d, want 1 / 0", len(r.Opened), len(r.Moved))
	}
}
