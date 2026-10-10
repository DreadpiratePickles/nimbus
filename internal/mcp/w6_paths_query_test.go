package mcp

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
)

// W6-ENGINE item 4 (competitive delta r4 #10): the MCP `paths` tool takes the CLI's graph-query
// arguments (from / to / through / max_hops) and answers from the same attackpath.Query over the
// stored graph, read-only. Bar: Wiz Security Graph Explorer / Prowler attack-path queries.
func TestMCPPathsQueryMirrorsCLI(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Traversal: labTraversal})
	c.initialize()
	before, _ := fx.st.AttackPaths()

	q := attackpath.PathQuery{From: "internet", To: "type:aws_s3_bucket", Through: "type:aws_iam_role", MaxHops: 4}
	g, err := storeReader{fx.st}.LoadGraph()
	if err != nil {
		t.Fatal(err)
	}
	want, err := attackpath.Query(g, labTraversal(g), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.Paths) == 0 {
		t.Fatal("fixture query returns no paths; pick another query")
	}
	res := c.toolOK("paths", map[string]any{"from": q.From, "to": q.To, "through": q.Through, "max_hops": q.MaxHops})
	paths, _ := res["paths"].([]any)
	if len(paths) != len(want.Paths) {
		t.Fatalf("MCP query returned %d paths, attackpath.Query %d", len(paths), len(want.Paths))
	}
	for i, p := range paths {
		m := p.(map[string]any)
		if m["id"] != fx.st.ExternalPathID(want.Paths[i].ID) { // ids leave MCP keyed (W6-VERIFY, store/extid.go)
			t.Errorf("path %d id %v, want %s (same order as the CLI)", i, m["id"], fx.st.ExternalPathID(want.Paths[i].ID))
		}
		for _, h := range m["hops"].([]any) {
			if h.(map[string]any)["because"] == "" {
				t.Errorf("path %v has a hop without because", m["id"])
			}
		}
	}
	if qq, _ := res["query"].(map[string]any); qq == nil || qq["through"] != q.Through || int(qq["max_hops"].(float64)) != 4 {
		t.Errorf("result does not echo the query: %v", res["query"])
	}
	if res["from_nodes"] == nil || res["to_nodes"] == nil {
		t.Errorf("result lacks from_nodes/to_nodes: %v", keys(res))
	}
	// Read-only: the stored paths are unchanged.
	after, _ := fx.st.AttackPaths()
	if len(after) != len(before) {
		t.Errorf("paths query changed the store: %d → %d stored paths", len(before), len(after))
	}
	// Bad arguments are tool errors, not crashes.
	for _, bad := range []map[string]any{
		{"from": "internet"}, // no to
		{"from": "internet", "to": "no-such-node-anywhere"},              // unresolvable selector
		{"from": "internet", "to": "type:aws_s3_bucket", "max_hops": 99}, // over the limit
		{"from": "internet", "to": "type:aws_s3_bucket", "max_hops": 0},  // 0 is an error, never 6
	} {
		if tr, r := c.tool("paths", bad); r.Error == nil && !tr.IsError {
			t.Errorf("paths %v: want a tool error", bad)
		}
	}
	// Without query arguments the tool still lists Issues.
	if res := c.toolOK("paths", map[string]any{"limit": 5}); res["issues"] == nil {
		t.Errorf("filter-only call lost the issues list: %v", keys(res))
	}
}
