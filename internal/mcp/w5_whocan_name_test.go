package mcp

import (
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// A client that names the resource ("nimbus-lab-customer-pii", as a user would) gets the same
// principals as with its ARN: a unique node name resolves to the node id first. Observed on the lab
// before the fix: 19 principals by name vs 21 by ARN (the CLI's answer).
func TestWhoCanResolvesAResourceName(t *testing.T) {
	fx := newFixture(t)
	g, _ := storeReader{fx.st}.LoadGraph()
	want := graph.WhoCan(g, "s3:GetObject", "arn:aws:s3:::nimbus-lab-customer-pii", 4)
	c := startServer(t, fx.st, Options{NoRedact: true})
	c.initialize()
	res := c.toolOK("who_can", map[string]any{"action": "s3:GetObject", "resource": "nimbus-lab-customer-pii"})
	if n := int(res["count"].(float64)); n != len(want) || len(want) == 0 {
		t.Fatalf("who_can by name: %d principals, by ARN %d", n, len(want))
	}
	if res["resource"] != "arn:aws:s3:::nimbus-lab-customer-pii" {
		t.Errorf("resolved resource %v", res["resource"])
	}
}
