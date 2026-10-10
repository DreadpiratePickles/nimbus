package graph_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

// W7-POLISH: one name-resolution rule for who-can, shared by the CLI (cli/whocan.go) and the MCP
// who_can tool (mcp/tools.go). A bare name that exactly one node carries resolves to that node's
// id; ids, ARNs and paths are used as given; an unknown or shared name is an error naming the
// candidates (the MCP tool keeps the input on error, the CLI prints the error).
func TestResolveNodeNameOneRule(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::customer-pii", Type: "aws_s3_bucket", Name: "customer-pii"})
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::dup-a", Type: "aws_s3_bucket", Name: "dup"})
	g.AddNode(&graph.Node{ID: "arn:aws:s3:::dup-b", Type: "aws_s3_bucket", Name: "dup"})

	cases := []struct {
		in, want string
		err      error
	}{
		{"customer-pii", "arn:aws:s3:::customer-pii", nil},
		{"arn:aws:s3:::customer-pii", "arn:aws:s3:::customer-pii", nil},
		{"arn:aws:s3:::not-in-graph/*", "arn:aws:s3:::not-in-graph/*", nil},
		{"some/path", "some/path", nil},
		{graph.InternetNodeID, graph.InternetNodeID, nil},
		{"Internet", "", graph.ErrNoSuchName}, // the Internet node's name is never a resource
		{"missing", "", graph.ErrNoSuchName},
		{"dup", "", graph.ErrAmbiguousName},
	}
	for _, c := range cases {
		got, err := graph.ResolveNodeName(g, c.in)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%q: err %v, want %v", c.in, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := graph.ResolveNodeName(g, "dup"); err == nil || !strings.Contains(err.Error(), "arn:aws:s3:::dup-a") {
		t.Errorf("ambiguous error does not name the candidates: %v", err)
	}
}

// The CLI and MCP must not carry their own copy of the rule.
func TestResolveNodeNameHasNoCopies(t *testing.T) {
	for _, f := range []string{"../cli/whocan.go", "../mcp/tools.go"} {
		b, err := os.ReadFile(filepath.FromSlash(f))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "graph.ResolveNodeName(") {
			t.Errorf("%s does not call graph.ResolveNodeName", f)
		}
		for _, own := range []string{"func resolveNodeName(", "func resolveWhoCanResource("} {
			if strings.Contains(string(b), own) {
				t.Errorf("%s still defines %s", f, own)
			}
		}
	}
}
