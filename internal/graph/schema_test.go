package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/graph-schema.md is generated from the registry (`go generate ./internal/graph`);
// this fails when the committed doc is stale.
func TestGraphSchemaDocCurrent(t *testing.T) {
	path := filepath.Join(repoRoot, "docs", "graph-schema.md")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing: run `go generate ./internal/graph` (%v)", path, err)
	}
	if want := SchemaMarkdown(); string(got) != want {
		t.Fatalf("docs/graph-schema.md is stale: run `go generate ./internal/graph`")
	}
	for _, s := range Registry() {
		if !strings.Contains(string(got), "`"+s.Type+"`") {
			t.Errorf("doc lacks %s", s.Type)
		}
	}
}
