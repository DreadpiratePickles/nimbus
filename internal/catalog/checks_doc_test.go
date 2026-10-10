package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/catalog/internal/checksdoc"
)

// docs/checks.md lists every canonical id with its scanner aliases; the block between the
// generated-catalog markers must equal what `go generate ./internal/catalog/...` writes.
func TestChecksDocInSync(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "checks.md")
	md, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := checksdoc.Render(catalogYAML)
	if err != nil {
		t.Fatal(err)
	}
	want, err := checksdoc.Splice(string(md), gen)
	if err != nil {
		t.Fatalf("%v (add the markers around the catalog section)", err)
	}
	if want != string(md) {
		t.Errorf("docs/checks.md drifted from internal/catalog/catalog.yaml: run `go generate ./internal/catalog/...`")
	}
	for _, id := range Default().IDs() {
		if !strings.Contains("\n"+gen, "\n## "+id+"\n") {
			t.Errorf("generated catalog section misses %s", id)
		}
	}
}
