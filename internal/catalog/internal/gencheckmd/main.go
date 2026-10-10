// Command gencheckmd rewrites the generated catalog block of docs/checks.md from catalog.yaml.
// Run via `go generate ./internal/catalog/...` (directive in internal/catalog/generate.go).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DreadpiratePickles/nimbus/internal/catalog/internal/checksdoc"
)

func main() {
	cat := flag.String("catalog", "catalog.yaml", "catalog.yaml path")
	doc := flag.String("doc", "../../docs/checks.md", "docs/checks.md path")
	flag.Parse()
	if err := run(*cat, *doc); err != nil {
		fmt.Fprintln(os.Stderr, "gencheckmd:", err)
		os.Exit(1)
	}
}

func run(catPath, docPath string) error {
	y, err := os.ReadFile(catPath)
	if err != nil {
		return err
	}
	md, err := os.ReadFile(docPath)
	if err != nil {
		return err
	}
	gen, err := checksdoc.Render(y)
	if err != nil {
		return err
	}
	out, err := checksdoc.Splice(string(md), gen)
	if err != nil {
		return err
	}
	if out == string(md) {
		return nil
	}
	return os.WriteFile(docPath, []byte(out), 0o644)
}
