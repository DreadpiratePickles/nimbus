// Command gen writes docs/graph-schema.md from the graph type registry
// (run via `go generate ./internal/graph`).
package main

import (
	"flag"
	"log"
	"os"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
)

func main() {
	out := flag.String("out", "docs/graph-schema.md", "output path")
	flag.Parse()
	if err := os.WriteFile(*out, []byte(graph.SchemaMarkdown()), 0o644); err != nil {
		log.Fatal(err)
	}
}
