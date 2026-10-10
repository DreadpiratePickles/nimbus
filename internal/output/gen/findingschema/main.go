// Command findingschema writes docs/spec/finding-v1.schema.json from internal/model.
// Run it with `go generate ./internal/output`.
package main

import (
	"fmt"
	"os"

	"github.com/DreadpiratePickles/nimbus/internal/output"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: findingschema <out.json>")
		os.Exit(2)
	}
	b, err := output.FindingSchemaJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
