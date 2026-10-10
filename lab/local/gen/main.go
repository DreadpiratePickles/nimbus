// Command gen renders the local ground-truth lab estate into native findings JSON.
//
//	go run ./lab/local/gen                       # lab/local/estate.yaml -> lab/local/out/estate.findings.json
//	go run ./lab/local/gen -in x.yaml -out y.json
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/nimbus/lab/local/estate"
)

func main() {
	in := flag.String("in", "lab/local/estate.yaml", "estate definition")
	out := flag.String("out", "lab/local/out/estate.findings.json", "native findings JSON to write")
	flag.Parse()
	e, err := estate.Load(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := e.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fs := e.Findings()
	fmt.Printf("wrote %s: %d records (%d seeded weaknesses, %d inventory) across %d resources\n", *out, len(fs), len(e.Weaknesses), len(fs)-len(e.Weaknesses), len(e.Resources))
}
