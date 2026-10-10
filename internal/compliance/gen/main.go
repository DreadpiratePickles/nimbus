// Command gen writes python/nimbus/frameworks/frameworks.yaml from the Go framework loader, so
// Go and Python read the same frameworks. Run: go generate ./internal/compliance/
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/DreadpiratePickles/nimbus/internal/compliance"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "compliance/gen:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("go.mod not found above the working directory")
		}
		dir = parent
	}
	data, err := compliance.BundleJSON()
	if err != nil {
		return err
	}
	out := filepath.Join(dir, compliance.BundlePath)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", out, len(data))
	return nil
}
