package main

import (
	"fmt"
	"os"

	"github.com/DreadpiratePickles/nimbus/internal/cli"
)

// Build metadata, injected at release time by goreleaser:
//
//	-X main.version={{.Version}} -X main.commit={{.Commit}} -X main.date={{.Date}}
//
// A plain `go build` keeps the fallbacks, so a dev build never claims to be a release.
var (
	version = "0.1.0-dev"
	commit  = ""
	date    = ""
)

// buildVersion is the string `cloud-posture version` prints.
func buildVersion() string {
	v := version
	if commit != "" {
		v += " (commit " + commit
		if date != "" {
			v += ", built " + date
		}
		v += ")"
	}
	return v
}

func main() {
	cli.SetVersion(version, commit, date)
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
