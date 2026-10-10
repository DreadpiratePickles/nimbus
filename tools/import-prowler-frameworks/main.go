// Command import-prowler-frameworks converts Prowler's compliance framework JSON files
// (prowler/compliance/**.json, Apache-2.0) into nimbus framework YAML files under
// internal/compliance/frameworks/.
//
// What is imported: requirement identifiers and requirement-to-check mappings, with each Prowler
// check id translated to the nimbus canonical id (catalog lookup, else "PROWLER:<check_id>", the id
// an unmapped Prowler finding gets). Requirement titles are nimbus's own catalog titles. No upstream
// descriptive text is copied by default (THIRD_PARTY_NOTICES.md §1-§2, plan O6): --cis-text
// unlocks text for CIS-derived files and --upstream-text for the others.
//
// Usage:
//
//	go run ./tools/import-prowler-frameworks                      # download 5.44.0 (pinned sha)
//	go run ./tools/import-prowler-frameworks --from-dir /path/to/prowler   # offline
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/catalog"
)

const (
	defaultRef = "5.44.0"
	defaultSHA = "499fd637f3393b485833b08cdaf4172917c5698e"
	repoURL    = "https://github.com/prowler-cloud/prowler"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "import-prowler-frameworks:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("import-prowler-frameworks", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ref := fs.String("ref", defaultRef, "Prowler release tag")
	sha := fs.String("sha", defaultSHA, "expected commit sha of --ref (pinned); passing it explicitly overrides the tag check")
	fromDir := fs.String("from-dir", "", "offline: a Prowler checkout (or its prowler/compliance directory)")
	out := fs.String("out", filepath.Join("internal", "compliance", "frameworks"), "output directory")
	cisText := fs.Bool("cis-text", false, "copy CIS descriptive text (titles, sections); off until O6 is signed off")
	upstreamText := fs.Bool("upstream-text", false, "copy upstream requirement names for non-CIS frameworks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	shaSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sha" {
			shaSet = true
		}
	})

	var files map[string][]byte // path relative to prowler/compliance -> JSON
	var err error
	if *fromDir != "" {
		files, err = readDir(*fromDir)
	} else {
		if os.Getenv("CLOUD_POSTURE_NO_NETWORK") == "1" {
			return errors.New("CLOUD_POSTURE_NO_NETWORK=1: refusing to download; pass --from-dir with an already-downloaded prowler/compliance tree")
		}
		files, err = download(*ref, *sha, shaSet)
	}
	if err != nil {
		return err
	}
	opt := options{Ref: *ref, SHA: *sha, CISText: *cisText, UpstreamText: *upstreamText, Lookup: catalogLookup}
	idx, err := writeAll(*out, files, opt)
	if err != nil {
		return err
	}
	total := 0
	for _, f := range idx.Files {
		total += f.Requirements
	}
	fmt.Fprintf(os.Stderr, "imported %d frameworks (%d requirements) from prowler@%s (%s) into %s\n", len(idx.Files), total, *ref, *sha, *out)
	return nil
}

// catalogLookup maps a Prowler check id to the nimbus canonical id, the catalog title, and whether
// nimbus knows the check natively.
func catalogLookup(check string) (string, string, bool) {
	if e, ok := catalog.Default().Lookup("prowler", check); ok {
		return e.ID, e.Title, true
	}
	return "PROWLER:" + check, "", false
}

// readDir loads every *.json under dir/prowler/compliance (or dir itself when it is that directory).
func readDir(dir string) (map[string][]byte, error) {
	base := filepath.Join(dir, "prowler", "compliance")
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		base = dir
	}
	files := map[string][]byte{}
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", p)
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no framework JSON files found", base)
	}
	return files, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
