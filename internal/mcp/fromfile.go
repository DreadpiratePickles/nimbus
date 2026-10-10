package mcp

import (
	"os"
	"path/filepath"
	"strings"
)

// The verify tool's from_file argument (W7-VERIFY r5 #6) reads one local findings export. The
// path is a client-controlled string, so it is confined: it must resolve (symlinks followed)
// to a regular file of at most maxFromFileBytes inside one of the server's file roots. Errors
// name the refusal, never file content.

const maxFromFileBytes = 64 << 20 // the CLI's --from-file cap (cli.verifyMaxFileBytes)

// DefaultFileRoots are the roots a from_file path may resolve into when Options.FileRoots is
// empty: the database directory and the working directory.
func DefaultFileRoots(dbPath string) []string {
	var out []string
	if dbPath != "" {
		if abs, err := filepath.Abs(filepath.Dir(dbPath)); err == nil {
			out = append(out, abs)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, wd)
	}
	return out
}

// resolveFromFile confines path to roots. A relative path is taken relative to the first root.
func resolveFromFile(path string, roots []string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errf("from_file is empty")
	}
	if strings.ContainsRune(path, 0) {
		return "", errf("from_file is not a valid path")
	}
	if len(roots) == 0 {
		return "", errf("from_file is disabled: the server has no file roots")
	}
	cand := path
	if !filepath.IsAbs(cand) {
		cand = filepath.Join(roots[0], cand)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(cand))
	if err != nil {
		return "", errf("from_file %q: no such file under the server's file roots", filepath.Base(path))
	}
	inside := false
	for _, r := range roots {
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(rr, real); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			inside = true
			break
		}
	}
	if !inside {
		return "", errf("from_file %q is outside the server's file roots (%d root(s): the database directory and the working directory unless configured)", filepath.Base(path), len(roots))
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return "", errf("from_file %q is not a regular file", filepath.Base(path))
	}
	if fi.Size() > maxFromFileBytes {
		return "", errf("from_file %q: %d bytes exceeds the 64 MiB cap", filepath.Base(path), fi.Size())
	}
	return real, nil
}
