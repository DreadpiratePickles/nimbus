package iac

import (
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// measureFull is the guard over one full lex (the pre-verify-4 algorithm): the reference the
// windowed measure must equal exactly.
func measureFull(src []byte, stop int) guardMeasure {
	g := newGuardState(stop)
	toks, _ := hclsyntax.LexConfig(src, "", hcl.Pos{Line: 1, Column: 1})
	for _, t := range toks {
		if g.feed(t) {
			break
		}
	}
	return g.m
}

func withWindow(t *testing.T, w, margin int) {
	t.Helper()
	ow, om := guardWindow, guardMargin
	guardWindow, guardMargin = w, margin
	t.Cleanup(func() { guardWindow, guardMargin = ow, om })
}

// Every .tf file in the repository's testdata, measured with tiny windows (so every file is
// split many times), gives exactly the single-lex measure.
func TestDepthGuardWindowedEqualsFullLexOnCorpus(t *testing.T) {
	var files []string
	filepath.WalkDir(filepath.Join("..", ".."), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == ".venv") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".tf") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) < 10 {
		t.Fatalf("corpus too small: %d", len(files))
	}
	for _, w := range []int{64, 256, 4096} {
		withWindow(t, w, w/8+8)
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, stop := range []int{4, 16, DefaultMaxDepth} {
				if got, want := measureNesting(src, stop), measureFull(src, stop); got != want {
					t.Fatalf("%s (window %d, stop %d): windowed %+v, full lex %+v", f, w, stop, got, want)
				}
			}
		}
	}
}

// Random token soup (brackets, operators, quoted and heredoc templates, interpolations,
// directives, comments of every kind, newlines) with tiny windows.
func TestDepthGuardWindowedEqualsFullLexOnRandomInput(t *testing.T) {
	parts := []string{"{", "}", "[", "]", "(", ")", "[*]", ".", "a", "b1", "-", "!", "?", ":", ",", "+", "*", "/", "==", "&&",
		"\n", " ", "\"", "\"x${", "}\"", "${", "%{ if a }", "%{ endif }", "%{ for x in y }", "%{ endfor }", "~}",
		"<<EOT\n", "\nEOT\n", "<<-X\n", "\n  X\n", "# c\n", "// c\n", "/*", "*/", "/* (((( */", "=", "=>", "...", "1.5e3",
		"for", "in", "if", "\\\"", "$${", "%%{", "<", "<<", "\t"}
	rng := rand.New(rand.NewSource(4))
	for _, w := range []int{48, 128, 1024} {
		withWindow(t, w, w/4+8)
		for i := 0; i < 3000; i++ {
			var b strings.Builder
			n := 20 + rng.Intn(400)
			for j := 0; j < n; j++ {
				b.WriteString(parts[rng.Intn(len(parts))])
			}
			src := []byte(b.String())
			for _, stop := range []int{3, 12, 64} {
				if got, want := measureNesting(src, stop), measureFull(src, stop); got != want {
					t.Fatalf("window %d stop %d: windowed %+v, full %+v\nsrc=%q", w, stop, got, want, src)
				}
			}
		}
	}
}
