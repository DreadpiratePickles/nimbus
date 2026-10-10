package governance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCodeownersErrors(t *testing.T) {
	co, err := ParseCodeowners(strings.NewReader("*.go @dev\n!negated @x\nfoo  not-valid\n[ab].tf @y\n\\#x @z\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(co.Errors) != 4 {
		t.Fatalf("want 4 line errors (negation, bad owner, char class, \\# escape), got %v", co.Errors)
	}
	if co.Errors[0].Line != 2 || co.Errors[1].Line != 3 || co.Errors[2].Line != 4 || co.Errors[3].Line != 5 {
		t.Errorf("line numbers = %+v", co.Errors)
	}
	m, ok := co.Match("a/b.go")
	if !ok || m.Line != 1 || m.Pattern != "*.go" || len(m.Owners) != 1 {
		t.Errorf("match = %+v %v", m, ok)
	}
	if _, ok := co.Match("README"); ok {
		t.Error("no pattern matches README")
	}
}

func TestCodeownersMatchTable(t *testing.T) {
	co := testCO(t)
	cases := map[string]string{
		"main.go":                "@org/default-team",
		"x.tf":                   "@org/terraform",
		"infra":                  "@org/default-team", // /infra/ matches only inside the directory
		"infra/a/b/c.tf":         "@org/infra",
		"infra/payments/x/y.yml": "@org/payments",
		"apps/a":                 "@org/apps",
		"logs":                   "@org/logging",
		"a/b/logs/c/d":           "@org/logging",
	}
	for p, want := range cases {
		m, ok := co.Match(p)
		if !ok || len(m.Owners) == 0 || m.Owners[0] != want {
			t.Errorf("Match(%q) = %+v %v, want %s", p, m, ok, want)
		}
	}
	if m, ok := co.Match("infra/legacy/x.tf"); !ok || len(m.Owners) != 0 {
		t.Errorf("unowned pattern must match with no owners: %+v %v", m, ok)
	}
}

func TestLoadCodeownersPrecedence(t *testing.T) {
	root := t.TempDir()
	if co, err := LoadCodeowners(root, ""); err != nil || co != nil {
		t.Fatalf("no file: want nil,nil got %v %v", co, err)
	}
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/CODEOWNERS", "* @docs\n")
	write("CODEOWNERS", "* @root\n")
	write(".github/CODEOWNERS", "* @github\n")
	co, err := LoadCodeowners(root, "")
	if err != nil || co == nil {
		t.Fatal(err)
	}
	if m, _ := co.Match("x"); m.Owners[0] != "@github" || !strings.HasSuffix(co.Path, filepath.Join(".github", "CODEOWNERS")) {
		t.Errorf(".github/CODEOWNERS must win, got %v from %s", m.Owners, co.Path)
	}
	co, err = LoadCodeowners(root, "docs/CODEOWNERS")
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := co.Match("x"); m.Owners[0] != "@docs" {
		t.Errorf("explicit file ignored: %v", m.Owners)
	}
	if _, err := LoadCodeowners(root, "missing/CODEOWNERS"); err == nil {
		t.Error("explicit missing file must be an error")
	}
}
