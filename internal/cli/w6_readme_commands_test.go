package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W6-POLISH item 1 (r4 #3, release readiness row 11): every command `--help` lists is in the
// README command table, and so are the wave-5 surfaces the r4 walk found undocumented.
func TestReadmeCommandTableCoversEveryCommand(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "## Commands")
	if i < 0 {
		t.Fatal("README has no ## Commands section")
	}
	table := s[i:]
	if j := strings.Index(table[3:], "\n## "); j >= 0 {
		table = table[:j+3]
	}
	for _, c := range root.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if !strings.Contains(table, "`"+c.Name()) && !strings.Contains(table, ", `"+c.Name()+"`") {
			t.Errorf("README command table lacks `%s` (%s)", c.Name(), c.Short)
		}
	}
	for _, want := range []string{"`risk", "catalog unmapped", "--from", "--through", "mark-pending", "--from-file", "who-can", "--no-python", "--grouped", "ask"} {
		if !strings.Contains(table, want) {
			t.Errorf("README command table lacks %q", want)
		}
	}
}
