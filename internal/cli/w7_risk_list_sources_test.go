package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W7-POLISH item 15: `risk list` shows the customer rules traversal uses (config path_rules.dirs
// and --rules-dir) next to the embedded library, each row labelled by its source.
func TestRiskListLabelsLibraryAndCustomRules(t *testing.T) {
	rulesDir, _ := filepath.Abs(filepath.Join("..", "attackpath", "testdata", "custom_rules"))
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("python:\n  enabled: false\npath_rules:\n  dirs: ["+rulesDir+"]\n"), 0o600)
	flagDB = filepath.Join(dir, "none.db")
	t.Cleanup(func() { flagDB = "" })
	out := run(t, "-c", cfgPath, "risk", "list")
	var custom, lib string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "acme-self-grant-billing-read") {
			custom = l
		}
		if strings.Contains(l, "aws-ec2-privesc-passrole-iam ") {
			lib = l
		}
	}
	if !strings.Contains(custom, "custom") || !strings.Contains(custom, "acme-self-grant-billing-read.yaml") {
		t.Errorf("custom rule row must name its source file: %q\n%s", custom, firstLines(out, 3))
	}
	if !strings.Contains(lib, "library") {
		t.Errorf("library rule row must say library: %q", lib)
	}
	if h := firstLines(out, 1); !strings.Contains(h, "library") || !strings.Contains(h, "1 custom") {
		t.Errorf("header must count library and custom rules: %s", h)
	}
	var doc []struct {
		ID         string `json:"id"`
		SourceKind string `json:"source_kind"`
	}
	if err := json.Unmarshal([]byte(run(t, "-c", cfgPath, "risk", "list", "--format", "json")), &doc); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range doc {
		kinds[r.SourceKind]++
	}
	if kinds["custom"] != 1 || kinds["library"] < 50 {
		t.Errorf("source_kind counts %v", kinds)
	}
	// The same through --rules-dir without a config entry.
	plain := filepath.Join(dir, "plain.yaml")
	os.WriteFile(plain, []byte("python:\n  enabled: false\n"), 0o600)
	if out := run(t, "-c", plain, "risk", "list", "--rules-dir", rulesDir); !strings.Contains(out, "acme-self-grant-billing-read") {
		t.Errorf("--rules-dir rule missing:\n%s", firstLines(out, 3))
	}
}
