package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Verification 7 defect 6 (W7-POLISH item 7): a mistyped --config (an explicitly named file that
// does not exist) is a hard error naming the path; only the implicit default may be absent.
func TestLoadExplicitMissingConfigIsAnError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "cloud-posture.lab.yml")
	_, err := Load(missing)
	if err == nil || !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("explicit missing config: %v", err)
	}
	// The implicit default path may be absent (no file in the cwd or ~/.cloud-posture).
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	cfg, err := Load("")
	if err != nil || cfg == nil {
		t.Fatalf("implicit default absent must load the defaults: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("db: p.db\n"), 0o600)
	if _, err := Load(filepath.Join(dir, "x.yaml")); err != nil {
		t.Fatal(err)
	}
}
