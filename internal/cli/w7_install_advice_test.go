package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// W7-POLISH r5 #12 / R3: until a PyPI release exists (the release build sets PyPIPublished), the
// install advice is the from-source command — a checkout's `pip install -e`, else pip's
// git+https form — never `pip install "nimbus-cspm[ai]"` (no such package is published). The
// [ai] extra (the anthropic SDK) is asked for only when an API key is configured: the offline
// copilot runs on the base package.
func TestInstallAdviceFromSourceUntilPyPI(t *testing.T) {
	t.Setenv("NIMBUS_PYTHON_DIR", "")
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	outside := t.TempDir() // no python/pyproject.toml above it
	t.Chdir(outside)
	prev := PyPIPublished
	t.Cleanup(func() { PyPIPublished = prev })

	PyPIPublished = ""
	t.Setenv("ANTHROPIC_API_KEY", "")
	got := copilotInstallCmd("python3")
	if !strings.Contains(got, "git+https://github.com/DreadpiratePickles/nimbus") || !strings.Contains(got, "#subdirectory=python") {
		t.Errorf("no PyPI release: want the from-source command, got %s", got)
	}
	if strings.Contains(got, "[ai]") {
		t.Errorf("no API key configured: [ai] must not be requested: %s", got)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-not-a-key")
	if got := copilotInstallCmd("python3"); !strings.Contains(got, "nimbus-cspm[ai] @ git+https://") {
		t.Errorf("API key configured: want [ai] on the from-source command, got %s", got)
	}

	PyPIPublished = "true"
	if got := copilotInstallCmd("python3"); got != `python3 -m pip install "nimbus-cspm[ai]"` {
		t.Errorf("PyPI release with a key: %s", got)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	if got := copilotInstallCmd("python3"); got != `python3 -m pip install "nimbus-cspm"` {
		t.Errorf("PyPI release without a key: %s", got)
	}

	// Inside a checkout: the editable install of that checkout, [ai] only with a key.
	PyPIPublished = ""
	t.Chdir(filepath.Join(repo, "internal"))
	if got := copilotInstallCmd("python3"); got != `python3 -m pip install -e "`+filepath.Join(repo, "python")+`"` {
		t.Errorf("checkout without a key: %s", got)
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-not-a-key")
	if got := copilotInstallCmd("python3"); got != `python3 -m pip install -e "`+filepath.Join(repo, "python")+`[ai]"` {
		t.Errorf("checkout with a key: %s", got)
	}
}

// doctor prints the same advice (it printed `pip install "nimbus-cspm[ai]"`, r5 R3).
func TestDoctorInstallAdviceIsFromSource(t *testing.T) {
	dir := t.TempDir()
	flagConfig = writeDoctorConfig(t, dir)
	flagDB = filepath.Join(dir, "missing.db")
	prevNoPy := flagNoPython
	flagNoPython = false
	t.Cleanup(func() { flagConfig, flagDB, flagNoPython = "", "", prevNoPy })
	t.Setenv("NIMBUS_PYTHON_DIR", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Chdir(dir)
	env := fakeDoctorEnv(nil, nil, nil)
	env.python = func(*config.Config) string { return "" }
	var buf bytes.Buffer
	_ = runDoctor(context.Background(), env, &buf)
	out := buf.String()
	if !strings.Contains(out, "git+https://github.com/DreadpiratePickles/nimbus") || strings.Contains(out, `"nimbus-cspm[ai]"`) {
		t.Errorf("doctor install advice:\n%s", out)
	}
}
