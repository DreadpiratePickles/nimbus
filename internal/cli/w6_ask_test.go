package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W6-POLISH item 4 (r4 #6 / N2 / E16, #10 / N5): `ask` from a fresh clone never ends in a Python
// traceback, names the exact install command or the setting that turned Python off, passes
// --full through, and no command prints its error twice ("Error:" + "error:").

// fakePython writes an interpreter stand-in: `import nimbus` succeeds, the dependency probe
// reports missing, and any other call leaves a marker (the copilot must not run).
func fakePython(t *testing.T, missing string) (exe, marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "copilot-ran")
	exe = filepath.Join(dir, "python3")
	script := "#!/bin/sh\ncase \"$*\" in\n  *find_spec*) echo '" + missing + "' ;;\n  *'import nimbus'*) exit 0 ;;\n  *) touch '" + marker + "' ;;\nesac\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe, marker
}

func TestAskProbesCopilotDependenciesFirst(t *testing.T) {
	w6IngestLabNoConfig(t)
	exe, marker := fakePython(t, "typer rich")
	t.Setenv("CLOUD_POSTURE_PYTHON", exe)
	t.Setenv("ANTHROPIC_API_KEY", "sk-test-not-a-key") // W7 r5 #12: [ai] is asked for only when a key is configured
	out, err := runErr(t, "ask", "who can read customer-pii")
	if err == nil {
		t.Fatalf("ask must fail when the copilot's dependencies are missing:\n%s", out)
	}
	msg := err.Error()
	for _, want := range []string{"typer", "rich", "-m pip install -e", `[ai]"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("ask error lacks %q: %s", want, msg)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the copilot ran although its imports are missing (that is the traceback the r4 walk saw)")
	}
}

func TestAskNamesTheSettingThatDisablesPython(t *testing.T) {
	w6IngestLabNoConfig(t)
	exe, _ := fakePython(t, "")
	t.Setenv("CLOUD_POSTURE_PYTHON", exe)
	cfg := labConfig(t) // python: enabled: false
	_, err := runErr(t, "-c", cfg, "ask", "top attack paths")
	if err == nil || !strings.Contains(err.Error(), "python.enabled: false") || !strings.Contains(err.Error(), cfg) {
		t.Errorf("ask with python.enabled: false must name the key and the file: %v", err)
	}
	_, err = runErr(t, "--no-python", "ask", "top attack paths")
	if err == nil || !strings.Contains(err.Error(), "--no-python") {
		t.Errorf("ask --no-python must name the flag: %v", err)
	}
}

func TestAskPassesFull(t *testing.T) {
	if got := strings.Join(askArgs("ask", "q", false, true), " "); got != "-m nimbus ask --full -- q" {
		t.Errorf("args %q", got)
	}
}

// N5 / #10: cobra's "Error:" line and main's "error:" line printed every failure twice.
func TestErrorsPrintedOnce(t *testing.T) {
	w6IngestLabNoConfig(t)
	out, err := runErr(t, "paths", "--from", "internet")
	if err == nil {
		t.Fatal("a path query without --to must fail")
	}
	if strings.Contains(out, "Error:") {
		t.Errorf("cobra printed the error as well (main prints it once):\n%s", out)
	}
	if !root.SilenceErrors {
		t.Error("root.SilenceErrors must be set: main prints the error once")
	}
}

func w6IngestLabNoConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "-c", labConfig(t), "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
}
