package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
)

// fakeTool puts an executable shell script named name first on PATH.
func fakeTool(t *testing.T, name, script string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// prowlerWritingOutput writes a valid output file into the directory after "-o", then
// prints stderr and exits with the given code.
func prowlerScript(writeOutput bool, stderr string, code int) string {
	s := `out=""; prev=""; for a in "$@"; do if [ "$prev" = "-o" ]; then out="$a"; fi; prev="$a"; done
`
	if writeOutput {
		s += `mkdir -p "$out"; echo '[{"status_code":"FAIL"}]' > "$out/prowler.ocsf.json"
`
	}
	return s + "echo '" + stderr + "' >&2\nexit " + itoa(code) + "\n"
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i))) }

func runProwlerAccount(t *testing.T, timeout time.Duration) Output {
	t.Helper()
	acct := &config.Account{Name: "prod", Provider: "aws", Tools: []string{"prowler"}}
	outs := RunAccount(context.Background(), acct, Options{WorkDir: t.TempDir(), Timeout: timeout})
	if len(outs) != 1 {
		t.Fatalf("outputs: %+v", outs)
	}
	return outs[0]
}

// Defect 19 (runner.go:317): valid output was discarded whenever stderr mentioned "error".
func TestRunnerKeepsValidOutputWhenStderrSaysError(t *testing.T) {
	fakeTool(t, "prowler", prowlerScript(true, "ERROR: botocore deprecation warning (not fatal)", 3))
	o := runProwlerAccount(t, time.Minute)
	if o.Run.Status != "ok" {
		t.Fatalf("status %q message %q: findings present (exit 3) with valid output must be ok", o.Run.Status, o.Run.Message)
	}
	if !strings.Contains(o.Run.Output, "deprecation") {
		t.Errorf("stderr must be kept on the run: %q", o.Run.Output)
	}
	if _, err := os.Stat(o.Path); err != nil {
		t.Errorf("output path %s: %v", o.Path, err)
	}
}

func TestRunnerFailsWithoutOutputAndRecordsStderrReason(t *testing.T) {
	fakeTool(t, "prowler", prowlerScript(false, "AccessDenied: sts:AssumeRole not authorized", 1))
	o := runProwlerAccount(t, time.Minute)
	if o.Run.Status != "failed" || !strings.Contains(o.Run.Message, "AccessDenied") {
		t.Fatalf("status %q message %q: a non-zero exit without output fails, with stderr as the reason", o.Run.Status, o.Run.Message)
	}
}

func TestRunnerTimeoutIsReported(t *testing.T) {
	fakeTool(t, "prowler", "sleep 5\n")
	o := runProwlerAccount(t, 200*time.Millisecond)
	if o.Run.Status != "failed" || !strings.Contains(o.Run.Message, "timeout") {
		t.Fatalf("status %q message %q: want a timeout failure", o.Run.Status, o.Run.Message)
	}
}

// Inventory defect 12 follow-up: `python3 -m nimbus.checks` must not import nimbus from
// the process working directory; it resolves the package only from Options.PythonDir.
func TestPythonChecksNotLoadedFromWorkingDirectory(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	cwd := t.TempDir()
	marker := filepath.Join(t.TempDir(), "pwned")
	os.MkdirAll(filepath.Join(cwd, "nimbus"), 0o755)
	os.WriteFile(filepath.Join(cwd, "nimbus", "__init__.py"), nil, 0o644)
	os.WriteFile(filepath.Join(cwd, "nimbus", "checks.py"), []byte("open("+pyQuote(marker)+", 'w').write('cwd code ran')\n"), 0o644)

	trusted := t.TempDir()
	os.MkdirAll(filepath.Join(trusted, "nimbus"), 0o755)
	os.WriteFile(filepath.Join(trusted, "nimbus", "__init__.py"), nil, 0o644)
	os.WriteFile(filepath.Join(trusted, "nimbus", "checks.py"), []byte(`import sys
out = sys.argv[sys.argv.index("--output") + 1]
open(out, "w").write("[]")
`), 0o644)

	t.Chdir(cwd)
	acct := &config.Account{Name: "prod", Provider: "aws", Tools: []string{"python-checks"}}
	outs := RunAccount(context.Background(), acct, Options{WorkDir: "runs", Python: py, PythonDir: trusted, Timeout: time.Minute})
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("nimbus.checks was imported from the working directory: %s", b)
	}
	if len(outs) != 1 || outs[0].Run.Status != "ok" {
		t.Fatalf("python-checks run: %+v", outs)
	}
	if b, err := os.ReadFile(outs[0].Path); err != nil || string(b) != "[]" {
		t.Fatalf("trusted module output at %s: %q %v", outs[0].Path, b, err)
	}
	if !filepath.IsAbs(outs[0].Path) {
		t.Errorf("output path must be absolute (the module runs from a neutral directory): %s", outs[0].Path)
	}
}

func pyQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "\\'") + "'" }
