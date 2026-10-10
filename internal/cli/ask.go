package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// `cloud-posture ask` (delta r3 #11): declaration and behaviour (registered on root in devx.go).

var askCmd = &cobra.Command{
	Use:   "ask <question>",
	Short: "AI security copilot: natural-language questions over your posture (Python layer; offline rule-based fallback)",
	Example: `  cloud-posture ask "show me all public databases with no encryption"
  cloud-posture ask "why did finding 3f9c fire and what is the blast radius"
  cloud-posture ask "write an OPA policy to block public S3 buckets"`,
	Args: cobra.MinimumNArgs(1),
	// main prints a returned error once; cobra's own "Error:" line would repeat it.
	SilenceErrors: true,
	RunE:          runAsk,
}

var askFlags struct {
	showSQL bool
	full    bool
}

func init() {
	askCmd.Long = `Answers a natural-language question with the Python copilot over the posture database. Engine
verdicts (exposure, path Issues, who-can) are answered by this binary, which the copilot is handed
as CLOUD_POSTURE_BIN. The answer ends with a Sources: block; --show-sql prints the SQL that ran.`
	askCmd.Flags().BoolVar(&askFlags.showSQL, "show-sql", false, "print the SQL the answer rests on (once, under Sources:)")
	askCmd.Flags().BoolVar(&askFlags.full, "full", false, "print every row of the answer's table (default: 20 rows, 2 KB)")
}

func runAsk(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if by := pythonDisabledBy(cfg); by != "" {
		how := "drop --no-python"
		if by != "--no-python" {
			how = "set python.enabled: true there (or remove the key)"
		}
		return fmt.Errorf("the copilot lives in the Python layer, which %s turns off: %s; scanning, paths, plan, who-can and prioritize need no Python", by, how)
	}
	exe := python(cfg)
	if exe == "" {
		return fmt.Errorf("the copilot lives in the Python layer, and no interpreter here can import nimbus: %s (works offline; set ANTHROPIC_API_KEY for LLM answers)", copilotInstallCmd("python3"))
	}
	if missing := copilotMissingModules(cmd.Context(), exe); len(missing) > 0 {
		return fmt.Errorf("the copilot's Python dependencies are missing (%s): %s", strings.Join(missing, ", "), copilotInstallCmd(exe))
	}
	st, err := openStore()
	if err != nil {
		return err
	}
	dbPath := st.Path()
	st.Close()
	q := strings.Join(args, " ")
	lq := strings.ToLower(q)
	sub := "ask"
	if strings.HasPrefix(lq, "write an opa") || strings.HasPrefix(lq, "write a rego") || strings.Contains(lq, "opa policy") {
		sub = "policy"
	}
	out, err := runPython(cmd.Context(), exe, askEnv(dbPath), askArgs(sub, q, askFlags.showSQL, askFlags.full)...)
	os.Stdout.Write(out)
	if err != nil {
		// the copilot already printed its own error on stderr; exit non-zero without repeating it
		return fmt.Errorf("copilot failed (%v)", err)
	}
	return nil
}

// askEnv is the copilot's extra environment: the database, and this executable as
// CLOUD_POSTURE_BIN unless the user set one (an explicit setting is never replaced).
func askEnv(dbPath string) []string {
	env := []string{"CLOUD_POSTURE_DB=" + dbPath}
	if strings.TrimSpace(os.Getenv("CLOUD_POSTURE_BIN")) == "" {
		if self, err := os.Executable(); err == nil {
			env = append(env, "CLOUD_POSTURE_BIN="+self)
		}
	}
	return env
}

// askArgs is the Python command line (`python -m nimbus <sub> [--show-sql] -- <question>`): the
// question follows "--", so one that starts with a dash is never read as an option.
func askArgs(sub, q string, showSQL bool, full ...bool) []string {
	a := []string{"-m", "nimbus", sub}
	if showSQL && sub == "ask" {
		a = append(a, "--show-sql")
	}
	if len(full) > 0 && full[0] && sub == "ask" {
		a = append(a, "--full")
	}
	return append(a, "--", q)
}

// copilotModules are the third-party imports `nimbus ask` needs (python/pyproject.toml core
// dependencies). `import nimbus` alone succeeds in a fresh clone, then typer is missing and the
// copilot dies with a traceback (r4 N2), so ask probes them first.
var copilotModules = []string{"typer", "rich", "pydantic", "yaml", "jinja2", "httpx"}

// copilotMissingModules returns the modules exe cannot import (nil when the probe itself fails:
// the copilot's own error is then the better message).
func copilotMissingModules(ctx context.Context, exe string) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	probe := "import importlib.util as u; print(' '.join(m for m in " + pyList(copilotModules) + " if u.find_spec(m) is None))"
	out, err := runPythonQuiet(ctx, exe, "-c", probe)
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

func pyList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = "'" + x + "'"
	}
	return "(" + strings.Join(q, ", ") + ")"
}

// PyPIPublished is set by a release build once the Python layer is on PyPI:
//
//	-ldflags "-X github.com/DreadpiratePickles/nimbus/internal/cli.PyPIPublished=true"
//
// Until then (r5 #12 / R3: no "nimbus-cspm" package is published) every install hint is the
// from-source command.
var PyPIPublished = ""

// pyRepoURL is the source the from-source install command points pip at.
const pyRepoURL = "https://github.com/DreadpiratePickles/nimbus"

// aiExtra is "[ai]" (the anthropic SDK) when an API key is configured, "" otherwise: the offline
// copilot runs on the base package, so it is asked for only when it would be used.
func aiExtra() string {
	if strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) != "" {
		return "[ai]"
	}
	return ""
}

// copilotInstallCmd is the exact command that installs the copilot for exe: the trusted source
// checkout beside this binary (pythonDir), or a clone above the working directory, as an
// editable install; otherwise the published package when the release says there is one
// (PyPIPublished), else pip's from-source form (git+https, the release tag or main,
// subdirectory python). The [ai] extra only when an API key is configured (aiExtra).
func copilotInstallCmd(exe string) string {
	extra := aiExtra()
	dir := pythonDir()
	if dir == "" {
		if wd, err := os.Getwd(); err == nil {
			// Advice only (nothing is imported from here): a clone's python/ above the working directory.
			for d := wd; ; d = filepath.Dir(d) {
				if b, err := os.ReadFile(filepath.Join(d, "python", "pyproject.toml")); err == nil && strings.Contains(string(b), "nimbus-cspm") {
					dir = filepath.Join(d, "python")
					break
				}
				if filepath.Dir(d) == d {
					break
				}
			}
		}
	}
	switch {
	case dir != "":
		return exe + ` -m pip install -e "` + dir + extra + `"`
	case PyPIPublished == "true":
		return exe + ` -m pip install "nimbus-cspm` + extra + `"`
	}
	ref := "main"
	if v := strings.TrimPrefix(Version, "v"); v != "" && !strings.Contains(v, "dev") {
		ref = "v" + v
	}
	return exe + ` -m pip install "nimbus-cspm` + extra + ` @ git+` + pyRepoURL + `@` + ref + `#subdirectory=python"`
}
