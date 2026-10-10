// Package scanner invokes external scanners (Prowler, ScoutSuite, Checkov, Trivy, Steampipe,
// the Python native check library and plugins) per account and collects their output files.
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/config"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Output is one produced artifact to ingest.
type Output struct {
	Tool    string
	Source  string // adapter name
	Account string
	Path    string
	Run     model.ToolRun
	// Root is the IaC path this output was scanned from (RunIaC); "" for accounts.
	Root string
}

type Options struct {
	WorkDir string
	Timeout time.Duration
	Python  string
	// PythonDir is the trusted source checkout holding the nimbus package (cli
	// pythonDir(): $NIMBUS_PYTHON_DIR or python/ beside the executable). The Python
	// checks never import from the working directory; "" means the installed package.
	PythonDir string
	Logf      func(format string, args ...any)
	IaCPaths  []string
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Available reports which external tools are installed.
func Available() map[string]string {
	out := map[string]string{}
	for _, t := range []string{"prowler", "scout", "checkov", "trivy", "steampipe", "powerpipe", "python3", "terraform", "kubectl", "aws", "az", "gcloud", "git", "gh"} {
		if p, err := exec.LookPath(t); err == nil {
			out[t] = p
		}
	}
	return out
}

// RunAccount executes the configured tools for one account and returns output artifacts.
func RunAccount(ctx context.Context, acct *config.Account, opts Options) []Output {
	tools := acct.Tools
	if len(tools) == 0 {
		tools = defaultTools(acct.Provider)
	}
	work := filepath.Join(opts.WorkDir, sanitize(acct.Name))
	os.MkdirAll(work, 0o755)
	var outs []Output
	for _, tool := range tools {
		switch strings.ToLower(tool) {
		case "native", "nimbus":
			continue // handled in-process by the collector package
		case "prowler":
			outs = append(outs, runProwler(ctx, acct, work, opts))
		case "scoutsuite", "scout":
			outs = append(outs, runScout(ctx, acct, work, opts))
		case "steampipe", "powerpipe":
			outs = append(outs, runSteampipe(ctx, acct, work, opts))
		case "trivy":
			outs = append(outs, runTrivy(ctx, acct, work, opts)...)
		case "checkov":
			outs = append(outs, runCheckovK8s(ctx, acct, work, opts))
		case "python-checks", "nimbus-checks":
			outs = append(outs, runPythonChecks(ctx, acct, work, opts))
		default:
			outs = append(outs, Output{Tool: tool, Account: acct.Name, Run: model.ToolRun{Tool: tool, Account: acct.Name, Status: "skipped", Message: "unknown tool"}})
		}
	}
	return outs
}

// RunIaC scans IaC directories with checkov and trivy config (whichever is installed).
func RunIaC(ctx context.Context, paths []string, opts Options) []Output {
	var outs []Output
	work := filepath.Join(opts.WorkDir, "iac")
	os.MkdirAll(work, 0o755)
	for i, p := range paths {
		if _, err := exec.LookPath("checkov"); err == nil {
			out := filepath.Join(work, fmt.Sprintf("checkov_%d", i))
			os.MkdirAll(out, 0o755)
			run := execTool(ctx, opts, filepath.Join(out, "results_json.json"), "checkov", "-d", p, "-o", "json", "--output-file-path", out, "--quiet", "--compact", "--skip-download")
			run.Account = "iac"
			outs = append(outs, Output{Tool: "checkov", Source: "checkov", Account: "iac", Path: filepath.Join(out, "results_json.json"), Run: run, Root: p})
		}
		if _, err := exec.LookPath("trivy"); err == nil {
			out := filepath.Join(work, fmt.Sprintf("trivy_config_%d.json", i))
			run := execTool(ctx, opts, out, "trivy", "config", "-f", "json", "-o", out, "--quiet", p)
			run.Account = "iac"
			outs = append(outs, Output{Tool: "trivy", Source: "trivy", Account: "iac", Path: out, Run: run, Root: p})
			secrets := filepath.Join(work, fmt.Sprintf("trivy_fs_%d.json", i))
			run2 := execTool(ctx, opts, secrets, "trivy", "fs", "--scanners", "secret,misconfig", "-f", "json", "-o", secrets, "--quiet", p)
			run2.Account = "iac"
			outs = append(outs, Output{Tool: "trivy", Source: "trivy", Account: "iac", Path: secrets, Run: run2, Root: p})
		}
	}
	return outs
}

// RunPlugin executes a plugin command that prints native findings JSON to stdout.
func RunPlugin(ctx context.Context, p config.Plugin, opts Options) Output {
	if len(p.Command) == 0 {
		return Output{Tool: p.Name, Run: model.ToolRun{Tool: p.Name, Status: "skipped", Message: "no command"}}
	}
	work := filepath.Join(opts.WorkDir, "plugins")
	os.MkdirAll(work, 0o755)
	out := filepath.Join(work, sanitize(p.Name)+".findings.json")
	run := execToolToFile(ctx, opts, out, p.Command[0], p.Command[1:]...)
	run.Tool = "plugin:" + p.Name
	run.Account = p.Account
	return Output{Tool: p.Name, Source: "native", Account: p.Account, Path: out, Run: run}
}

func defaultTools(provider string) []string {
	switch provider {
	case "aws":
		return []string{"native", "python-checks", "prowler", "steampipe"}
	case "azure", "gcp", "m365", "github":
		return []string{"native", "prowler", "steampipe"}
	case "kubernetes":
		return []string{"native", "trivy", "checkov", "steampipe"}
	case "okta", "oci":
		return []string{"native", "steampipe"}
	}
	return []string{"native"}
}

func runProwler(ctx context.Context, a *config.Account, work string, opts Options) Output {
	provider := a.Provider
	if provider == "kubernetes" {
		provider = "kubernetes"
	}
	args := []string{provider, "-M", "json-ocsf", "-o", work, "-F", "prowler", "--no-banner", "-z"}
	switch a.Provider {
	case "aws":
		if a.Profile != "" {
			args = append(args, "--profile", a.Profile)
		}
		if a.RoleARN != "" {
			args = append(args, "--role", a.RoleARN)
		}
		if len(a.Regions) > 0 {
			args = append(args, "-f")
			args = append(args, a.Regions...)
		}
	case "azure":
		if a.SubscriptionID != "" {
			args = append(args, "--subscription-ids", a.SubscriptionID)
		}
		args = append(args, "--az-cli-auth")
	case "gcp":
		if a.ProjectID != "" {
			args = append(args, "--project-ids", a.ProjectID)
		}
	case "kubernetes":
		if a.KubeContext != "" {
			args = append(args, "--context", a.KubeContext)
		}
	case "github":
		if a.Org != "" {
			args = append(args, "--organization", a.Org)
		}
	}
	run := execTool(ctx, opts, filepath.Join(work, "prowler.ocsf.json"), "prowler", args...)
	run.Account = a.Name
	return Output{Tool: "prowler", Source: "prowler", Account: a.Name, Path: filepath.Join(work, "prowler.ocsf.json"), Run: run}
}

func runScout(ctx context.Context, a *config.Account, work string, opts Options) Output {
	dir := filepath.Join(work, "scoutsuite")
	args := []string{a.Provider, "--no-browser", "--report-dir", dir, "--report-name", "scout"}
	switch a.Provider {
	case "aws":
		if a.Profile != "" {
			args = append(args, "--profile", a.Profile)
		}
	case "azure":
		args = append(args, "--cli")
		if a.SubscriptionID != "" {
			args = append(args, "--subscriptions", a.SubscriptionID)
		}
	case "gcp":
		args = append(args, "--user-account")
		if a.ProjectID != "" {
			args = append(args, "--project-id", a.ProjectID)
		}
	}
	run := execTool(ctx, opts, filepath.Join(dir, "scoutsuite-results", "scoutsuite_results_scout.js"), "scout", args...)
	run.Account = a.Name
	return Output{Tool: "scoutsuite", Source: "scoutsuite", Account: a.Name, Path: filepath.Join(dir, "scoutsuite-results", "scoutsuite_results_scout.js"), Run: run}
}

func runSteampipe(ctx context.Context, a *config.Account, work string, opts Options) Output {
	out := filepath.Join(work, "steampipe.json")
	bin := "powerpipe"
	if _, err := exec.LookPath(bin); err != nil {
		bin = "steampipe"
	}
	mod := map[string]string{"aws": "aws_compliance", "azure": "azure_compliance", "gcp": "gcp_compliance", "oci": "oci_compliance", "kubernetes": "kubernetes_compliance", "github": "github_compliance", "okta": "okta_compliance", "m365": "microsoft365_compliance"}[a.Provider]
	var run model.ToolRun
	if bin == "powerpipe" {
		run = execTool(ctx, opts, out, bin, "benchmark", "run", "all", "--export", "json:"+out, "--mod-location", filepath.Join(os.Getenv("HOME"), ".cloud-posture", "mods", mod))
	} else {
		run = execTool(ctx, opts, out, bin, "check", "all", "--export", "json="+out, "--workspace-chdir", filepath.Join(os.Getenv("HOME"), ".cloud-posture", "mods", mod))
	}
	run.Account = a.Name
	return Output{Tool: "steampipe", Source: "steampipe", Account: a.Name, Path: out, Run: run}
}

func runTrivy(ctx context.Context, a *config.Account, work string, opts Options) []Output {
	if a.Provider != "kubernetes" {
		return nil
	}
	out := filepath.Join(work, "trivy_k8s.json")
	args := []string{"k8s", "--report", "all", "-f", "json", "-o", out, "--quiet"}
	if a.KubeContext != "" {
		args = append(args, "--kubeconfig", os.Getenv("KUBECONFIG"), "--context", a.KubeContext)
	}
	run := execTool(ctx, opts, out, "trivy", args...)
	run.Account = a.Name
	return []Output{{Tool: "trivy", Source: "trivy", Account: a.Name, Path: out, Run: run}}
}

func runCheckovK8s(ctx context.Context, a *config.Account, work string, opts Options) Output {
	if a.Provider != "kubernetes" {
		return Output{Tool: "checkov", Run: model.ToolRun{Tool: "checkov", Account: a.Name, Status: "skipped", Message: "checkov live scan only supports kubernetes"}}
	}
	// Dump live manifests then scan them.
	dump := filepath.Join(work, "k8s-manifests.yaml")
	kargs := []string{"get", "all,sa,clusterrolebindings,networkpolicies,ns", "-A", "-o", "yaml"}
	if a.KubeContext != "" {
		kargs = append([]string{"--context", a.KubeContext}, kargs...)
	}
	run := execToolToFile(ctx, opts, dump, "kubectl", kargs...)
	if run.Status != "ok" {
		run.Tool, run.Account = "checkov", a.Name
		return Output{Tool: "checkov", Run: run}
	}
	out := filepath.Join(work, "checkov")
	os.MkdirAll(out, 0o755)
	run = execTool(ctx, opts, filepath.Join(out, "results_json.json"), "checkov", "-f", dump, "--framework", "kubernetes", "-o", "json", "--output-file-path", out, "--quiet", "--compact")
	run.Account = a.Name
	return Output{Tool: "checkov", Source: "checkov", Account: a.Name, Path: filepath.Join(out, "results_json.json"), Run: run}
}

func runPythonChecks(ctx context.Context, a *config.Account, work string, opts Options) Output {
	if a.Provider != "aws" {
		return Output{Tool: "python-checks", Run: model.ToolRun{Tool: "python-checks", Account: a.Name, Status: "skipped", Message: "native python checks currently cover aws"}}
	}
	py := opts.Python
	if py == "" {
		py = "python3"
	}
	// The module runs from an empty directory, so every path argument must be absolute.
	out, err := filepath.Abs(filepath.Join(work, "nimbus-checks.findings.json"))
	if err != nil {
		return Output{Tool: "python-checks", Run: model.ToolRun{Tool: "python-checks", Account: a.Name, Status: "failed", Message: err.Error()}}
	}
	args := []string{"-m", "nimbus.checks", "--provider", "aws", "--output", out}
	if a.Profile != "" {
		args = append(args, "--profile", a.Profile)
	}
	if a.RoleARN != "" {
		args = append(args, "--role-arn", a.RoleARN)
	}
	if len(a.Regions) > 0 {
		args = append(args, "--regions", strings.Join(a.Regions, ","))
	}
	// Never resolve nimbus from the process working directory (inventory defect 12): run
	// from a fresh private directory with PYTHONSAFEPATH=1, and put only the trusted
	// PythonDir on PYTHONPATH — the same discovery as cli.pythonDir/runPython.
	neutral, err := os.MkdirTemp("", "cloud-posture-py-")
	if err != nil {
		return Output{Tool: "python-checks", Run: model.ToolRun{Tool: "python-checks", Account: a.Name, Status: "failed", Message: err.Error()}}
	}
	defer os.RemoveAll(neutral)
	env := append(os.Environ(), "PYTHONSAFEPATH=1")
	if opts.PythonDir != "" {
		pp := opts.PythonDir
		if cur := os.Getenv("PYTHONPATH"); cur != "" {
			pp += string(os.PathListSeparator) + cur
		}
		env = append(env, "PYTHONPATH="+pp)
	}
	run := runExec(ctx, opts, execSpec{artifact: out, dir: neutral, env: env}, py, args...)
	run.Tool, run.Account = "python-checks", a.Name
	return Output{Tool: "python-checks", Source: "native", Account: a.Name, Path: out, Run: run}
}

// execSpec describes one tool invocation. artifact is the output file the tool is
// expected to produce; it decides whether a non-zero exit still produced usable output.
type execSpec struct {
	stdoutFile string
	artifact   string
	dir        string
	env        []string
}

func execTool(ctx context.Context, opts Options, artifact, bin string, args ...string) model.ToolRun {
	return runExec(ctx, opts, execSpec{artifact: artifact}, bin, args...)
}

func execToolToFile(ctx context.Context, opts Options, stdoutFile string, bin string, args ...string) model.ToolRun {
	return runExec(ctx, opts, execSpec{stdoutFile: stdoutFile, artifact: stdoutFile}, bin, args...)
}

// runExec runs one tool. Failure is decided by the exit status, a timeout, or a missing
// output artifact — never by words on stderr (inventory defect 19: prowler/checkov/trivy
// print "error" in warnings while writing valid output). Prowler, checkov and trivy exit
// non-zero when findings exist, so a non-zero exit (< 100) that still produced a
// non-empty artifact is ok; the adapter then rejects output it cannot parse. stderr is
// kept on the run, and its last line is the failure reason.
func runExec(ctx context.Context, opts Options, spec execSpec, bin string, args ...string) model.ToolRun {
	run := model.ToolRun{Tool: bin, Status: "ok"}
	if _, err := exec.LookPath(bin); err != nil {
		run.Status, run.Message = "skipped", bin+" not installed"
		return run
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = spec.dir
	if spec.env != nil {
		cmd.Env = spec.env
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	opts.logf("▶ %s %s", bin, strings.Join(args, " "))
	if spec.stdoutFile != "" {
		f, err := os.Create(spec.stdoutFile)
		if err != nil {
			run.Status, run.Message = "failed", err.Error()
			return run
		}
		defer f.Close()
		cmd.Stdout = f
	} else {
		cmd.Stdout = &stderr
	}
	err := cmd.Run()
	run.Output = truncate(stderr.String(), 2000)
	reason := lastLine(stderr.String())
	switch {
	case err == nil:
		return run
	case errors.Is(cctx.Err(), context.DeadlineExceeded):
		run.Status, run.Message = "failed", fmt.Sprintf("timeout after %s", timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		run.Status, run.Message = "failed", "canceled"
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() > 0 && ee.ExitCode() < 100 && nonEmptyFile(spec.artifact) {
			run.Message = fmt.Sprintf("exit %d (findings present)", ee.ExitCode())
			return run
		}
		run.Status, run.Message = "failed", err.Error()
		if spec.artifact != "" && !nonEmptyFile(spec.artifact) {
			run.Message += ", no output produced"
		}
	}
	if reason != "" {
		run.Message += ": " + reason
	}
	return run
}

func nonEmptyFile(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir() && st.Size() > 0
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return ""
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
