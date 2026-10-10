package gitops

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Verify-4 defect 6: the action's plan-diff guard is an allowlist of events (pull_request, push,
// workflow_dispatch); every other event (pull_request_target, workflow_run, issue_comment, ...)
// is refused by name. The step's own shell is evaluated with each event.
func TestActionPlanDiffGuardAllowlistsEvents(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &action); err != nil {
		t.Fatal(err)
	}
	script := ""
	for _, s := range action.Runs.Steps {
		if s.Name == "Plan-diff guard" {
			script = s.Run
			if !strings.Contains(s.Env["CP_EVENT"], "github.event_name") {
				t.Fatalf("guard does not read github.event_name: %v", s.Env)
			}
		}
	}
	if script == "" {
		t.Fatal("Plan-diff guard step not found")
	}
	run := func(event string) (int, string) {
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "CP_EVENT="+event)
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	for _, ev := range []string{"pull_request", "push", "workflow_dispatch"} {
		if code, out := run(ev); code != 0 {
			t.Errorf("%s refused (exit %d): %s", ev, code, out)
		}
	}
	for _, ev := range []string{"pull_request_target", "workflow_run", "issue_comment", "pull_request_review_comment", "schedule", "repository_dispatch", "merge_group", "", "pull_request ", "PULL_REQUEST", "push;true"} {
		code, out := run(ev)
		if code == 0 {
			t.Errorf("event %q allowed", ev)
		}
		if ev != "" && !strings.Contains(out, "::error::") {
			t.Errorf("event %q: no ::error:: message: %s", ev, out)
		}
	}
}

// Shortfall #6 (delta r3): the Action passes --iac by default (the checkout's iac-path, or the
// terraform-dir when the action runs the plan), so one-click suggestions are reachable from the
// Action; suggestions: "false" turns it off. The plan-diff step's own shell is run with a fake
// cloud-posture that records its arguments.
func TestActionPlanDiffPassesIaCByDefault(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Runs struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &action); err != nil {
		t.Fatal(err)
	}
	if action.Inputs["suggestions"].Default != "true" {
		t.Errorf("suggestions input default %q, want true", action.Inputs["suggestions"].Default)
	}
	script, env := "", map[string]string{}
	for _, s := range action.Runs.Steps {
		if strings.HasPrefix(s.Name, "Plan diff (") {
			script, env = s.Run, s.Env
		}
	}
	if script == "" {
		t.Fatal("plan diff step not found")
	}
	if !strings.Contains(env["CP_IAC"], "inputs.iac-path") || !strings.Contains(env["CP_SUGGEST"], "inputs.suggestions") || !strings.Contains(env["CP_TF_DIR"], "inputs.terraform-dir") {
		t.Fatalf("plan diff env %v", env)
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	os.WriteFile(filepath.Join(dir, "cloud-posture"), []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > "+argsFile+"\n"), 0o755)
	run := func(extra ...string) string {
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "GITHUB_STEP_SUMMARY="+filepath.Join(dir, "summary"), "GITHUB_ENV="+filepath.Join(dir, "env"),
			"CP_PLAN_INPUT=plan.json", "CP_EVENT=push", "CP_REPO=o/r", "CP_PR=", "CP_REDACT=auto", "CP_TRUSTED=", "CP_MAX_PATHS=10", "CP_FAIL_OPENED=false", "CP_COMMENT=true", "CP_IAC=.", "CP_TF_DIR=", "CP_SUGGEST=true")
		cmd.Env = append(cmd.Env, extra...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("step failed: %v %s", err, out)
		}
		a, _ := os.ReadFile(argsFile)
		return "\n" + string(a)
	}
	if a := run(); !strings.Contains(a, "\n--iac\n.\n") {
		t.Errorf("default run lacks --iac .: %q", a)
	}
	if a := run("CP_TF_DIR=infra/prod"); !strings.Contains(a, "\n--iac\ninfra/prod\n") {
		t.Errorf("terraform-dir run lacks --iac infra/prod: %q", a)
	}
	if a := run("CP_SUGGEST=false"); strings.Contains(a, "--iac") {
		t.Errorf("suggestions=false still passes --iac: %q", a)
	}
}
