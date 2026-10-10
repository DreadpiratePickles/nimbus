package gitops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestSafeJoinContainsPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(root, "infra"), 0o755)
	os.WriteFile(filepath.Join(outside, "secret.tf"), []byte("x"), 0o600)
	os.Symlink(filepath.Join(outside, "secret.tf"), filepath.Join(root, "infra", "link.tf"))
	os.Symlink(outside, filepath.Join(root, "dirlink"))
	for _, bad := range []string{"../etc/passwd", "../../../../etc/passwd", "infra/../../x.tf", "/etc/passwd", filepath.Join(outside, "secret.tf"),
		"infra/link.tf", "dirlink/secret.tf", "dirlink/new.tf", ""} {
		_, err := SafeJoin(root, bad)
		var pe *PathEscapeError
		if !errors.As(err, &pe) {
			t.Errorf("SafeJoin(root, %q) = %v, want *PathEscapeError", bad, err)
		}
	}
	for _, ok := range []string{"infra/main.tf", "main.tf", "infra/new/file.tf", filepath.Join(root, "infra", "main.tf"), "./infra//main.tf"} {
		if _, err := SafeJoin(root, ok); err != nil {
			t.Errorf("SafeJoin(root, %q) = %v", ok, err)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// repoWithInfra builds top/{main.tf,infra/main.tf} committed, with a bare "origin" to push to.
func repoWithInfra(t *testing.T) (top, infra string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for k, v := range map[string]string{"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_NOSYSTEM": "1"} {
		t.Setenv(k, v)
	}
	base := t.TempDir()
	top, bare := filepath.Join(base, "repo"), filepath.Join(base, "origin.git")
	infra = filepath.Join(top, "infra")
	os.MkdirAll(infra, 0o755)
	os.WriteFile(filepath.Join(top, "main.tf"), []byte("# top-level, must not change\n"), 0o644)
	os.WriteFile(filepath.Join(infra, "main.tf"), []byte("# infra before\n"), 0o644)
	gitRun(t, base, "init", "-q", "--bare", bare)
	gitRun(t, top, "init", "-q", "-b", "main")
	gitRun(t, top, "add", ".")
	gitRun(t, top, "commit", "-q", "-m", "init")
	gitRun(t, top, "remote", "add", "origin", bare)
	return top, infra
}

// Inventory defect 5: the patch was read relative to --iac but written relative to the git
// top level, so `--iac infra` overwrote top/main.tf.
func TestOpenFixPRWritesTheFileItRead(t *testing.T) {
	top, infra := repoWithInfra(t)
	p := iac.Patch{File: "main.tf", Address: "aws_instance.web", CanonicalID: "EC2_IMDSV1", Before: "# infra before\n", After: "# infra patched\n"}
	_, err := OpenFixPR(context.Background(), []iac.Patch{p}, []model.Finding{{CanonicalID: "EC2_IMDSV1"}}, nil, PROptions{RepoDir: infra, Branch: "fix/x"})
	if err == nil || !errors.Is(err, ErrUnknownHost) {
		t.Logf("OpenFixPR: %v", err) // unknown host after a successful push is expected
	}
	if b, _ := os.ReadFile(filepath.Join(top, "main.tf")); string(b) != "# top-level, must not change\n" {
		t.Errorf("top-level main.tf was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(infra, "main.tf")); string(b) != "# infra patched\n" {
		t.Errorf("infra/main.tf not patched: %q", b)
	}
}

func TestOpenFixPRRejectsEscapingPaths(t *testing.T) {
	top, infra := repoWithInfra(t)
	outside := filepath.Join(filepath.Dir(top), "outside.tf")
	os.WriteFile(outside, []byte("# outside\n"), 0o644)
	os.Symlink(outside, filepath.Join(infra, "link.tf"))
	gitRun(t, top, "add", ".")
	gitRun(t, top, "commit", "-q", "-m", "link")
	for i, file := range []string{"../../outside.tf", outside, "link.tf", "../main.tf"} {
		p := iac.Patch{File: file, CanonicalID: "EC2_IMDSV1", After: "# pwned\n"}
		_, err := OpenFixPR(context.Background(), []iac.Patch{p}, nil, nil, PROptions{RepoDir: infra, Branch: fmt.Sprintf("fix/%d", i)})
		var pe *PathEscapeError
		if !errors.As(err, &pe) {
			t.Errorf("OpenFixPR(%q) = %v, want *PathEscapeError", file, err)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "# outside\n" {
		t.Errorf("file outside the repo was written: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(top, "main.tf")); string(b) != "# top-level, must not change\n" {
		t.Errorf("file outside --iac root was written: %q", b)
	}
}
