package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W7-VERIFY r5 #6: the verify tool takes an optional from_file inside the read scope. It
// evaluates the file exactly as `cloud-posture verify --from-file` does (the evaluator is the
// CLI's, registered at start-up) and writes nothing: no verification row, no state change, no
// ticket. The file must be a regular file under the server's file roots (the database directory
// and the working directory by default): a client cannot make the server read /etc/passwd or
// follow a symlink out of the roots.

type fakeFileVerifier struct {
	calls []string
	issue string
}

func (f *fakeFileVerifier) verify(_ context.Context, rd Reader, is model.Issue, path string) (map[string]any, error) {
	f.calls = append(f.calls, path)
	f.issue = is.ID
	if _, err := rd.Findings(store.Filter{}); err != nil {
		return nil, err
	}
	return map[string]any{"result": "verified-fixed", "reason": "no surviving path", "recorded": false}, nil
}

func TestVerifyToolFromFileEvaluatesInsideRoots(t *testing.T) {
	fx := newFixture(t)
	issues, _ := fx.st.Issues(store.IssueFilter{})
	is := issues[0]
	root := t.TempDir()
	inside := filepath.Join(root, "fixed.findings.json")
	if err := os.WriteFile(inside, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "elsewhere.json")
	os.WriteFile(outside, []byte("[]"), 0o600)
	link := filepath.Join(root, "escape.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	fv := &fakeFileVerifier{}
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{Traversal: labTraversal, NoRedact: true, VerifyFile: fv.verify, FileRoots: []string{root}})
	c.initialize()

	out := c.toolOK("verify", map[string]any{"issue_id": is.ID, "from_file": inside})
	fe, _ := out["file_evaluation"].(map[string]any)
	if fe == nil || fe["result"] != "verified-fixed" || fe["recorded"] != false {
		t.Fatalf("file_evaluation = %v", out["file_evaluation"])
	}
	if out["mutates"] != false {
		t.Errorf("mutates = %v", out["mutates"])
	}
	if len(fv.calls) != 1 || fv.issue != is.ID {
		t.Fatalf("evaluator calls %v issue %q", fv.calls, fv.issue)
	}
	// Relative to the first root.
	c.toolOK("verify", map[string]any{"issue_id": is.ID, "from_file": "fixed.findings.json"})

	for _, bad := range []string{outside, link, "/etc/passwd", filepath.Join(root, "missing.json"), root, "../" + filepath.Base(outsideDir) + "/elsewhere.json"} {
		tr, r := c.tool("verify", map[string]any{"issue_id": is.ID, "from_file": bad})
		if r.Error == nil && !tr.IsError {
			t.Errorf("from_file %q accepted", bad)
		}
		if len(tr.Content) > 0 && strings.Contains(tr.Content[0].Text, "root:") {
			t.Errorf("an error leaks file content: %s", tr.Content[0].Text)
		}
	}
	if len(fv.calls) != 2 {
		t.Errorf("evaluator ran for a refused path: %v", fv.calls)
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Errorf("verify from_file wrote to the database")
	}
}

func TestVerifyToolFromFileWithoutEvaluator(t *testing.T) {
	fx := newFixture(t)
	issues, _ := fx.st.Issues(store.IssueFilter{})
	old := DefaultFileVerifier
	DefaultFileVerifier = nil
	t.Cleanup(func() { DefaultFileVerifier = old })
	root := t.TempDir()
	p := filepath.Join(root, "f.json")
	os.WriteFile(p, []byte("[]"), 0o600)
	c := startServer(t, fx.st, Options{Traversal: labTraversal, NoRedact: true, FileRoots: []string{root}})
	c.initialize()
	tr, r := c.tool("verify", map[string]any{"issue_id": issues[0].ID, "from_file": p})
	if r.Error == nil && !tr.IsError {
		t.Fatalf("from_file without an evaluator must be a tool error")
	}
	// Without from_file the tool is unchanged.
	c.toolOK("verify", map[string]any{"issue_id": issues[0].ID})
}
