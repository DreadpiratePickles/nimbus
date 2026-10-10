package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W5-ISSUES / Verification 5 V1/C7, C8, V2: `verify --from-file` needs positive evidence. A file
// that never mentions the Issue's resource (or never evaluates its check) proves nothing: the
// result is `unverified`, the Issue and its ticket are untouched. The weakness observed again in
// the file reopens a closed Issue. Inputs are capped at 64 MiB and must be regular files.

type jiraRecorder struct {
	mu    sync.Mutex
	calls []string
	srv   *httptest.Server
}

func newJiraRecorder(t *testing.T) *jiraRecorder {
	t.Helper()
	j := &jiraRecorder{}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.mu.Lock()
		j.calls = append(j.calls, r.Method+" "+r.URL.Path)
		j.mu.Unlock()
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/transitions") {
			fmt.Fprint(w, `{"transitions":[{"id":"31","name":"Done","to":{"statusCategory":{"key":"done"}}},{"id":"11","name":"Reopen","to":{"statusCategory":{"key":"new"}}}]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(j.srv.Close)
	t.Setenv("JIRA_EMAIL", "bot@example.com")
	t.Setenv("JIRA_API_TOKEN", "test-token")
	return j
}

func (j *jiraRecorder) transitions() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	n := 0
	for _, c := range j.calls {
		if strings.HasPrefix(c, "POST ") && strings.HasSuffix(c, "/transitions") {
			n++
		}
	}
	return n
}

func lastVerification(t *testing.T, id string) store.Verification {
	t.Helper()
	st := openTestStore(t)
	vs, err := st.Verifications(id)
	if err != nil || len(vs) == 0 {
		t.Fatalf("verifications of %s: %d %v", id, len(vs), err)
	}
	return vs[len(vs)-1]
}

// The verifier's repro: one PASS finding on an unrelated bucket in the same scope.
func unrelatedFile(t *testing.T) string {
	t.Helper()
	src := labFinding(labCopy(t), "lab-W01")
	other := map[string]any{}
	for k, v := range src {
		other[k] = v
	}
	other["id"] = "zz-unrelated"
	other["status"] = "PASS"
	other["resource"] = map[string]any{"id": "arn:aws:s3:::totally-unrelated-bucket", "type": "aws_s3_bucket"}
	return writeFindings(t, t.TempDir(), "unrelated.findings.json", []map[string]any{other})
}

func TestVerifyFromFileWithoutTheResourceIsUnverified(t *testing.T) {
	h := withVerifyHooks(t)
	j := newJiraRecorder(t)
	cfg := writeConfig(t, t.TempDir(), "integrations:\n  jira:\n    url: "+j.srv.URL+"\n    project: SEC\n")
	ingestLab(t, cfg, labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	st := openTestStore(t)
	if err := st.SetIssueTicket(w01.ID, store.IssueTicket{Sink: "jira", Key: "SEC-9", URL: j.srv.URL + "/browse/SEC-9", State: "open"}); err != nil {
		t.Fatal(err)
	}
	file := unrelatedFile(t)
	for _, id := range []string{w01.ID, p01Issue(t)} {
		h.exit = -1
		before := issueByID(t, id)
		out := run(t, "-c", cfg, "verify", id, "--from-file", file, "--attempts", "1")
		got := issueByID(t, id)
		if got.State != before.State || got.VerifiedAt != nil || got.State == store.StateVerifiedFixed {
			t.Fatalf("%s: state %s → %s from a file that never mentions it:\n%s", id, before.State, got.State, out)
		}
		if v := lastVerification(t, id); v.Result != store.VerifyUnverified {
			t.Fatalf("%s: result %q, want unverified:\n%s", id, v.Result, out)
		}
		if h.exit != 2 || !strings.Contains(out, "unverified") {
			t.Fatalf("%s: exit %d, output lacks 'unverified':\n%s", id, h.exit, out)
		}
	}
	if issueByID(t, w01.ID).TicketState != "open" || j.transitions() != 0 {
		t.Fatalf("ticket touched: state %s, %d transitions", issueByID(t, w01.ID).TicketState, j.transitions())
	}
}

// The file observes the bucket, but only through a different check: S3_PUBLIC_BUCKET was never
// evaluated, so the finding Issue is unverified, and the path Issue is not verified fixed.
func TestVerifyFromFileOtherCheckOnResourceIsUnverified(t *testing.T) {
	h := withVerifyHooks(t)
	ingestLab(t, labConfig(t), labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	src := labFinding(labCopy(t), "lab-W01")
	other := map[string]any{}
	for k, v := range src {
		other[k] = v
	}
	other["id"], other["check_id"], other["status"], other["title"] = "zz-versioning", "s3_bucket_versioning_enabled", "PASS", "versioning"
	file := writeFindings(t, t.TempDir(), "other-check.json", []map[string]any{other})
	out := run(t, "-c", labConfig(t), "verify", w01.ID, "--from-file", file, "--attempts", "1")
	if v := lastVerification(t, w01.ID); v.Result != store.VerifyUnverified || h.exit != 2 {
		t.Fatalf("W01: result %q exit %d, want unverified:\n%s", v.Result, h.exit, out)
	}
	out = run(t, "-c", labConfig(t), "verify", p01Issue(t), "--from-file", file, "--attempts", "1")
	if got := issueByID(t, p01Issue(t)); got.State == store.StateVerifiedFixed {
		t.Fatalf("P01 verified fixed by an unrelated check on its anchor:\n%s", out)
	}
}

// Fixed (W01 PASS), then a file that observes W01 FAIL again: the verified_fixed Issue reopens.
func TestVerifyFromFileWeaknessObservedReopens(t *testing.T) {
	h := withVerifyHooks(t)
	ingestLab(t, labConfig(t), labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	fs := labCopy(t)
	pass := labFinding(fs, "lab-W01")
	pass["status"] = "PASS"
	fixed := writeFindings(t, t.TempDir(), "fixed.json", []map[string]any{pass})
	out := run(t, "-c", labConfig(t), "verify", w01.ID, "--from-file", fixed, "--attempts", "1")
	if got := issueByID(t, w01.ID); got.State != store.StateVerifiedFixed {
		t.Fatalf("W01 PASS in the file: state %s, want verified_fixed:\n%s", got.State, out)
	}
	fail := labFinding(labCopy(t), "lab-W01")
	again := writeFindings(t, t.TempDir(), "again.json", []map[string]any{fail})
	h.exit = -1
	out = run(t, "-c", labConfig(t), "verify", w01.ID, "--from-file", again, "--attempts", "1")
	if got := issueByID(t, w01.ID); got.State != model.StateReopened {
		t.Fatalf("W01 FAIL observed again: state %s, want reopened:\n%s", got.State, out)
	}
	if v := lastVerification(t, w01.ID); v.Result != store.VerifyReopened || h.exit != 2 {
		t.Fatalf("result %q exit %d, want reopened / 2", v.Result, h.exit)
	}
}

// A suppressed Issue stays suppressed whatever the file says (C8).
func TestVerifyFromFileKeepsSuppression(t *testing.T) {
	withVerifyHooks(t)
	ingestLab(t, labConfig(t), labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	st := openTestStore(t)
	if err := st.SuppressIssue(w01.ID, store.Suppression{Reason: "accepted", ExpiresAt: time.Now().Add(72 * time.Hour)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	pass := labFinding(labCopy(t), "lab-W01")
	pass["status"] = "PASS"
	run(t, "-c", labConfig(t), "verify", w01.ID, "--from-file", writeFindings(t, t.TempDir(), "p.json", []map[string]any{pass}), "--attempts", "1")
	if got := issueByID(t, w01.ID); got.State != model.StateSuppressed || got.Reason != "accepted" {
		t.Fatalf("suppression dropped: %s %q", got.State, got.Reason)
	}
}

// V2: the input is capped at 64 MiB and must be a regular file (no /dev/zero, no FIFO).
func TestVerifyFromFileInputCap(t *testing.T) {
	withVerifyHooks(t)
	ingestLab(t, labConfig(t), labFile(t, "estate.findings.json"))
	w01 := singleIssue(t, "S3_PUBLIC_BUCKET", labPII)
	big := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64<<20 + 1); err != nil { // sparse: no disk
		t.Fatal(err)
	}
	f.Close()
	for _, c := range []struct{ path, want string }{{big, "64 MiB"}, {"/dev/zero", "regular file"}} {
		start := time.Now()
		out, err := runErr(t, "-c", labConfig(t), "verify", w01.ID, "--from-file", c.path, "--attempts", "1")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: err %v, want %q:\n%s", c.path, err, c.want, out)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("%s: refused only after %s", c.path, time.Since(start))
		}
	}
	if got := issueByID(t, w01.ID); !model.IsActive(got.State) {
		t.Fatalf("state changed by a refused file: %s", got.State)
	}
}
