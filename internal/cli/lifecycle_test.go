package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// writeProwler writes the prowler fixture, optionally without the public-bucket finding
// (the user fixed it) — the "fix the public bucket" scenario across two ingests.
func writeProwler(t *testing.T, dir, name string, fixed bool) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "prowler.ocsf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var items []map[string]any
	if err := json.Unmarshal(data, &items); err != nil {
		t.Fatal(err)
	}
	var keep []map[string]any
	for _, it := range items {
		md, _ := it["metadata"].(map[string]any)
		if fixed && md["event_code"] == "s3_bucket_public_access" {
			continue
		}
		keep = append(keep, it)
	}
	out, _ := json.Marshal(keep)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIngestDiffFixThePublicBucket(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	before := writeProwler(t, dir, "prowler-before.ocsf.json", false)
	after := writeProwler(t, dir, "prowler-after.ocsf.json", true)

	out := run(t, "ingest", before, "--source", "prowler", "--diff", "-o", "summary")
	if !regexp.MustCompile(`12 new, 0 resolved, 0 reopened`).MatchString(out) {
		t.Fatalf("first ingest diff:\n%s", out)
	}
	out = run(t, "ingest", after, "--source", "prowler", "--diff", "-o", "summary")
	if !regexp.MustCompile(`0 new, 1 resolved, 0 reopened`).MatchString(out) || !strings.Contains(out, "S3_PUBLIC_BUCKET") {
		t.Fatalf("second ingest must resolve the fixed bucket:\n%s", out)
	}
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := st.Findings(store.Filter{CanonicalID: "S3_PUBLIC_BUCKET", IncludeResolved: true})
	if len(fs) != 1 {
		t.Fatalf("public bucket finding rows: %d", len(fs))
	}
	id := fs[0].ID
	if !strings.Contains(out, id) {
		t.Errorf("diff must print the resolved id %s:\n%s", id, out)
	}
	if lc, _ := st.Lifecycle(id); lc.State != model.StateResolved {
		t.Errorf("state %s, want resolved", lc.State)
	}
	if open, _ := st.Findings(store.Filter{CanonicalID: "S3_PUBLIC_BUCKET"}); len(open) != 0 {
		t.Errorf("the fixed bucket still counts as current posture")
	}
	counts, _ := st.IssueCounts()
	st.Close()
	if counts == nil || counts.Open == 0 {
		t.Fatalf("issues not rebuilt after ingest: %+v", counts)
	}

	out = run(t, "ingest", before, "--source", "prowler", "--diff", "-o", "summary")
	if !regexp.MustCompile(`0 new, 0 resolved, 1 reopened`).MatchString(out) || !strings.Contains(out, id) {
		t.Fatalf("regression must reopen:\n%s", out)
	}
}

// O46: tool statuses, collector errors and runner failures land in the coverage table;
// collector errors no longer masquerade as failed tool runs.
func TestScanRecordsCoverage(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	sum := model.ScanSummary{ScanID: "cov-1", Tools: []model.ToolRun{
		{Tool: "nimbus-aws", Account: "prod", Status: "ok", Findings: 3},
		{Tool: "prowler", Account: "prod", Status: "skipped", Message: "prowler not installed"},
		{Tool: "steampipe", Account: "prod", Status: "failed", Message: "timeout after 45m0s"},
		{Tool: "scoutsuite", Account: "prod", Status: "failed", Message: "exit status 1, no output produced: AccessDenied: not authorized"},
	}}
	errs := []collector.CollectError{
		{Provider: "aws", Account: "prod", API: "s3:pii", Reason: "access_denied", Message: "AccessDenied", Err: errors.New("AccessDenied")},
	}
	f := model.Finding{Source: "nimbus", CheckID: "c", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "prod", Resource: model.Resource{ID: "r"}, ScanID: "cov-1"}
	f.Finalize(time.Now())
	if _, err := finishScanWith(t.Context(), nil, []model.Finding{f}, graph.New(), nil, sum, scanOptions{CollectErrors: errs, Providers: map[string]string{"prod": "aws"}}); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(flagDB)
	defer st.Close()
	cov, err := st.Coverage("cov-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cov {
		got[c.API] = c.Status
		if c.Provider != "aws" {
			t.Errorf("%s: provider %q, want aws (from config)", c.API, c.Provider)
		}
		if c.Status != store.CoverageOK && c.Reason == "" {
			t.Errorf("%s: %s without a reason", c.API, c.Status)
		}
	}
	want := map[string]string{"tool:nimbus-aws": "ok", "tool:prowler": "skipped", "tool:steampipe": "timeout", "tool:scoutsuite": "denied", "s3:pii": "denied"}
	for api, status := range want {
		if got[api] != status {
			t.Errorf("coverage %s = %q, want %q (all: %v)", api, got[api], status, got)
		}
	}
}
