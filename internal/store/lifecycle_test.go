package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func bucketFinding(scan string, check, bucket string, status model.Status, now time.Time) model.Finding {
	f := model.Finding{Source: "prowler", CheckID: check, CanonicalID: "S3_PUBLIC_BUCKET", Title: "public bucket", Severity: model.High, Status: status,
		Provider: "aws", Account: "123", Region: "us-east-1", ScanID: scan,
		Resource: model.Resource{ID: "arn:aws:s3:::" + bucket, Type: "aws_s3_bucket", Name: bucket}, Weaknesses: []string{"PUBLIC_DATA_STORE"}}
	f.Finalize(now)
	return f
}

// Defect 19a: the fix-the-public-bucket scenario. Scan 1 sees two public buckets; the user
// fixes "pii"; scan 2 (same source/provider/account) no longer reports it. It must become
// resolved, and come back as reopened (first_seen preserved) when it regresses in scan 3.
func TestFixThePublicBucketLifecycle(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	pii := bucketFinding("s1", "s3_bucket_public_access", "pii", model.Fail, t0)
	logs := bucketFinding("s1", "s3_bucket_public_access", "logs", model.Fail, t0)

	d1, err := st.ApplyScan("s1", []model.Finding{pii, logs}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{pii, logs})})
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.New) != 2 || len(d1.Resolved) != 0 || len(d1.Reopened) != 0 {
		t.Fatalf("scan 1 diff = %+v, want 2 new", d1)
	}

	// scan 2: pii fixed (absent), logs still public
	t1 := t0.Add(24 * time.Hour)
	logs2 := bucketFinding("s2", "s3_bucket_public_access", "logs", model.Fail, t1)
	d2, err := st.ApplyScan("s2", []model.Finding{logs2}, t1, ApplyOptions{Scopes: ScopesOf([]model.Finding{logs2})})
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.New) != 0 || len(d2.Resolved) != 1 || d2.Resolved[0] != pii.ID || len(d2.Reopened) != 0 {
		t.Fatalf("scan 2 diff = %+v, want pii resolved", d2)
	}
	lc, err := st.Lifecycle(pii.ID)
	if err != nil || lc.State != model.StateResolved || lc.ResolvedAt == nil || !lc.ResolvedAt.Equal(t1) {
		t.Fatalf("pii lifecycle after fix: %+v %v", lc, err)
	}
	open, _ := st.Findings(Filter{Status: "FAIL"})
	if len(open) != 1 || open[0].ID != logs.ID {
		t.Fatalf("open findings after fix = %d, want only logs", len(open))
	}
	all, _ := st.Findings(Filter{IncludeResolved: true})
	if len(all) != 2 {
		t.Fatalf("history must be kept: %d rows", len(all))
	}

	// scan 3: pii public again -> reopened, first_seen preserved
	t2 := t1.Add(24 * time.Hour)
	pii3 := bucketFinding("s3", "s3_bucket_public_access", "pii", model.Fail, t2)
	logs3 := bucketFinding("s3", "s3_bucket_public_access", "logs", model.Fail, t2)
	d3, err := st.ApplyScan("s3", []model.Finding{pii3, logs3}, t2, ApplyOptions{Scopes: ScopesOf([]model.Finding{pii3, logs3})})
	if err != nil {
		t.Fatal(err)
	}
	if len(d3.Reopened) != 1 || d3.Reopened[0] != pii.ID || len(d3.New) != 0 || len(d3.Resolved) != 0 {
		t.Fatalf("scan 3 diff = %+v, want pii reopened", d3)
	}
	lc, _ = st.Lifecycle(pii.ID)
	if lc.State != model.StateReopened || lc.ReopenedAt == nil || !lc.ReopenedAt.Equal(t2) || !lc.FirstSeen.Equal(t0) {
		t.Fatalf("pii lifecycle after regression: %+v", lc)
	}
	f, _ := st.Finding(pii.ID)
	if !f.FirstSeen.Equal(t0) {
		t.Errorf("stored doc first_seen = %v, want %v (preserved)", f.FirstSeen, t0)
	}
	hist, err := st.History(pii.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"open:s1", "resolved:s2", "reopened:s3"}
	if len(hist) != len(want) {
		t.Fatalf("history = %+v, want %v", hist, want)
	}
	for i, h := range hist {
		if h.State+":"+h.ScanID != want[i] {
			t.Errorf("history[%d] = %s:%s, want %s", i, h.State, h.ScanID, want[i])
		}
	}
}

// A finding re-observed with status PASS is resolved too; absence outside the scanned scope is not.
func TestResolveOnlyWithinScannedScope(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a := bucketFinding("s1", "c", "a", model.Fail, t0)
	other := bucketFinding("s1", "c", "b", model.Fail, t0)
	other.Account = "999" // different account
	other.ID = ""
	other.Finalize(t0)
	ckv := bucketFinding("s1", "c", "a", model.Fail, t0)
	ckv.Source = "checkov" // different source, same resource
	ckv.ID = ""
	ckv.Finalize(t0)
	if _, err := st.ApplyScan("s1", []model.Finding{a, other, ckv}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{a, other, ckv})}); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Hour)
	aPass := bucketFinding("s2", "c", "a", model.Pass, t1)
	d, err := st.ApplyScan("s2", []model.Finding{aPass}, t1, ApplyOptions{Scopes: ScopesOf([]model.Finding{aPass})})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Resolved) != 1 || d.Resolved[0] != a.ID {
		t.Fatalf("diff %+v: only the PASS-observed finding should resolve", d)
	}
	for _, id := range []string{other.ID, ckv.ID} {
		if lc, _ := st.Lifecycle(id); lc.State != model.StateOpen {
			t.Errorf("%s outside the scanned scope changed state to %s", id, lc.State)
		}
	}
	// A skipped scope (e.g. the collector had access-denied errors) never resolves by absence.
	d, err = st.ApplyScan("s3", nil, t1.Add(time.Hour), ApplyOptions{Scopes: []Scope{{Source: "prowler", Provider: "aws", Account: "999"}}, SkipScopes: []Scope{{Source: "prowler", Provider: "aws", Account: "999"}}})
	if err != nil || len(d.Resolved) != 0 {
		t.Fatalf("skipped scope resolved findings: %+v %v", d, err)
	}
}

func TestScopeRootLimitsIaCResolution(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(root, file string) model.Finding {
		f := model.Finding{Source: "nimbus-iac", CheckID: "tf_public", Severity: model.High, Status: model.Fail, Provider: "iac", Account: "iac", File: file,
			Resource: model.Resource{ID: "aws_s3_bucket.x"}, Tags: map[string]string{TagScanRoot: root}}
		f.Finalize(t0)
		return f
	}
	a, b := mk("./a", "a/main.tf"), mk("./b", "b/main.tf")
	st.ApplyScan("s1", []model.Finding{a}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{a})})
	st.ApplyScan("s2", []model.Finding{b}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{b})})
	if lc, _ := st.Lifecycle(a.ID); lc.State != model.StateOpen {
		t.Fatalf("scanning ./b resolved a finding under ./a: %s", lc.State)
	}
}
