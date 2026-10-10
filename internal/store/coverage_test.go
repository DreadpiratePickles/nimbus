package store

import (
	"context"
	"testing"
	"time"
)

// O46: per-account record of which API calls / tools ran, were denied, skipped, errored or timed out.
func TestCoverageRecordedAndSummarized(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	entries := []CoverageEntry{
		{Provider: "aws", Account: "prod", API: "collector:nimbus-aws", Status: CoverageOK},
		{Provider: "aws", Account: "prod", API: "s3:GetBucketPolicyStatus", Status: CoverageDenied, Reason: "AccessDenied: not authorized"},
		{Provider: "aws", Account: "prod", API: "tool:prowler", Status: CoverageSkipped, Reason: "prowler not installed"},
		{Provider: "aws", Account: "prod", API: "account", Status: CoverageTimeout, Reason: "context deadline exceeded"},
		{Provider: "github", Account: "acme", API: "github: repo acme/x", Status: CoverageError, Reason: "rate_limited"},
	}
	if err := st.RecordCoverage("s1", now, entries); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCoverage("s1", now, []CoverageEntry{{Provider: "aws", Account: "prod", API: "x", Status: "bogus"}}); err == nil {
		t.Errorf("an unknown coverage status must be rejected")
	}
	got, err := st.Coverage("s1")
	if err != nil || len(got) != len(entries) {
		t.Fatalf("coverage rows = %d %v", len(got), err)
	}
	if _, err := st.EnsureViews(); err != nil {
		t.Fatal(err)
	}
	res, err := st.QueryReadOnly(context.Background(), "SELECT provider, account, status, count FROM coverage_summary WHERE scan_id = 's1' AND status = 'denied'", ReadOnlyOptions{})
	if err != nil || len(res.Rows) != 1 || res.Rows[0][3] != int64(1) {
		t.Fatalf("coverage_summary: %v %+v", err, res)
	}
}

// The documented hook: any collector error type exposing provider/account/API/reason can be recorded.
type fakeCollectErr struct{ p, a, api, reason, msg string }

func (f fakeCollectErr) CoverageFields() (string, string, string, string, string) {
	return f.p, f.a, f.api, f.reason, f.msg
}

func TestRecordCollectErrors(t *testing.T) {
	st := openTemp(t)
	now := time.Now().UTC()
	errs := []CollectErrorLike{
		fakeCollectErr{"aws", "prod", "s3:pii", "access_denied", "AccessDenied"},
		fakeCollectErr{"aws", "prod", "account", "timeout", "deadline"},
		fakeCollectErr{"gcp", "proj", "iam", "rate_limited", "429"},
		fakeCollectErr{"azure", "sub", "collector", "unsupported_provider", "nope"},
	}
	if err := st.RecordCollectErrors("s1", now, errs); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Coverage("s1")
	want := map[string]string{"s3:pii": CoverageDenied, "account": CoverageTimeout, "iam": CoverageError, "collector": CoverageSkipped}
	for _, c := range got {
		if want[c.API] != c.Status {
			t.Errorf("%s -> %s, want %s", c.API, c.Status, want[c.API])
		}
		if c.Reason == "" {
			t.Errorf("%s: reason must be kept", c.API)
		}
	}
}
