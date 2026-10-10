package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verify-4 defect 7 (D3): a single/combination Issue whose suppression expires gets a fresh
// episode, recorded as issue-level transitions (suppressed at suppression time, reopened at
// the rebuild that un-suppresses it), exactly as a path Issue's history records them.
func TestExpiredSuppressionStartsFreshEpisodeForSingleIssue(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{mkFinding("prowler", "c", "S3_PUBLIC_BUCKET", "arn:aws:s3:::b", model.High, "PUBLIC_DATA_STORE")}
	if _, err := st.ApplyScan("s1", fs, t0, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	is, _ := st.Issues(IssueFilter{Kind: model.IssueSingle})
	if len(is) != 1 {
		t.Fatalf("single issues: %d", len(is))
	}
	ts, until := t0.Add(24*time.Hour), t0.Add(30*24*time.Hour)
	if err := st.SuppressIssue(is[0].ID, Suppression{Reason: "accepted", ExpiresAt: until}, ts); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(ts.Add(time.Hour)); err != nil { // still suppressed: no transition
		t.Fatal(err)
	}
	after := until.Add(time.Hour)
	if err := st.RebuildIssues(after); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(after.Add(time.Hour)); err != nil { // stays reopened: no duplicate row
		t.Fatal(err)
	}
	h, err := st.PathIssueHistory(is[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range h {
		got = append(got, e.State+"@"+e.At.UTC().Format(time.RFC3339))
	}
	want := []string{model.StateSuppressed + "@" + ts.Format(time.RFC3339), model.StateReopened + "@" + after.Format(time.RFC3339)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("issue transitions %v, want %v", got, want)
	}
}

// Verify-4 LOW: suppression bounds.
func TestSuppressionBounds(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{mkFinding("prowler", "c", "S3_PUBLIC_BUCKET", "arn:aws:s3:::b", model.High, "PUBLIC_DATA_STORE")}
	st.ApplyScan("s1", fs, t0, ApplyOptions{Scopes: ScopesOf(fs)})
	st.RebuildIssues(t0)
	is, _ := st.Issues(IssueFilter{Kind: model.IssueSingle})
	id := is[0].ID
	var se *SuppressionError
	for name, sup := range map[string]Suppression{
		"expiry 9999-12-31":   {Reason: "r", ExpiresAt: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)},
		"expiry > 1 year":     {Reason: "r", ExpiresAt: t0.Add(MaxSuppression + time.Second)},
		"900 KB reason":       {Reason: strings.Repeat("x", 900<<10), ExpiresAt: t0.Add(time.Hour)},
		"reason > 2 KB":       {Reason: strings.Repeat("y", MaxSuppressionReason+1), ExpiresAt: t0.Add(time.Hour)},
		"approved_by > 256 B": {Reason: "r", ExpiresAt: t0.Add(time.Hour), ApprovedBy: strings.Repeat("a", 300)},
	} {
		if err := st.SuppressIssue(id, sup, t0); !errors.As(err, &se) {
			t.Errorf("%s: SuppressIssue = %v, want *SuppressionError", name, err)
		}
	}
	if err := st.SuppressIssue(id, Suppression{Reason: strings.Repeat("z", MaxSuppressionReason), ExpiresAt: t0.Add(MaxSuppression)}, t0); err != nil {
		t.Errorf("exactly at the bounds: %v", err)
	}
}
