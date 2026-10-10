package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Verification 7 defect 8: a regression caught by `verify` (verified_fixed → reopened) was never
// counted as "regressed after verify": the Issue row and its history row carried 0, and the next
// scan saw an already-reopened Issue. It now marks the Issue and the history row and the next
// scan's trend counts it once.
func TestVerifyReopenCountsAsRegressedAfterVerify(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b := mkFinding("prowler", "b", "CHECK_B", "arn:aws:s3:::b", model.High)
	trendScan(t, st, "s1", t0, b)
	is, _ := st.Issues(IssueFilter{})
	id := is[0].ID
	verifyFixed(t, st, id, t0.Add(10*time.Minute))
	if err := st.RecordVerification(Verification{IssueID: id, Result: VerifyReopened, At: t0.Add(20 * time.Minute), VerifiedBy: "rescan", Reads: 3, Required: 3}); err != nil {
		t.Fatal(err)
	}
	var flag int
	st.db.QueryRow("SELECT regressed_after_verify FROM issues WHERE id = ?", id).Scan(&flag)
	if flag != 1 {
		t.Errorf("Issue regressed_after_verify = %d, want 1", flag)
	}
	h, _ := st.PathIssueHistory(id)
	if len(h) == 0 || !h[len(h)-1].RegressedAfterVerify {
		t.Errorf("history row of the verify reopen lacks regressed_after_verify: %+v", h)
	}
	m, err := st.ClosureMetrics()
	if err != nil || m.RegressionsAfterVerify != 1 {
		t.Errorf("closure metrics regressions = %+v %v", m, err)
	}
	trendScan(t, st, "s2", t0.Add(time.Hour), b)
	tr, _ := st.ScanTrendOf("s2")
	if tr == nil || tr.Regressed != 1 || tr.Reopened != 0 {
		t.Fatalf("trend after a verify-caught regression = %+v", tr)
	}
	// A reopen of an Issue that was never verified_fixed is not a regression after verify.
	c := mkFinding("prowler", "c", "CHECK_C", "arn:aws:s3:::c", model.High)
	trendScan(t, st, "s3", t0.Add(2*time.Hour), b, c)
	for _, i := range mustIssues(t, st) {
		if i.CanonicalID == "CHECK_C" {
			st.RecordVerification(Verification{IssueID: i.ID, Result: VerifyReopened, At: t0.Add(150 * time.Minute)})
			st.db.QueryRow("SELECT regressed_after_verify FROM issues WHERE id = ?", i.ID).Scan(&flag)
			if flag != 0 {
				t.Errorf("an Issue never verified fixed marked regressed")
			}
		}
	}
}

func mustIssues(t *testing.T, st *Store) []model.Issue {
	t.Helper()
	is, err := st.Issues(IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return is
}
