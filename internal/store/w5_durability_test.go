package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W5-ISSUES item 1 (r3 #3) and Verification 5 C2: verified_fixed is a terminal closed state that
// survives later rebuilds while the problem stays absent, and turns into reopened (flagged
// regressed_after_verify) the moment the same finding / path is observed again.

func singleIssueID(t *testing.T, st *Store) string {
	t.Helper()
	is, err := st.Issues(IssueFilter{Kind: model.IssueSingle})
	if err != nil || len(is) != 1 {
		t.Fatalf("single Issues: %d %v, want 1", len(is), err)
	}
	return is[0].ID
}

func verifyFixed(t *testing.T, st *Store, id string, at time.Time) {
	t.Helper()
	if err := st.RecordVerification(Verification{IssueID: id, Result: VerifyFixed, At: at, VerifiedBy: "rescan", Reads: 3, Confirmations: 3, Required: 3,
		Evidence: []string{"read 1: absent", "read 2: absent", "read 3: absent"}}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifiedFixedFindingIssueSurvivesIngestWhileAbsent(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f := mkFinding("prowler", "s3_public", "S3_PUBLIC_BUCKET", "arn:aws:s3:::pii", model.High, "PUBLIC_DATA_STORE")
	if _, err := st.ApplyScan("s1", []model.Finding{f}, t0, ApplyOptions{Scopes: ScopesOf([]model.Finding{f})}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(t0); err != nil {
		t.Fatal(err)
	}
	id := singleIssueID(t, st)
	verifyFixed(t, st, id, t0.Add(time.Hour))
	// The next ingest no longer reports the finding: it resolves, the Issue stays verified_fixed.
	if _, err := st.ApplyScan("s2", nil, t0.Add(2*time.Hour), ApplyOptions{Scopes: ScopesOf([]model.Finding{f})}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: idempotent
		if err := st.RebuildIssues(t0.Add(time.Duration(2+i) * time.Hour)); err != nil {
			t.Fatal(err)
		}
		is := issueByID(t, st, id)
		if is.State != model.StateVerifiedFixed || is.VerifiedAt == nil || is.VerifiedBy != "rescan" {
			t.Fatalf("rebuild %d: state %s verified_at %v by %q, want verified_fixed kept", i, is.State, is.VerifiedAt, is.VerifiedBy)
		}
	}
	c, err := st.IssueCounts()
	if err != nil {
		t.Fatal(err)
	}
	if c.VerifiedFixed != 1 || c.Resolved != 0 || c.Open != 0 {
		t.Errorf("counts: verified %d resolved %d open %d, want 1/0/0", c.VerifiedFixed, c.Resolved, c.Open)
	}
}

func TestVerifiedFixedFindingIssueReopensWhenProblemPresent(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f := mkFinding("prowler", "s3_public", "S3_PUBLIC_BUCKET", "arn:aws:s3:::pii", model.High, "PUBLIC_DATA_STORE")
	apply := func(scan string, at time.Time) {
		if _, err := st.ApplyScan(scan, []model.Finding{f}, at, ApplyOptions{Scopes: ScopesOf([]model.Finding{f})}); err != nil {
			t.Fatal(err)
		}
		if err := st.RebuildIssues(at); err != nil {
			t.Fatal(err)
		}
	}
	apply("s1", t0)
	id := singleIssueID(t, st)
	verifyFixed(t, st, id, t0.Add(time.Hour))
	// C2: the problem is still (or again) observed — the Issue must not stay hidden.
	apply("s2", t0.Add(2*time.Hour))
	is := issueByID(t, st, id)
	if is.State != model.StateReopened || !is.RegressedAfterVerify {
		t.Fatalf("state %s regressed %v, want reopened + regressed_after_verify", is.State, is.RegressedAfterVerify)
	}
	h, err := st.PathIssueHistory(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) == 0 || h[len(h)-1].State != model.StateReopened || !h[len(h)-1].RegressedAfterVerify {
		t.Fatalf("history %+v: want a last reopened row flagged regressed_after_verify", h)
	}
	m, err := st.ClosureMetrics()
	if err != nil {
		t.Fatal(err)
	}
	if m.RegressionsAfterVerify != 1 {
		t.Errorf("regressions after verify = %d, want 1", m.RegressionsAfterVerify)
	}
	// Open again: counted as open, so it reaches overdue, digest and reopen workflows.
	if c, _ := st.IssueCounts(); c.Open != 1 {
		t.Errorf("open = %d, want 1", c.Open)
	}
}

func TestVerifiedFixedPathIssueDurability(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	present := &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 10)}}
	if _, err := st.RebuildPathIssues("s1", present, t0); err != nil {
		t.Fatal(err)
	}
	id := onlyPathIssue(t, st).ID
	verifyFixed(t, st, id, t0.Add(time.Hour))
	res, err := st.RebuildPathIssues("s2", &attackpath.Analysis{}, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if is := onlyPathIssue(t, st); is.State != model.StateVerifiedFixed || len(res.ResolvedIDs) != 0 {
		t.Fatalf("absent: state %s resolved %v, want verified_fixed kept", is.State, res.ResolvedIDs)
	}
	// The same path at 10.0 returns: reopened, flagged, never hidden.
	res, err = st.RebuildPathIssues("s3", present, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	is := onlyPathIssue(t, st)
	if is.State != model.StateReopened || !is.RegressedAfterVerify || res.Reopened != 1 || len(res.RegressedIDs) != 1 {
		t.Fatalf("present: state %s regressed %v reopened %d regressed ids %v", is.State, is.RegressedAfterVerify, res.Reopened, res.RegressedIDs)
	}
	h, _ := st.PathIssueHistory(id)
	if last := h[len(h)-1]; last.State != model.StateReopened || !last.RegressedAfterVerify {
		t.Fatalf("history last %+v", last)
	}
	// Verified-but-present directly (no absent scan in between) also reopens.
	verifyFixed(t, st, id, t0.Add(4*time.Hour))
	if _, err := st.RebuildPathIssues("s4", present, t0.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if is := onlyPathIssue(t, st); is.State != model.StateReopened {
		t.Fatalf("verified then present: %s, want reopened", is.State)
	}
}

func TestPlainAbsenceResolvesOnlyUnverifiedIssues(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a := syntheticPath("sg-1", 9.5)
	b := syntheticPath("sg-2", 7.0)
	b.Steps[2].Resource = "role/batch"
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{a, b}}, t0); err != nil {
		t.Fatal(err)
	}
	ids := pathIssueIDs(t, st)
	verifyFixed(t, st, ids[0], t0.Add(time.Hour))
	if _, err := st.RebuildPathIssues("s2", &attackpath.Analysis{}, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := issueByID(t, st, ids[0]).State; s != model.StateVerifiedFixed {
		t.Errorf("verified Issue: %s", s)
	}
	if s := issueByID(t, st, ids[1]).State; s != model.StateResolved {
		t.Errorf("unverified Issue: %s, want resolved", s)
	}
}

func TestPendingVerificationSettledByScanOrVerify(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	present := &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 9.5)}}
	if _, err := st.RebuildPathIssues("s1", present, t0); err != nil {
		t.Fatal(err)
	}
	id := onlyPathIssue(t, st).ID
	if err := st.MarkPendingVerification(id, "pr:https://github.com/acme/infra/pull/7", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	is := onlyPathIssue(t, st)
	if is.State != model.StatePendingVerification || is.PendingBy == "" || is.PendingAt == nil || is.Overdue {
		t.Fatalf("pending: %+v", is)
	}
	if c, _ := st.IssueCounts(); c.Paths.Pending != 1 || c.Paths.Open != 0 {
		t.Errorf("pending counts %+v", c.Paths)
	}
	// Marking a closed Issue pending is refused.
	if _, err := st.RebuildPathIssues("s2", present, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Next scan still sees it: the fix did not take — back to open (not hidden).
	if s := onlyPathIssue(t, st).State; !model.IsActive(s) {
		t.Fatalf("pending + present: %s, want active", s)
	}
	// Pending again, next scan does not see it: resolved (not verified — only verify verifies).
	if err := st.MarkPendingVerification(id, "cli", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RebuildPathIssues("s3", &attackpath.Analysis{}, t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := onlyPathIssue(t, st).State; s != model.StateResolved {
		t.Fatalf("pending + absent: %s, want resolved", s)
	}
	if err := st.MarkPendingVerification(id, "cli", t0.Add(4*time.Hour)); err == nil {
		t.Errorf("marking a resolved Issue pending must fail")
	}
	// verify settles a pending Issue too.
	if _, err := st.RebuildPathIssues("s4", present, t0.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPendingVerification(id, "cli", t0.Add(6*time.Hour)); err != nil {
		t.Fatal(err)
	}
	verifyFixed(t, st, id, t0.Add(7*time.Hour))
	if s := onlyPathIssue(t, st).State; s != model.StateVerifiedFixed {
		t.Fatalf("pending + verify: %s", s)
	}
	m, _ := st.ClosureMetrics()
	if m.VerifiedFixed != 1 {
		t.Errorf("closure metrics %+v", m)
	}
}

// Verification 5 C8: verifying a suppressed Issue keeps the suppression.
func TestVerificationKeepsSuppression(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 9.5)}}, t0); err != nil {
		t.Fatal(err)
	}
	id := onlyPathIssue(t, st).ID
	if err := st.SuppressIssue(id, Suppression{Reason: "WAF", ExpiresAt: t0.Add(30 * 24 * time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{VerifyFixed, VerifyReopened} {
		if err := st.RecordVerification(Verification{IssueID: id, Result: r, At: t0.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if is := onlyPathIssue(t, st); is.State != model.StateSuppressed || is.Reason != "WAF" {
			t.Fatalf("%s on suppressed: %s %q", r, is.State, is.Reason)
		}
	}
}
