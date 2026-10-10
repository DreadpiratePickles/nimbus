package governance

// Item 16 (verify-4 D3): a single/combination Issue reopened by suppression expiry gets a fresh
// SLA clock, like a path Issue. The store records the suppress / reopen transitions of every
// Issue kind in path_issue_history; CollectEvents must read them for single Issues too, not
// only their evidence findings' history. The test is the verifier's repro, verbatim.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func v4finding(scan string, now time.Time) model.Finding {
	f := model.Finding{Source: "prowler", CheckID: "c", CanonicalID: "S3_PUBLIC_BUCKET", Title: "public", Severity: model.High, Status: model.Fail,
		Provider: "aws", Account: "123", Region: "us-east-1", ScanID: scan,
		Resource: model.Resource{ID: "arn:aws:s3:::b", Type: "aws_s3_bucket", Name: "b"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}}
	f.Finalize(now)
	return f
}

func TestV4SuppressionExpiryClockSingleVsPath(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := v4finding("s1", t0)
	st.ApplyScan("s1", []model.Finding{f}, t0, store.ApplyOptions{Scopes: store.ScopesOf([]model.Finding{f})})
	st.RebuildIssues(t0)
	p := model.AttackPath{ID: "p-sg", RuleID: "GRAPH_TRAVERSAL", Name: "internet → role/web", Provider: "aws", Account: "111",
		Score: 7.6, Severity: model.Critical, FindingIDs: []string{"f-sg"}, Steps: []model.Step{
			{Stage: 1, Relation: "exposes", Resource: "sg-1", Evidence: map[string]any{"edge": "exposes", "confidence": "verified"}},
			{Stage: 2, Relation: "allows_traffic_to", Resource: "i-web", Evidence: map[string]any{"edge": "allows_traffic_to"}},
			{Stage: 3, Relation: "runs_as", Resource: "role/web", Evidence: map[string]any{"edge": "runs_as", "toxic_combination": "exposed+admin"}},
		}}
	an := &attackpath.Analysis{Paths: []model.AttackPath{p}}
	if _, err := st.RebuildPathIssues("s1", an, t0); err != nil {
		t.Fatal(err)
	}
	all, _ := st.Issues(store.IssueFilter{})
	ts := t0.Add(24 * time.Hour)
	until := t0.Add(30 * 24 * time.Hour)
	for _, is := range all {
		if err := st.SuppressIssue(is.ID, store.Suppression{Reason: "accepted", ExpiresAt: until}, ts); err != nil {
			t.Fatal(err)
		}
	}
	after := until.Add(time.Hour)
	st.RebuildIssues(after)
	st.RebuildPathIssues("s2", an, after)
	all, _ = st.Issues(store.IssueFilter{})
	evs, _ := CollectEvents(st, nil)
	for _, is := range all {
		start := CurrentEpisodeStart(evs, is.ID)
		t.Logf("%s kind=%s state=%s episode start=%v", is.ID, is.Kind, is.State, start)
		if is.State == model.StateReopened && !start.Equal(after) {
			t.Errorf("%s (%s) is reopened after suppression expiry but its SLA clock starts at %v, not the reopen %v (docs: a reopened Issue gets a fresh clock)", is.ID, is.Kind, start, after)
		}
	}
}
