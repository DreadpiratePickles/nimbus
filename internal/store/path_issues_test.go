package store

import (
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
)

// labAnalysis parses the lab estate (lab/local/out/estate.findings.json) and traverses it with
// the lab's trusted CIDRs, each call from scratch (a second "ingest").
func labAnalysis(t *testing.T) *attackpath.Analysis {
	t.Helper()
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	g.AttachFindings(fs)
	o := attackpath.DefaultTraversalOptions()
	o.TrustedCIDRs = []string{"203.0.113.0/24"} // lab/local/cloud-posture.lab.yaml
	return attackpath.Traverse(g, o)
}

func pathIssueIDs(t *testing.T, st *Store) []string {
	t.Helper()
	is, err := st.Issues(IssueFilter{Kind: model.IssuePath})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, i := range is {
		ids = append(ids, i.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestPathIssueIDStableAcrossIngests(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a1 := labAnalysis(t)
	if len(a1.Paths) == 0 {
		t.Fatal("lab produced no complete paths")
	}
	st := openTemp(t)
	if _, err := st.RebuildPathIssues("s1", a1, t0); err != nil {
		t.Fatal(err)
	}
	first := pathIssueIDs(t, st)
	if len(first) == 0 {
		t.Fatal("no path Issues written")
	}
	res, err := st.RebuildPathIssues("s2", labAnalysis(t), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	second := pathIssueIDs(t, st)
	if !equalStrings(first, second) {
		t.Fatalf("path Issue ids changed across ingests:\n %v\n %v", first, second)
	}
	if res.Opened != 0 || res.Reopened != 0 || res.Resolved != 0 {
		t.Errorf("second identical ingest churned: %+v", res)
	}
	// A different database fed the same estate derives the same Issues under its own key
	// (MCP-1: ids are HMAC-keyed per database, so they differ across databases).
	other := openTemp(t)
	if _, err := other.RebuildPathIssues("x", labAnalysis(t), t0); err != nil {
		t.Fatal(err)
	}
	if got := pathIssueIDs(t, other); len(got) != len(first) || equalStrings(first, got) {
		t.Fatalf("ids across databases: want the same count under different keys:\n %v\n %v", first, got)
	}
	// Every Issue carries the path fields and its id is PathIssueID(kind|entry|anchor|rule).
	is, _ := st.Issues(IssueFilter{Kind: model.IssuePath})
	for _, i := range is {
		if i.ID != st.KeyID(model.PathIssueID(model.IssuePath, i.EntryID, i.AnchorID, i.RuleID)) {
			t.Errorf("%s: id is not KeyID(PathIssueID(%s, %s, %s))", i.ID, i.EntryID, i.AnchorID, i.RuleID)
		}
		if i.SecondaryKey == "" || i.Score <= 0 || i.Band == "" || !i.ConfidenceLabel.Valid() || i.Validation == nil ||
			i.Validation.Status != model.ValidationTheoretical || !i.FirstSeen.Equal(t0) || i.State != model.StateOpen {
			t.Errorf("path Issue fields: %+v", i)
		}
	}
	// Issue score = max over its paths; at least one lab path carries a toxic combination.
	best := map[string]float64{}
	toxic := 0
	for _, p := range a1.Paths {
		id := st.PathIssueIDOf(p)
		if p.Score > best[id] {
			best[id] = p.Score
		}
	}
	for _, i := range is {
		if i.Score != best[i.ID] {
			t.Errorf("%s score %.2f, want max over paths %.2f", i.ID, i.Score, best[i.ID])
		}
		if i.ToxicCombination != "" {
			toxic++
		}
	}
	if toxic == 0 {
		t.Error("no path Issue carries toxic_combination")
	}
}

func syntheticPath(middle string, score float64) model.AttackPath {
	return model.AttackPath{ID: "p-" + middle, RuleID: "GRAPH_TRAVERSAL", Name: "internet → role/web", Provider: "aws", Account: "111",
		Score: score, Severity: model.Critical, FindingIDs: []string{"f-" + middle}, Steps: []model.Step{
			{Stage: 1, Relation: "exposes", Resource: middle, Evidence: map[string]any{"edge": "exposes", "confidence": "verified"}},
			{Stage: 2, Relation: "allows_traffic_to", Resource: "i-web", Evidence: map[string]any{"edge": "allows_traffic_to"}},
			{Stage: 3, Relation: "runs_as", Resource: "role/web", Evidence: map[string]any{"edge": "runs_as", "toxic_combination": "exposed+admin"}},
		}}
}

func onlyPathIssue(t *testing.T, st *Store) model.Issue {
	t.Helper()
	is, err := st.Issues(IssueFilter{Kind: model.IssuePath})
	if err != nil || len(is) != 1 {
		t.Fatalf("path Issues: %d %v, want 1", len(is), err)
	}
	return is[0]
}

func TestPathIssueIDIgnoresPlumbingHop(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 7.6)}}, t0); err != nil {
		t.Fatal(err)
	}
	a := onlyPathIssue(t, st)
	res, err := st.RebuildPathIssues("s2", &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-2", 7.6)}}, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b := onlyPathIssue(t, st)
	if a.ID != b.ID {
		t.Fatalf("plumbing hop changed the Issue id: %s -> %s", a.ID, b.ID)
	}
	if a.SecondaryKey == b.SecondaryKey || b.SecondaryKey != st.PathSecondaryKeyOf(syntheticPath("sg-2", 7.6)) {
		t.Fatalf("secondary key %s -> %s, want the new hop list's key", a.SecondaryKey, b.SecondaryKey)
	}
	if b.State != model.StateOpen || !b.FirstSeen.Equal(t0) || res.Opened+res.Reopened+res.Resolved != 0 {
		t.Errorf("hop change churned the Issue: %+v %+v", b, res)
	}
	h, err := st.PathIssueHistory(a.ID)
	if err != nil || len(h) != 2 || h[1].SecondaryKey != b.SecondaryKey || h[1].ScanID != "s2" {
		t.Errorf("history should record the secondary key change: %+v %v", h, err)
	}
}

func TestPathIssueLifecycleKeepsFirstSeen(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p := syntheticPath("sg-1", 7.6)
	inc := syntheticPath("sg-9", 9)
	inc.Steps = inc.Steps[:2] // a prefix: never an Issue
	an := &attackpath.Analysis{Paths: []model.AttackPath{p}, Incomplete: []model.AttackPath{inc}}
	if _, err := st.RebuildPathIssues("s1", an, t0); err != nil {
		t.Fatal(err)
	}
	id := onlyPathIssue(t, st).ID
	// the fix: the path is gone -> resolved
	res, err := st.RebuildPathIssues("s2", &attackpath.Analysis{}, t0.Add(time.Hour))
	if err != nil || res.Resolved != 1 {
		t.Fatalf("resolve: %+v %v", res, err)
	}
	if is := onlyPathIssue(t, st); is.State != model.StateResolved || is.ResolvedAt == nil {
		t.Fatalf("after fix: %+v", is)
	}
	// restore -> reopened, first_seen kept
	res, err = st.RebuildPathIssues("s3", an, t0.Add(2*time.Hour))
	if err != nil || res.Reopened != 1 {
		t.Fatalf("reopen: %+v %v", res, err)
	}
	is := onlyPathIssue(t, st)
	if is.ID != id || is.State != model.StateReopened || !is.FirstSeen.Equal(t0) || is.ResolvedAt != nil || !is.LastSeen.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("after restore: %+v", is)
	}
	h, _ := st.PathIssueHistory(id)
	var states []string
	for _, e := range h {
		states = append(states, e.State)
	}
	if !equalStrings(states, []string{"open", "resolved", "reopened"}) {
		t.Errorf("history states %v", states)
	}
	// Rebuilding finding Issues must not touch path Issues.
	if err := st.RebuildIssues(t0.Add(3 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if is := onlyPathIssue(t, st); is.State != model.StateReopened {
		t.Errorf("RebuildIssues changed a path Issue to %s", is.State)
	}
}

func TestPathIssueAggregatesPaths(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	weak := syntheticPath("sg-1", 5)
	weak.WeakLink = true
	strong := syntheticPath("i-direct", 7.6)
	strong.Steps = []model.Step{strong.Steps[0], strong.Steps[2]}
	strong.Steps[0].Resource = "i-web"
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{weak, strong}}, t0); err != nil {
		t.Fatal(err)
	}
	is := onlyPathIssue(t, st)
	if is.Score != 7.6 || is.Band != "High" || is.WeakLink || is.ToxicCombination != "exposed+admin" || len(is.SecondaryKeys) != 2 ||
		is.SecondaryKey != st.PathSecondaryKeyOf(strong) || is.Kind != model.IssuePath || is.ResourceID != "role/web" || is.EntryID != "internet" {
		t.Fatalf("aggregate: %+v", is)
	}
}

func TestSuppressedRequiresReasonAndExpiry(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	an := &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 7.6)}}
	if _, err := st.RebuildPathIssues("s1", an, t0); err != nil {
		t.Fatal(err)
	}
	id := onlyPathIssue(t, st).ID
	var se *SuppressionError
	for _, bad := range []Suppression{{ExpiresAt: t0.Add(24 * time.Hour)}, {Reason: "accepted"}, {Reason: "past", ExpiresAt: t0.Add(-time.Hour)}} {
		if err := st.SuppressIssue(id, bad, t0); !errors.As(err, &se) {
			t.Errorf("SuppressIssue(%+v) = %v, want *SuppressionError", bad, err)
		}
	}
	if err := st.SuppressIssue("nope", Suppression{Reason: "r", ExpiresAt: t0.Add(time.Hour)}, t0); !errors.Is(err, ErrIssueNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	until := t0.Add(24 * time.Hour)
	if err := st.SuppressIssue(id, Suppression{Reason: "compensating WAF rule", ExpiresAt: until, ApprovedBy: "owner@example.com"}, t0); err != nil {
		t.Fatal(err)
	}
	is := onlyPathIssue(t, st)
	if is.State != model.StateSuppressed || is.Reason != "compensating WAF rule" || is.ExpiresAt == nil || !is.ExpiresAt.Equal(until) || is.ApprovedBy != "owner@example.com" {
		t.Fatalf("suppressed: %+v", is)
	}
	if open, _ := st.Issues(IssueFilter{OpenOnly: true}); len(open) != 0 {
		t.Errorf("suppressed Issue listed as open")
	}
	// before expiry the path is still there -> stays suppressed
	if _, err := st.RebuildPathIssues("s2", an, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := onlyPathIssue(t, st).State; s != model.StateSuppressed {
		t.Fatalf("before expiry: %s", s)
	}
	c, _ := st.IssueCounts()
	if c.Paths.Suppressed != 1 || c.Paths.Open != 0 {
		t.Errorf("counts while suppressed: %+v", c.Paths)
	}
	// after expiry -> reopened automatically
	res, err := st.RebuildPathIssues("s3", an, until.Add(time.Minute))
	if err != nil || res.Reopened != 1 {
		t.Fatalf("expiry: %+v %v", res, err)
	}
	if is := onlyPathIssue(t, st); is.State != model.StateReopened || !is.FirstSeen.Equal(t0) {
		t.Fatalf("after expiry: %+v", is)
	}
}

func TestIssueCountsIncludePathIssues(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{mkFinding("prowler", "c", "S3_PUBLIC_BUCKET", "arn:aws:s3:::b", model.High, "PUBLIC_DATA_STORE")}
	if _, err := st.ApplyScan("s1", fs, now, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(now); err != nil {
		t.Fatal(err)
	}
	p2 := syntheticPath("sg-1", 9.5)
	p2.Steps[2].Resource = "role/other"
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{syntheticPath("sg-1", 7.6), p2}}, now); err != nil {
		t.Fatal(err)
	}
	c, err := st.IssueCounts()
	if err != nil {
		t.Fatal(err)
	}
	// Finding-derived headers are unchanged; path Issues are counted under their own key.
	if c.Total != 1 || c.Open != 1 || c.BySeverity["HIGH"] != 1 {
		t.Errorf("finding Issue counts changed by path Issues: %+v", c)
	}
	if c.Paths.Total != 2 || c.Paths.Open != 2 || c.Paths.ByBand["Critical"] != 1 || c.Paths.ByBand["High"] != 1 ||
		c.Paths.BySeverity["CRITICAL"] != 1 || c.Paths.BySeverity["HIGH"] != 1 { // integration pass 2: path severity = band
		t.Errorf("path counts: %+v", c.Paths)
	}
	if _, err := st.EnsureViews(); err != nil {
		t.Fatal(err)
	}
	var n int
	var maxScore float64
	if err := st.DB().QueryRow("SELECT SUM(count), MAX(max_score) FROM issues_summary WHERE kind = 'path'").Scan(&n, &maxScore); err != nil || n != 2 || maxScore != 9.5 {
		t.Errorf("issues_summary path rows: n=%d max=%v err=%v", n, maxScore, err)
	}
}

func TestRebuildPathIssuesRejectsNilAnalysis(t *testing.T) {
	st := openTemp(t)
	if _, err := st.RebuildPathIssues("s", nil, time.Now()); err == nil {
		t.Fatal("nil analysis must be an error, not 'every path resolved'")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Suppression applies to finding-derived Issues too, and RebuildIssues honours its expiry.
func TestSuppressedSingleIssueSurvivesRebuildAndExpires(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs := []model.Finding{mkFinding("prowler", "c", "S3_PUBLIC_BUCKET", "arn:aws:s3:::b", model.High, "PUBLIC_DATA_STORE")}
	if _, err := st.ApplyScan("s1", fs, now, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(now); err != nil {
		t.Fatal(err)
	}
	is, _ := st.Issues(IssueFilter{Kind: model.IssueSingle})
	if len(is) != 1 {
		t.Fatalf("single issues: %d", len(is))
	}
	until := now.Add(48 * time.Hour)
	if err := st.SuppressIssue(is[0].ID, Suppression{Reason: "public website bucket", ExpiresAt: until}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(now.Add(time.Hour)); err != nil {
		t.Fatalf("rebuild with a suppressed Issue: %v", err)
	}
	is, _ = st.Issues(IssueFilter{Kind: model.IssueSingle})
	if is[0].State != model.StateSuppressed {
		t.Fatalf("before expiry: %s", is[0].State)
	}
	if c, _ := st.IssueCounts(); c.Suppressed != 1 || c.Open != 0 || c.Resolved != 0 {
		t.Errorf("counts: %+v", c)
	}
	if err := st.RebuildIssues(until.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	is, _ = st.Issues(IssueFilter{Kind: model.IssueSingle})
	if is[0].State != model.StateReopened || !is[0].FirstSeen.Equal(now) {
		t.Fatalf("after expiry: %+v", is[0])
	}
}

func TestScoreBandMatchesRiskBands(t *testing.T) {
	for s := 0.0; s <= 10.0; s += 0.05 {
		if model.ScoreBand(s) != risk.BandFor(s) {
			t.Fatalf("ScoreBand(%v)=%s, risk.BandFor=%s", s, model.ScoreBand(s), risk.BandFor(s))
		}
	}
}
