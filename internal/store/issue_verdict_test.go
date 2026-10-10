package store

import (
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func issueSeverities(t *testing.T, st *Store, kind string) map[string]model.Severity {
	t.Helper()
	is, err := st.Issues(IssueFilter{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.Severity{}
	for _, i := range is {
		out[i.ResourceID] = i.Severity
	}
	return out
}

// Integration pass 2 item 2: an Issue's severity is the verdict, not the scanner's label.
// The finding's risk band may lower it (benign context), a complete attack path through the
// resource raises it to the path band, and an exposure-only context never raises it above
// the scanner severity. Without a verdict the scanner severity stands.
func TestIssueSeverityFromVerdict(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	benign := mkFinding("prowler", "c1", "S3_PUBLIC_BUCKET", "benign", model.Critical, "PUBLIC_DATA_STORE")
	onPath := mkFinding("prowler", "c2", "S3_NO_LOGGING", "onpath", model.Low)
	exposed := mkFinding("prowler", "c3", "EC2_SG_OPEN_SSH", "exposed", model.High, "PUBLIC_NETWORK_EXPOSURE")
	unscored := mkFinding("prowler", "c4", "S3_UNENCRYPTED", "unscored", model.High)
	fs := []model.Finding{benign, onPath, exposed, unscored}
	if _, err := st.ApplyScan("s1", fs, now, ApplyOptions{Scopes: ScopesOf(fs)}); err != nil {
		t.Fatal(err)
	}
	if err := st.RebuildIssues(now); err != nil {
		t.Fatal(err)
	}
	if got := issueSeverities(t, st, model.IssueSingle); got["benign"] != model.Critical || got["unscored"] != model.High {
		t.Fatalf("without a verdict the scanner severity must stand: %v", got)
	}
	v := &IssueVerdict{
		FindingBand: map[string]string{benign.ID: "Medium", onPath.ID: "Low", exposed.ID: "Critical"},
		PathBand:    map[string]string{"onpath": "High"},
	}
	if err := st.RebuildIssuesWithVerdict(now.Add(time.Hour), v); err != nil {
		t.Fatal(err)
	}
	got := issueSeverities(t, st, model.IssueSingle)
	want := map[string]model.Severity{
		"benign":   model.Medium, // risk band lowers a benign CRITICAL
		"onpath":   model.High,   // the path band raises a LOW on a High path
		"exposed":  model.High,   // exposure context alone never raises above the scanner
		"unscored": model.High,   // no band: scanner severity
	}
	for r, w := range want {
		if got[r] != w {
			t.Errorf("%s: severity %s, want %s", r, got[r], w)
		}
	}
	c, err := st.IssueCounts()
	if err != nil {
		t.Fatal(err)
	}
	if c.BySeverity["CRITICAL"] != 0 || c.BySeverity["HIGH"] != 3 || c.BySeverity["MEDIUM"] != 1 {
		t.Errorf("counts follow the verdict: %v", c.BySeverity)
	}
}

// Path Issue severity is its band, not the path's own severity label.
func TestPathIssueSeverityIsBand(t *testing.T) {
	st := openTemp(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	p := syntheticPath("sg-1", 5.2) // Severity CRITICAL, score Medium
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{p}}, now); err != nil {
		t.Fatal(err)
	}
	if is := onlyPathIssue(t, st); is.Severity != model.Medium || is.Band != "Medium" {
		t.Fatalf("path Issue severity %s band %s, want MEDIUM / Medium", is.Severity, is.Band)
	}
}

func scopedPath(id, entryAcct, anchorAcct string, score float64) model.AttackPath {
	return model.AttackPath{ID: id, RuleID: "GRAPH_TRAVERSAL", Name: id, Provider: "aws", Account: entryAcct, Score: score, Severity: model.High,
		Steps: []model.Step{
			{Stage: 1, Relation: "exposes", Resource: "i-" + id + "-" + entryAcct},
			{Stage: 2, Relation: "runs_as", Resource: "role/" + id + "-" + anchorAcct},
		}}
}

// Integration pass 2 item 8: a partial-scope scan (scan --accounts A) rebuilds path Issues only
// for paths wholly inside the scanned accounts and never resolves Issues outside them.
func TestRebuildPathIssuesScoped(t *testing.T) {
	st := openTemp(t)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	inA := scopedPath("a", "111", "111", 7.5)
	inB := scopedPath("b", "222", "222", 7.5)
	cross := scopedPath("x", "111", "222", 7.5)
	if _, err := st.RebuildPathIssues("s1", &attackpath.Analysis{Paths: []model.AttackPath{inA, inB, cross}}, t0); err != nil {
		t.Fatal(err)
	}
	newA := scopedPath("a2", "111", "111", 9.1)
	nodeAcct := func(id string) (string, bool) {
		for _, p := range []model.AttackPath{inA, inB, cross, newA} {
			for _, s := range p.Steps {
				if s.Resource == id {
					return "aws/" + id[len(id)-3:], true
				}
			}
		}
		return "", false
	}
	scope := &PathScope{Accounts: map[string]bool{"aws/111": true}, NodeAccount: nodeAcct}
	// Account 111 rescanned: path "a" is gone. A partial analysis would also drop b and x.
	res, err := st.RebuildPathIssuesScoped("s2", &attackpath.Analysis{Paths: []model.AttackPath{newA, cross}}, t0.Add(time.Hour), scope)
	if err != nil {
		t.Fatal(err)
	}
	is, _ := st.Issues(IssueFilter{Kind: model.IssuePath})
	state := map[string]string{}
	for _, i := range is {
		state[i.AnchorID] = i.State
	}
	if state["role/a-111"] != model.StateResolved {
		t.Errorf("in-scope path Issue absent from the rescan must resolve: %v", state)
	}
	if state["role/b-222"] != model.StateOpen {
		t.Errorf("out-of-scope path Issue must not resolve: %v", state)
	}
	if state["role/x-222"] != model.StateOpen {
		t.Errorf("cross-scope path Issue must be left alone: %v", state)
	}
	if state["role/a2-111"] != model.StateOpen {
		t.Errorf("new in-scope path must open: %v", state)
	}
	if res.Opened != 1 || res.Resolved != 1 || res.OutOfScope != 1 {
		t.Errorf("result %+v, want opened 1, resolved 1, out_of_scope 1", res)
	}
	// nil scope = whole estate (RebuildPathIssues).
	if _, err := st.RebuildPathIssuesScoped("s3", &attackpath.Analysis{}, t0.Add(2*time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	if n := countOpenPaths(t, st); n != 0 {
		t.Errorf("whole-estate empty analysis resolves everything; %d open", n)
	}
}

func countOpenPaths(t *testing.T, st *Store) int {
	is, _ := st.Issues(IssueFilter{Kind: model.IssuePath, OpenOnly: true})
	return len(is)
}
