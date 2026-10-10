package attackpath_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/adapters"
	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/pathdiff"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Shortfall #1 (competitive delta 2026-10-09): one risk, one severity. For every lab path the
// `paths` JSON, Analysis, Analysis.Grouped(), the pathdiff PathRef and the stored path Issue
// all carry the band of the same score (model.ScoreBand), so "[CRITICAL 5.2]" next to
// "HIGH band High" cannot happen.
func TestPathSeverityConsistent(t *testing.T) {
	fs, _, err := adapters.ParseFile(filepath.Join("..", "..", "lab", "local", "out", "estate.findings.json"), "native", adapters.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	g.AttachFindings(fs)
	o := attackpath.DefaultTraversalOptions()
	o.TrustedCIDRs = []string{"203.0.113.0/24"}
	an := attackpath.Traverse(g, o)
	rules, _ := attackpath.LoadRules(nil)
	an.Paths = attackpath.Merge(an.Paths, attackpath.EvaluateWith(fs, rules, attackpath.EvalOptions{TrustedCIDRs: o.TrustedCIDRs, Graph: g}))
	if len(an.Paths) < 10 {
		t.Fatalf("lab produced %d paths", len(an.Paths))
	}
	sev := func(score float64) model.Severity { return store.BandSeverity(model.ScoreBand(score)) }

	// paths JSON
	b, _ := json.Marshal(an.Paths)
	var js []struct {
		ID       string  `json:"id"`
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	}
	if err := json.Unmarshal(b, &js); err != nil {
		t.Fatal(err)
	}
	for _, p := range js {
		if model.Severity(p.Severity) != sev(p.Score) {
			t.Errorf("paths JSON %s: %s at %.2f, band %s", p.ID, p.Severity, p.Score, model.ScoreBand(p.Score))
		}
	}
	// Analysis + Grouped
	groups := map[string]attackpath.PathGroup{}
	for _, gr := range an.Grouped() {
		groups[gr.IssueID] = gr
		if gr.Severity != sev(gr.Score) || gr.Band != model.ScoreBand(gr.Score) || gr.Best.Severity != gr.Severity {
			t.Errorf("group %s: severity %s band %s score %.2f", gr.IssueID, gr.Severity, gr.Band, gr.Score)
		}
	}
	// stored path Issues (internal/store RebuildPathIssues)
	st, err := store.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.RebuildPathIssues("s1", an, time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	iss, err := st.Issues(store.IssueFilter{Kind: model.IssuePath})
	if err != nil {
		t.Fatal(err)
	}
	if len(iss) != len(groups) {
		t.Errorf("%d stored path Issues, %d groups", len(iss), len(groups))
	}
	for _, is := range iss {
		gr, ok := groups[is.ID]
		if !ok { // stored ids are HMAC-keyed per database (store/idkey.go, MCP-1)
			gr, ok = groups[model.PathIssueID(model.IssuePath, is.EntryID, is.AnchorID, is.RuleID)]
		}
		if !ok {
			t.Errorf("path Issue %s has no group", is.ID)
			continue
		}
		if is.Band != gr.Band || is.Severity != gr.Severity {
			t.Errorf("Issue %s: %s/%s, group %s/%s", is.ID, is.Severity, is.Band, gr.Severity, gr.Band)
		}
	}
	// pathdiff: a plan-only diff of an empty plan against the lab graph changes nothing, so every
	// path Issue appears unchanged; open the F01 SG to check an Opened ref.
	plan, err := iac.ParsePlanJSON([]byte(`{"format_version":"1.2","resource_changes":[{"address":"aws_security_group.corp_ssh","mode":"managed","type":"aws_security_group","name":"corp_ssh",
	 "change":{"actions":["update"],"before":{"ingress":[{"cidr_blocks":["203.0.113.0/24"],"from_port":22,"to_port":22,"protocol":"tcp"}],"id":"sg-0a1b2c3d4e5f60002","arn":"arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60002","name":"nimbus-lab-corp-ssh"},
	 "after":{"ingress":[{"cidr_blocks":["0.0.0.0/0"],"from_port":22,"to_port":22,"protocol":"tcp"}],"id":"sg-0a1b2c3d4e5f60002","arn":"arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60002","name":"nimbus-lab-corp-ssh"}}}]}`), iac.PlanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	res := pathdiff.Diff(g, nil, plan, pathdiff.Options{Traversal: o})
	refs := append(append([]pathdiff.PathRef{}, res.Opened...), res.Closed...)
	for _, c := range res.ChangedScore {
		refs = append(refs, c.Path)
	}
	if len(refs) == 0 {
		t.Fatal("pathdiff produced no path refs to check")
	}
	for _, r := range refs {
		if r.Band != model.ScoreBand(r.Score) || r.Severity != sev(r.Score) {
			t.Errorf("pathdiff %s: severity %s band %s score %.2f", r.IssueID, r.Severity, r.Band, r.Score)
		}
	}
}
