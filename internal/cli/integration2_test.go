package cli

// Integration pass 2: path Issues, Issue severity verdict, exposures, gate semantics and
// partial-scope path Issues wired through the CLI.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func labFile(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "lab", "local", "out", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pathIssues(t *testing.T) []model.Issue {
	t.Helper()
	st, err := store.Open(flagDB)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	is, err := st.Issues(store.IssueFilter{Kind: model.IssuePath})
	if err != nil {
		t.Fatal(err)
	}
	return is
}

// Item 1: scan writes path Issues, --diff prints their transitions, and the `issues`
// command lists, filters, shows, suppresses and prints the history of them.
func TestPathIssuesWiredAndIssuesCommand(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	out := run(t, "scan", "--from-dir", labFile(t, "estate.findings.json"), "-o", "summary", "--diff")
	is := pathIssues(t)
	if len(is) == 0 {
		t.Fatalf("scan wrote no path Issues:\n%s", out)
	}
	if !strings.Contains(out, "Path Issues:") || !strings.Contains(out, "opened") {
		t.Fatalf("--diff lacks the path Issue transitions:\n%s", out)
	}
	id := is[0].ID
	if !strings.Contains(out, id) {
		t.Errorf("--diff does not name opened path Issue %s:\n%s", id, out)
	}

	out = run(t, "issues", "--kind", "path")
	if !strings.Contains(out, id) {
		t.Fatalf("issues --kind path does not list %s:\n%s", id, out)
	}
	var listed []model.Issue
	if err := json.Unmarshal([]byte(run(t, "issues", "--kind", "path", "--band", is[0].Band, "--json")), &listed); err != nil || len(listed) == 0 {
		t.Fatalf("issues --band --json: %v %d", err, len(listed))
	}
	for _, l := range listed {
		if l.Band != is[0].Band || l.Kind != model.IssuePath {
			t.Errorf("filter leaked %s/%s", l.Kind, l.Band)
		}
	}
	out = run(t, "issues", "show", id)
	if !strings.Contains(out, id) || !strings.Contains(out, "band") {
		t.Errorf("issues show: %s", out)
	}
	if _, err := runErr(t, "issues", "suppress", id, "--expires", "2099-01-01"); err == nil {
		t.Errorf("suppress without --reason must fail")
	}
	run(t, "issues", "suppress", id, "--reason", "accepted: lab", "--expires", suppressUntil, "--approved-by", "bobby")
	var sup []model.Issue
	json.Unmarshal([]byte(run(t, "issues", "--kind", "path", "--state", "suppressed", "--json")), &sup)
	if len(sup) != 1 || sup[0].ID != id || sup[0].Reason != "accepted: lab" || sup[0].ApprovedBy != "bobby" {
		t.Fatalf("suppressed listing: %+v", sup)
	}
	out = run(t, "issues", "history", id)
	if !strings.Contains(out, "suppressed") || !strings.Contains(out, "open") {
		t.Errorf("issues history: %s", out)
	}

	// prioritize re-derives Issues from the full stored analysis too.
	st, _ := store.Open(flagDB)
	st.DB().Exec("DELETE FROM issues WHERE kind = 'path' AND state <> 'suppressed'")
	st.Close()
	run(t, "prioritize", "--top", "1")
	if got := pathIssues(t); len(got) != len(is) {
		t.Errorf("prioritize did not rebuild path Issues: %d, want %d", len(got), len(is))
	}
}

// pathCollector builds, per account, internet → instance (IMDSv1) → admin role: a complete
// path that exists only in the collector graph (no finding carries it).
type pathCollector struct{}

func (pathCollector) Name() string     { return "path-aws" }
func (pathCollector) Provider() string { return "aws" }
func (pathCollector) Collect(ctx context.Context, spec collector.AccountSpec, g *graph.Graph) (collector.Result, error) {
	acct := map[string]string{"a": "111111111111", "b": "222222222222"}[spec.Name]
	web, role := "arn:aws:ec2:us-east-1:"+acct+":instance/i-web", "arn:aws:iam::"+acct+":role/admin"
	g.AddNode(&graph.Node{ID: web, Type: "aws_instance", Name: "web-" + spec.Name, Provider: "aws", Account: acct,
		Weaknesses: []string{"PUBLIC_NETWORK_EXPOSURE", "IMDSV1_ENABLED"}})
	g.AddNode(&graph.Node{ID: role, Type: "aws_iam_role", Name: "admin-" + spec.Name, Provider: "aws", Account: acct,
		Weaknesses: []string{"OVERPRIVILEGED_IDENTITY"}})
	g.AddEdge(graph.InternetNodeID, web, graph.EdgeExposes, map[string]any{"ports": "443", "exposure": "wide", "exposure_cidrs": []string{"0.0.0.0/0"}})
	g.AddEdge(web, role, graph.EdgeRunsAs, nil)
	return collector.Result{}, nil
}

// Item 8: `scan --accounts a` must not resolve account b's path Issues (its graph was not
// collected this time), and still resolves a's own path Issues when they disappear.
func TestPartialAccountScanKeepsOtherPathIssues(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	cfg := filepath.Join(dir, "cfg.yaml")
	os.WriteFile(cfg, []byte("accounts:\n  a:\n    provider: aws\n  b:\n    provider: aws\n"), 0o644)
	old := collectorHook
	t.Cleanup(func() { collectorHook = old; flagConfig = "" })
	collectorHook = func(o *collector.Options) {
		o.Collectors = map[string]collector.Collector{"aws": pathCollector{}}
	}
	runErr(t, "scan", "--config", cfg, "--tools", "native", "-o", "summary")
	open := func() map[string]string {
		m := map[string]string{}
		for _, is := range pathIssues(t) {
			m[is.Account] = is.State
		}
		return m
	}
	if s := open(); s["111111111111"] != model.StateOpen || s["222222222222"] != model.StateOpen {
		t.Fatalf("setup: both accounts need an open path Issue: %v", s)
	}
	runErr(t, "scan", "--config", cfg, "--accounts", "a", "--tools", "native", "-o", "summary")
	if s := open(); s["222222222222"] != model.StateOpen || s["111111111111"] != model.StateOpen {
		t.Fatalf("scan --accounts a changed path Issues: %v", s)
	}
}

// Item 3: `paths` names the exposures that are not attack paths; --exposures lists them.
func TestPathsPrintsExposures(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", labFile(t, "noise.findings.json"), "--source", "native", "-o", "summary")
	out := run(t, "paths")
	if !strings.Contains(out, "Exposures (not attack paths): ") {
		t.Fatalf("paths lacks the exposures block:\n%s", out)
	}
	if strings.Contains(out, "Exposures (not attack paths): 0") {
		t.Fatalf("noise estate has exposures:\n%s", out)
	}
	list := run(t, "paths", "--exposures")
	if strings.Count(list, "  - ") < 2 || !strings.Contains(list, "[wide") {
		t.Fatalf("--exposures does not list them:\n%s", list)
	}
}
