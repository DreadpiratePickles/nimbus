package cli

// Integration pass 3, item 1 (#6): commands users could not reach — mcp, convert, scan -o
// ocsf|asff|gitlab|junit|csv, paths one row per path Issue, pr-comment escalations.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/pathdiff"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
)

// labDB ingests the lab estate into a fresh database.
func labDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	run(t, "ingest", labFile(t, "estate.findings.json"), "-o", "summary")
	return dir
}

func TestMCPCommandServesStdio(t *testing.T) {
	dir := labDB(t)
	frames := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sql","arguments":{"query":"SELECT count(*) AS n FROM findings"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"draft_fix","arguments":{"finding_id":"lab-W01"}}}`,
	}, "\n") + "\n"
	audit := filepath.Join(dir, "audit.jsonl")
	mcpStdin = strings.NewReader(frames)
	t.Cleanup(func() { mcpStdin = nil })
	out := run(t, "mcp", "--scope", "read", "--audit", audit)
	var tools []string
	sawSQL, refused := false, false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal([]byte(line), &m) != nil {
			t.Fatalf("stdout carries a non JSON-RPC line (logs must go to stderr): %q", line)
		}
		switch m.ID {
		case 2:
			var r struct{ Tools []struct{ Name string } }
			json.Unmarshal(m.Result, &r)
			for _, x := range r.Tools {
				tools = append(tools, x.Name)
			}
		case 3:
			sawSQL = strings.Contains(string(m.Result), `"n"`) || strings.Contains(string(m.Result), "n\\\"")
		case 4:
			refused = len(m.Error) > 0 || strings.Contains(string(m.Result), "isError")
		}
	}
	if !containsExact(tools, "sql") || !containsExact(tools, "paths") || !containsExact(tools, "issue") {
		t.Errorf("tools/list = %v", tools)
	}
	if containsExact(tools, "draft_fix") {
		t.Errorf("--scope read must hide draft_fix: %v", tools)
	}
	if !sawSQL {
		t.Errorf("sql call did not answer over the store:\n%s", out)
	}
	if !refused {
		t.Errorf("draft_fix outside --scope read was not refused:\n%s", out)
	}
	if b, err := os.ReadFile(audit); err != nil || !bytes.Contains(b, []byte("sql")) {
		t.Errorf("--audit file not written: %v %s", err, b)
	}
}

func nativeInput(t *testing.T, dir string) string {
	t.Helper()
	in := filepath.Join(dir, "in.json")
	run(t, "scan", "--from-dir", labFile(t, "estate.findings.json"), "-o", "json", "--out-file", in)
	return in
}

func TestConvertCommand(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	in := nativeInput(t, dir)

	out := run(t, "convert", in, "--to", "ocsf")
	var events []map[string]any
	if err := json.Unmarshal([]byte(out), &events); err != nil || len(events) == 0 {
		t.Fatalf("convert --to ocsf: %v\n%.300s", err, out)
	}
	if events[0]["class_uid"] == nil {
		t.Errorf("not an OCSF event: %v", events[0])
	}
	junit := filepath.Join(dir, "r.xml")
	run(t, "convert", in, "--to", "junit", "-o", junit)
	b, err := os.ReadFile(junit)
	if err != nil || xml.Unmarshal(b, new(any)) != nil && !bytes.Contains(b, []byte("<testsuites")) {
		t.Fatalf("convert -o junit: %v %.200s", err, b)
	}
	// Round trip through OCSF back to native keeps every finding.
	ocsf := filepath.Join(dir, "o.json")
	os.WriteFile(ocsf, []byte(out), 0o644)
	back := run(t, "convert", ocsf, "--from", "ocsf", "--to", "json")
	if !strings.Contains(back, "lab-W01") {
		t.Errorf("ocsf → json lost lab-W01:\n%.300s", back)
	}
	if _, err := runErr(t, "convert", in, "--to", "pdf"); err == nil || !strings.Contains(err.Error(), "ocsf") {
		t.Errorf("unknown --to must fail naming the formats: %v", err)
	}
}

func TestScanOutputInteropFormats(t *testing.T) {
	dir := t.TempDir()
	flagDB = filepath.Join(dir, "p.db")
	flagQuiet = true
	t.Setenv("CLOUD_POSTURE_PYTHON", "/nonexistent/python")
	for _, c := range []struct{ format, want string }{
		{"ocsf", `"class_uid"`}, {"asff", `"ProductArn"`}, {"gitlab", `"vulnerabilities"`}, {"junit", "<testsuite"}, {"csv", "canonical_id"},
	} {
		f := filepath.Join(dir, "out."+c.format)
		run(t, "scan", "--from-dir", labFile(t, "estate.findings.json"), "-o", c.format, "--out-file", f)
		b, err := os.ReadFile(f)
		if err != nil || !bytes.Contains(b, []byte(c.want)) {
			t.Errorf("scan -o %s --out-file: %v %.200s", c.format, err, b)
		}
	}
}

func TestPathsOneRowPerPathIssue(t *testing.T) {
	labDB(t)
	var raw []model.AttackPath
	if err := json.Unmarshal([]byte(run(t, "paths", "--format", "json", "--all-variants", "--limit", "0")), &raw); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, p := range raw {
		e, a, r := model.PathIssueKey(p)
		keys[e+"|"+a+"|"+r] = true
	}
	if len(keys) >= len(raw) {
		t.Skipf("lab has no duplicate variants (%d paths, %d keys)", len(raw), len(keys))
	}
	out := run(t, "paths", "--limit", "0")
	rows := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimLeft(l, " "), "[") || (len(l) > 4 && l[2] == '.' && strings.Contains(l, "[")) {
			rows++
		}
	}
	if rows != len(keys) {
		t.Errorf("paths default printed %d rows, want one per path Issue (%d; %d raw variants):\n%s", rows, len(keys), len(raw), out)
	}
	if !strings.Contains(out, "variant") {
		t.Errorf("grouped rows must say how many hop variants they fold:\n%s", out)
	}
	all := run(t, "paths", "--all-variants", "--limit", "0")
	if n := strings.Count(all, "] "); n < len(raw) {
		t.Errorf("--all-variants printed %d rows, want %d", n, len(raw))
	}
	// JSON stays the raw path list (the benchmark harness and other machine consumers read
	// every variant); --all-variants is a no-op there.
	var asJSON []model.AttackPath
	if err := json.Unmarshal([]byte(run(t, "paths", "--format", "json", "--limit", "0")), &asJSON); err != nil || len(asJSON) != len(raw) {
		t.Errorf("paths --format json: %v, %d rows want %d", err, len(asJSON), len(raw))
	}
}

func TestPlanCommentEscalationsGate(t *testing.T) {
	esc := pathdiff.PathRef{IssueID: "abc", EntryName: "internet", AnchorName: "db", Score: 7.0, Band: "High"}
	low := pathdiff.PathRef{IssueID: "def", EntryName: "internet", AnchorName: "bucket", Score: 4.0, Band: "Low"}
	res := pathdiff.Result{Opened: []pathdiff.PathRef{}, Closed: []pathdiff.PathRef{},
		ChangedScore: []pathdiff.ScoreChange{{Path: esc, Before: 1.9, After: 7.0}, {Path: low, Before: 2.0, After: 4.0}}}
	got := escalatedPaths(res)
	if len(got) != 1 || got[0].Path.IssueID != "abc" {
		t.Fatalf("escalatedPaths = %+v, want only the path that rose to High", got)
	}
	if n := planGateCount(res, false); n != 1 {
		t.Errorf("--fail-on-opened must count escalations: %d", n)
	}
	if n := planGateCount(res, true); n != 0 {
		t.Errorf("--opened-only must ignore escalations: %d", n)
	}
	body := renderPlanComment(res, commentOptions{MaxPaths: 10})
	for _, want := range []string{"escalates 1", "nimbus-escalates-paths: 1", "1.9", "7.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("comment lacks %q:\n%s", want, body)
		}
	}
}

// Housekeeping: prioritize / scan rank with the real traversal analysis, so a resource the
// analysis says reaches a crown jewel is not off-path capped just because it is not a path step.
func TestRankAllUsesAnalysis(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "r1", Type: "aws_instance", Provider: "aws", Account: "1"})
	f := model.Finding{ID: "f1", CanonicalID: "EC2_IMDSV1", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: "r1", Type: "aws_instance"}}
	offPath := func(rs []risk.Ranked) float64 {
		for _, fc := range risk.Explain(rs[0]).Factors {
			if fc.Name == "off_path" {
				return fc.Multiplier
			}
		}
		return -1
	}
	without := rankAll(context.Background(), nil, []model.Finding{f}, g, nil, nil)
	with := rankAll(context.Background(), nil, []model.Finding{f}, g, nil, &attackpath.Analysis{ReachesCrownJewel: map[string]bool{"r1": true}})
	if m := offPath(without); m >= 1 {
		t.Fatalf("control: without analysis the finding should be off-path (multiplier %v)", m)
	}
	if m := offPath(with); m != 1 {
		t.Errorf("rankAll ignored the analysis: off_path multiplier %v, want 1 (reaches a crown jewel)", m)
	}
}

// Housekeeping: the graph-schema contract states the IAM confidence decision (verified = Allow
// from complete exact documents), not the earlier "policy evaluation = inferred" wording.
func TestGraphSchemaStatesIAMConfidenceRule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "graph-schema.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"Allow from complete", "exact", "approximate", "heuristic fallback"} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/graph-schema.md confidence text lacks %q", want)
		}
	}
	if strings.Contains(s, "`inferred` = policy evaluation (possibly with conditions)") {
		t.Error("docs/graph-schema.md still says every policy evaluation is inferred")
	}
}

// Item 6 (engine round 2 wiring): rule chains get the graph (EvalOptions.Graph: SCP-neutralised
// admins and REACH-blocked exposure do not count) and the traversal gets the CVE gate inputs
// (NodeCVEs from the findings, Intel from the live enricher, which honours --no-network).
func TestEngineRound2OptionsWired(t *testing.T) {
	g := graph.New()
	if o := evalOptionsFor(nil, g); o.Graph != g {
		t.Error("evalOptionsFor must pass the graph to the rule engine")
	}
	fs := []model.Finding{{ID: "c1", CheckID: "CVE-2021-44228", CanonicalID: "CVE-2021-44228", Status: model.Fail, Resource: model.Resource{ID: "i-1"}}}
	o := traversalOptionsFor(nil, g, fs)
	if len(o.NodeCVEs["i-1"]) == 0 {
		t.Errorf("NodeCVEs not set from the findings: %v", o.NodeCVEs)
	}
	if o.Intel == nil {
		t.Error("traversal Intel not set to the live enricher")
	}
}
