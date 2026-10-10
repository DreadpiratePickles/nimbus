package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/remediation"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

type tool struct {
	name, title, description string
	input                    map[string]any
	run                      func(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error)
}

var tools = []tool{
	{name: "sql", title: "Read-only SQL", run: toolSQL,
		description: "Run ONE read-only SELECT/WITH query over the posture database (tables and views listed by the schema tool) " +
			"on the hardened path: lexer, read-only connection, bytecode allowlist, timeout and row cap. Returns the SQL run, columns and rows.",
		input: obj(props{
			"query":    str("A single SQLite SELECT or WITH statement."),
			"max_rows": integer("Row cap for this call (server ceiling applies)."),
		}, "query")},
	{name: "schema", title: "Queryable schema", run: toolSchema,
		description: "List the tables and views the sql tool may read, with their columns.",
		input:       obj(props{})},
	{name: "paths", title: "Attack path Issues", run: toolPaths,
		description: "List attack-path Issues (the unit every nimbus surface counts), highest score first, each with its hop variants, " +
			"filtered by severity, band, account, provider or minimum score. Each hop carries the resource, weakness and `because`; " +
			"each Issue carries the entry's reachability verdict. With `from` and `to` (optionally `through`, `max_hops`) it is a " +
			"read-only graph query, the same as `cloud-posture paths --from --to --through --max-hops`: every attack-step path " +
			"between the two node sets, highest score first. Selectors: `internet`, `type:<node type>`, `class:<class>`, a node " +
			"id or name, comma-separated.",
		input: obj(props{
			"from":      str("Query: start selector (internet, type:<t>, class:<c>, node id or name; comma-separated)."),
			"to":        str("Query: end selector (same forms as from)."),
			"through":   str("Query: every path must visit one of these nodes (same forms as from)."),
			"max_hops":  integer("Query: maximum hops (default 6, max 10)."),
			"severity":  enum("Path severity.", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
			"band":      enum("Score band.", "Critical", "High", "Medium", "Low"),
			"account":   str("Account / subscription / project (exact)."),
			"provider":  str("aws, azure, gcp, kubernetes, ..."),
			"min_score": number("Minimum path score (0-10)."),
			"limit":     integer("Maximum Issues returned (default 20, max 200)."),
		})},
	{name: "who_can", title: "Who can", run: toolWhoCan,
		description: "Which principals can perform an action on a resource, directly or through can_assume chains, from the IAM " +
			"evaluator (the same engine as `cloud-posture who-can`). Anonymous (internet) access is listed first.",
		input: obj(props{
			"action":   str("IAM action, e.g. s3:GetObject."),
			"resource": str("Resource ARN, graph node id or a unique resource name (placeholders as returned)."),
			"depth":    integer("Maximum can_assume chain length (default 4, max 8)."),
		}, "action", "resource")},
	{name: "prioritize", title: "Prioritised findings", run: toolPrioritize,
		description: "Failing findings ranked by contextual risk (the same scorer as `cloud-posture prioritize`): score, band, " +
			"attack-path count and the reachability verdict of the resource.",
		input: obj(props{
			"limit":    integer("Maximum findings (default 20, max 200)."),
			"band":     enum("Only this band.", "Critical", "High", "Medium", "Low"),
			"provider": str("aws, azure, gcp, kubernetes, ..."),
		})},
	{name: "verify", title: "Verification state", run: toolVerify,
		description: "Read-only evaluation of an Issue: what `cloud-posture verify <issue>` would re-read (each resource with the targeted " +
			"reader that covers it), whether the stored evidence already shows the problem gone (failing findings; for path Issues a " +
			"re-traversal of the stored graph), and the last verification and history. With from_file, also evaluates that local findings " +
			"export exactly as `cloud-posture verify --from-file --attempts 1` would (file_evaluation) — and still records nothing. " +
			"Never re-collects, never changes the Issue or a ticket.",
		input: obj(props{
			"issue_id":  str("Issue id."),
			"from_file": str("Optional path of a findings export (any format `ingest` reads) under the server's file roots (database directory, working directory); evaluated read-only."),
		}, "issue_id")},
	{name: "summary", title: "Posture summary", run: toolSummary,
		description: "The headline counts every nimbus surface prints (store.Headline): open Issues, attack-path Issues and their " +
			"variants, Critical, by severity / provider, verification states, last scan.",
		input: obj(props{})},
	{name: "issue", title: "Issue detail", run: toolIssue,
		description: "One Issue by id: its fields, evidence findings (no raw provider JSON), and for path Issues the paths and state history.",
		input:       obj(props{"id": str("Issue id.")}, "id")},
	{name: "explain", title: "Risk explanation", run: toolExplain,
		description: "Why a finding scores what it does: base, every multiplier factor with its reason and evidence, top paths. " +
			"Accepts a finding id or an Issue id (explains the Issue's evidence findings).",
		input: obj(props{"id": str("Finding id or Issue id.")}, "id")},
	{name: "coverage", title: "Collection coverage", run: toolCoverage,
		description: "What the last (or given) scan could and could not see: per provider/account/API status and reason.",
		input:       obj(props{"scan_id": str("Scan id (default: latest).")})},
	{name: "simulate_fix", title: "Simulate fixes", run: toolSimulate,
		description: "What-if: remove the given weaknesses or edges from an in-memory copy of the graph, re-run the attack-path " +
			"traversal and report how many paths are resolved and the remaining score. Never applies anything.",
		input: obj(props{
			"fixes": map[string]any{"type": "array", "description": "Fixes to simulate.", "items": obj(props{
				"node_id":  str("Resource (graph node) id."),
				"weakness": str("Weakness to remove from that node, e.g. PUBLIC_DATA_STORE."),
				"edge":     obj(props{"from": str("From node."), "to": str("To node."), "kind": str("Edge kind.")}, "from", "to", "kind"),
			})},
			"min_fix_set": map[string]any{"type": "boolean", "description": "Simulate the analysis's minimum fix set instead."},
		})},
	{name: "draft_fix", title: "Draft a fix", run: toolDraftFix,
		description: "Generate the remediation for a finding (Terraform, CloudFormation, Bicep or Kubernetes) and return it as text " +
			"and as a new-file diff. Never writes a file and never applies: a human reviews and applies it through the IaC pipeline.",
		input: obj(props{
			"finding_id": str("Finding id."),
			"format":     enum("Output format (default: the first template the check has, else terraform).", "terraform", "cloudformation", "bicep", "kubernetes", ""),
		}, "finding_id")},
}

var toolsByName = func() map[string]tool {
	m := map[string]tool{}
	for _, t := range tools {
		m[t.name] = t
	}
	return m
}()

type props map[string]any

func obj(p props, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": map[string]any(p), "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}
func str(d string) map[string]any     { return map[string]any{"type": "string", "description": d} }
func number(d string) map[string]any  { return map[string]any{"type": "number", "description": d} }
func integer(d string) map[string]any { return map[string]any{"type": "integer", "description": d} }
func enum(d string, v ...string) map[string]any {
	return map[string]any{"type": "string", "description": d, "enum": v}
}

func (s *session) listTools() []any {
	var out []any
	for _, t := range tools {
		if !s.scope.Allows(t.name) {
			continue
		}
		out = append(out, map[string]any{
			"name": t.name, "title": t.title, "description": t.description, "inputSchema": t.input,
			"annotations": map[string]any{"title": t.title, "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
		})
	}
	return out
}

// decode parses arguments strictly: unknown fields are an error, so a typo is not ignored.
func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errf("bad arguments: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------- sql / schema

func toolSQL(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		Query   string `json:"query"`
		MaxRows int    `json:"max_rows"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	meta := &callMeta{sql: a.Query}
	max := s.opts.MaxRows
	if a.MaxRows > 0 && a.MaxRows < max {
		max = a.MaxRows
	}
	run := a.Query
	if s.sqlRed != nil {
		var err error
		if run, err = s.sqlRed.rewrite(a.Query); err != nil {
			return nil, meta, err
		}
	}
	res, err := s.rd.QueryReadOnly(ctx, run, store.ReadOnlyOptions{Timeout: s.opts.SQLTimeout, MaxRows: max})
	if err != nil {
		return nil, meta, errf("%v", err)
	}
	meta.rows = len(res.Rows)
	rows := res.Rows
	if rows == nil {
		rows = [][]any{}
	}
	if s.red != nil {
		s.red.table(res.Columns, rows)
	}
	return map[string]any{"sql": a.Query, "columns": res.Columns, "rows": rows, "row_count": len(rows), "truncated": res.Truncated,
		"engine": "local-readonly"}, meta, nil
}

func toolSchema(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct{}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	sch, err := schema(s.rd)
	if err != nil {
		return nil, nil, err
	}
	return map[string]any{"tables": sch, "note": "Only these tables/views are readable by the sql tool."}, nil, nil
}

func schema(rd Reader) (map[string][]string, error) {
	names, err := rd.QueryableTables()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, n := range names {
		cols, err := rd.TableColumns(n)
		if err != nil {
			continue
		}
		out[n] = cols
	}
	return out, nil
}

// ---------------------------------------------------------------- paths

type hopOut struct {
	Stage      int    `json:"stage"`
	Resource   string `json:"resource"`
	Weakness   string `json:"weakness"`
	WeaknessOn string `json:"weakness_on,omitempty"`
	Relation   string `json:"relation"`
	Because    string `json:"because"`
	FindingID  string `json:"finding_id,omitempty"`
	Title      string `json:"title,omitempty"`
	Summary    string `json:"summary,omitempty"`
}

type pathOut struct {
	ID         string   `json:"id"`
	IssueID    string   `json:"issue_id,omitempty"`
	Name       string   `json:"name"`
	RuleID     string   `json:"rule_id"`
	Provider   string   `json:"provider"`
	Account    string   `json:"account"`
	Severity   string   `json:"severity"`
	Score      float64  `json:"score"`
	Band       string   `json:"band"`
	Impact     string   `json:"impact,omitempty"`
	Narrative  string   `json:"narrative,omitempty"`
	Mitre      []string `json:"mitre,omitempty"`
	WeakLink   bool     `json:"weak_link,omitempty"`
	FindingIDs []string `json:"finding_ids"`
	Hops       []hopOut `json:"hops"`
	// Verdict is graph.Verdict of the path's entry (first hop) node: the one internet-
	// reachability verdict and wording every surface prints (delta r2 #1/#8).
	Verdict *graph.Verdict `json:"verdict,omitempty"`
}

// withVerdicts sets each path row's entry verdict from the stored graph (no-op without one).
func withVerdicts(rd Reader, rows []pathOut) {
	if len(rows) == 0 {
		return
	}
	g, err := rd.LoadGraph()
	if err != nil || g == nil {
		return
	}
	withVerdictsGraph(g, rows)
}

func withVerdictsGraph(g *graph.Graph, rows []pathOut) {
	for i := range rows {
		if len(rows[i].Hops) == 0 || rows[i].Hops[0].Resource == "" {
			continue
		}
		v := g.Verdict(rows[i].Hops[0].Resource)
		rows[i].Verdict = &v
	}
}

func toPathOut(p model.AttackPath, issueID string) pathOut {
	o := pathOut{ID: p.ID, IssueID: issueID, Name: p.Name, RuleID: p.RuleID, Provider: p.Provider, Account: p.Account,
		Severity: string(p.Severity), Score: p.Score, Band: model.ScoreBand(p.Score), Impact: p.Impact, Narrative: p.Narrative,
		Mitre: p.Mitre, WeakLink: p.WeakLink, FindingIDs: p.FindingIDs, Hops: []hopOut{}}
	if o.FindingIDs == nil {
		o.FindingIDs = []string{}
	}
	for _, st := range p.Steps {
		o.Hops = append(o.Hops, hopOut{Stage: st.Stage, Resource: st.Resource, Weakness: st.Weakness, WeaknessOn: st.WeaknessOn,
			Relation: st.Relation, Because: st.Because, FindingID: st.FindingID, Title: st.Title, Summary: st.Summary})
	}
	return o
}

var bands = map[string]string{"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

// issueRow is one attack-path Issue with the hop variants that make it up.
type issueRow struct {
	IssueID      string         `json:"issue_id"`
	Title        string         `json:"title,omitempty"`
	State        string         `json:"state,omitempty"`
	Severity     string         `json:"severity"`
	Score        float64        `json:"score"`
	Band         string         `json:"band"`
	Provider     string         `json:"provider"`
	Account      string         `json:"account"`
	Entry        string         `json:"entry,omitempty"`
	Anchor       string         `json:"anchor,omitempty"`
	VariantCount int            `json:"variant_count"`
	Verdict      *graph.Verdict `json:"verdict,omitempty"`
	Variants     []pathOut      `json:"variants"`
}

func toolPaths(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		Severity string   `json:"severity"`
		Band     string   `json:"band"`
		Account  string   `json:"account"`
		Provider string   `json:"provider"`
		MinScore *float64 `json:"min_score"`
		Limit    int      `json:"limit"`
		From     string   `json:"from"`
		To       string   `json:"to"`
		Through  string   `json:"through"`
		MaxHops  *int     `json:"max_hops"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	band := ""
	if a.Band != "" {
		b, ok := bands[strings.ToLower(a.Band)]
		if !ok {
			return nil, nil, errf("band must be one of Critical, High, Medium, Low")
		}
		band = b
	}
	if a.Limit <= 0 {
		a.Limit = 20
	}
	if a.Limit > 200 {
		a.Limit = 200
	}
	keep := func(p model.AttackPath) bool {
		return (a.Severity == "" || strings.EqualFold(string(p.Severity), a.Severity)) &&
			(band == "" || model.ScoreBand(p.Score) == band) && (a.Account == "" || p.Account == a.Account) &&
			(a.Provider == "" || strings.EqualFold(p.Provider, a.Provider)) && (a.MinScore == nil || p.Score >= *a.MinScore)
	}
	if a.From != "" || a.To != "" || a.Through != "" || a.MaxHops != nil {
		// Graph query (W6-ENGINE, delta r4 #10): read-only, the CLI's attackpath.Query.
		g, err := s.rd.LoadGraph()
		if err != nil {
			return nil, nil, err
		}
		if g == nil {
			return nil, nil, errf("no stored graph: run a scan or ingest first")
		}
		hops := attackpath.DefaultQueryMaxHops
		if a.MaxHops != nil {
			hops = *a.MaxHops
		}
		qr, err := attackpath.Query(g, s.opts.Traversal(g), attackpath.PathQuery{From: a.From, To: a.To, Through: a.Through, MaxHops: hops})
		if err != nil {
			return nil, nil, errf("%s", strings.NewReplacer("--max-hops", "max_hops", "--from", "from", "--to", "to", "--through", "through").Replace(err.Error()))
		}
		out := []pathOut{}
		for _, p := range qr.Paths {
			if keep(p) {
				out = append(out, toPathOut(p, ""))
			}
		}
		matched := len(out)
		if len(out) > a.Limit {
			out = out[:a.Limit]
		}
		withVerdictsGraph(g, out)
		return map[string]any{"query": qr.Query, "from_nodes": qr.FromNodes, "to_nodes": qr.ToNodes, "through_nodes": qr.Through,
			"paths": out, "matched_paths": matched, "returned": len(out), "explored": qr.Explored, "truncated": qr.Truncated,
			"unit": "graph-query paths (attack steps between the selected nodes; not Issues)"}, nil, nil
	}
	paths, err := s.rd.AttackPaths()
	if err != nil {
		return nil, nil, err
	}
	issueOf := pathIssueIndex(s.rd)
	meta := map[string]model.Issue{}
	if all, err := s.rd.Issues(store.IssueFilter{Kind: model.IssuePath}); err == nil {
		for _, is := range all {
			meta[is.ID] = is
		}
	}
	byKey := map[string]*issueRow{}
	var order []string
	variants := 0
	for _, p := range paths {
		if a.Severity != "" && !strings.EqualFold(string(p.Severity), a.Severity) {
			continue
		}
		if band != "" && model.ScoreBand(p.Score) != band {
			continue
		}
		if a.Account != "" && p.Account != a.Account {
			continue
		}
		if a.Provider != "" && !strings.EqualFold(p.Provider, a.Provider) {
			continue
		}
		if a.MinScore != nil && p.Score < *a.MinScore {
			continue
		}
		variants++
		key := issueOf[p.ID]
		if key == "" {
			key = "path:" + p.ID // a stored path no Issue groups (e.g. a rule path): its own row
		}
		row, ok := byKey[key]
		if !ok {
			row = &issueRow{IssueID: issueOf[p.ID], Provider: p.Provider, Account: p.Account}
			if is, ok := meta[row.IssueID]; ok {
				row.Title, row.State, row.Entry, row.Anchor = is.Title, string(is.State), is.EntryID, is.AnchorID
			}
			byKey[key] = row
			order = append(order, key)
		}
		row.Variants = append(row.Variants, toPathOut(p, issueOf[p.ID]))
	}
	rows := make([]*issueRow, 0, len(order))
	for _, k := range order {
		r := byKey[k]
		sort.SliceStable(r.Variants, func(i, j int) bool {
			if r.Variants[i].Score != r.Variants[j].Score {
				return r.Variants[i].Score > r.Variants[j].Score
			}
			return r.Variants[i].ID < r.Variants[j].ID
		})
		best := r.Variants[0]
		r.Score, r.Band, r.Severity, r.VariantCount = best.Score, best.Band, best.Severity, len(r.Variants)
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].IssueID+rows[i].Variants[0].ID < rows[j].IssueID+rows[j].Variants[0].ID
	})
	total := len(rows)
	if len(rows) > a.Limit {
		rows = rows[:a.Limit]
	}
	if g, err := s.rd.LoadGraph(); err == nil && g != nil {
		for _, r := range rows {
			withVerdictsGraph(g, r.Variants)
			r.Verdict = r.Variants[0].Verdict
		}
	}
	return map[string]any{"issues": rows, "matched_issues": total, "matched_variants": variants, "returned": len(rows),
		"unit": "attack-path Issues (each with its hop variants)"}, nil, nil
}

func pathIssueIndex(rd Reader) map[string]string {
	idx := map[string]string{}
	issues, err := rd.Issues(store.IssueFilter{Kind: model.IssuePath})
	if err != nil {
		return idx
	}
	for _, is := range issues {
		for _, pid := range is.PathIDs {
			idx[pid] = is.ID
		}
	}
	return idx
}

// ---------------------------------------------------------------- issue

// findingOut is a finding without raw provider JSON or resource attributes (policy documents,
// user data): the minimised evidence view.
type findingOut struct {
	ID           string              `json:"id"`
	CanonicalID  string              `json:"canonical_id"`
	Source       string              `json:"source"`
	Title        string              `json:"title"`
	Description  string              `json:"description,omitempty"`
	Severity     string              `json:"severity"`
	Status       string              `json:"status"`
	Provider     string              `json:"provider"`
	Account      string              `json:"account"`
	Region       string              `json:"region,omitempty"`
	ResourceID   string              `json:"resource_id"`
	ResourceType string              `json:"resource_type"`
	ResourceName string              `json:"resource_name"`
	File         string              `json:"file,omitempty"`
	LineStart    int                 `json:"line_start,omitempty"`
	Weaknesses   []string            `json:"weaknesses,omitempty"`
	Compliance   map[string][]string `json:"compliance,omitempty"`
	Tags         map[string]string   `json:"tags,omitempty"`
	Remediation  string              `json:"remediation,omitempty"`
	FirstSeen    string              `json:"first_seen,omitempty"`
	LastSeen     string              `json:"last_seen,omitempty"`
}

func toFindingOut(f model.Finding) findingOut {
	o := findingOut{ID: f.ID, CanonicalID: f.CanonicalID, Source: f.Source, Title: f.Title, Description: f.Description,
		Severity: string(f.Severity), Status: string(f.Status), Provider: f.Provider, Account: f.Account, Region: f.Region,
		ResourceID: f.Resource.ID, ResourceType: f.Resource.Type, ResourceName: f.Resource.Name, File: f.File, LineStart: f.LineStart,
		Weaknesses: f.Weaknesses, Compliance: f.Compliance, Tags: f.Tags, Remediation: f.Remediation}
	if !f.FirstSeen.IsZero() {
		o.FirstSeen = f.FirstSeen.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !f.LastSeen.IsZero() {
		o.LastSeen = f.LastSeen.UTC().Format("2006-01-02T15:04:05Z")
	}
	return o
}

func findIssue(rd Reader, id string) (*model.Issue, error) {
	issues, err := rd.Issues(store.IssueFilter{})
	if err != nil {
		return nil, err
	}
	for i := range issues {
		if issues[i].ID == id {
			return &issues[i], nil
		}
	}
	return nil, nil
}

const maxEvidence = 50

func toolIssue(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if a.ID == "" {
		return nil, nil, errf("id is required")
	}
	is, err := findIssue(s.rd, a.ID)
	if err != nil {
		return nil, nil, err
	}
	if is == nil {
		return nil, nil, errf("no Issue with id %q", a.ID)
	}
	out := map[string]any{"issue": is}
	if node := firstNonEmptyStr(is.AnchorID, is.ResourceID); node != "" {
		if g, err := s.rd.LoadGraph(); err == nil && g != nil {
			out["verdict"] = g.Verdict(node) // graph.Verdict of the Issue's anchor / resource
		}
	}
	ev := []findingOut{}
	for i, fid := range is.FindingIDs {
		if i >= maxEvidence {
			out["evidence_truncated"] = true
			break
		}
		f, err := s.rd.Finding(fid)
		if err != nil || f == nil {
			continue
		}
		ev = append(ev, toFindingOut(*f))
	}
	out["evidence"] = ev
	if is.Kind == model.IssuePath {
		h, err := s.rd.PathIssueHistory(is.ID)
		if err != nil {
			return nil, nil, err
		}
		if h == nil {
			h = []store.PathIssueHistoryEntry{}
		}
		out["history"] = h
		want := map[string]bool{}
		for _, pid := range is.PathIDs {
			want[pid] = true
		}
		paths, err := s.rd.AttackPaths()
		if err != nil {
			return nil, nil, err
		}
		ps := []pathOut{}
		for _, p := range paths {
			if want[p.ID] {
				ps = append(ps, toPathOut(p, is.ID))
			}
		}
		withVerdicts(s.rd, ps)
		out["variants"] = ps
		out["variant_count"] = len(ps)
	}
	return out, nil, nil
}

// ---------------------------------------------------------------- explain

func toolExplain(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if a.ID == "" {
		return nil, nil, errf("id is required")
	}
	var ids []string
	var issueID string
	if f, _ := s.rd.Finding(a.ID); f != nil {
		ids = []string{f.ID} // the stored id (a.ID may be the external one)
	} else {
		is, err := findIssue(s.rd, a.ID)
		if err != nil {
			return nil, nil, err
		}
		if is == nil {
			return nil, nil, errf("no finding or Issue with id %q", a.ID)
		}
		issueID, ids = is.ID, is.FindingIDs
		if len(ids) > 10 {
			ids = ids[:10]
		}
	}
	fs, err := s.rd.Findings(store.Filter{Status: string(model.Fail)})
	if err != nil {
		return nil, nil, err
	}
	paths, _ := s.rd.AttackPaths()
	g, err := s.rd.LoadGraph()
	if err != nil {
		return nil, nil, err
	}
	ranked := risk.PrioritizeWith(fs, g, paths, s.opts.RiskOptions())
	byID := map[string]risk.Ranked{}
	for _, r := range ranked {
		byID[r.Finding.ID] = r
	}
	var out []map[string]any
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			continue
		}
		e := risk.Explain(r)
		out = append(out, map[string]any{
			"finding_id": id, "canonical_id": r.Finding.CanonicalID, "title": r.Finding.Title, "score": r.Score, "band": r.Band,
			"version": e.Version, "base": e.Base, "base_reason": e.BaseReason, "raw": e.Raw, "factors": nonNil(e.Factors),
			"top_paths": e.TopPaths, "missing": e.Missing, "attack_paths": r.AttackPaths,
		})
	}
	if len(out) == 0 {
		return nil, nil, errf("%q has no failing finding to explain (passed, resolved or not scored)", a.ID)
	}
	res := map[string]any{"explanations": out}
	if issueID != "" {
		res["issue_id"] = issueID
	}
	return res, nil, nil
}

func nonNil(f []risk.Factor) []risk.Factor {
	if f == nil {
		return []risk.Factor{}
	}
	return f
}

// ---------------------------------------------------------------- coverage

func toolCoverage(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		ScanID string `json:"scan_id"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	return coverage(s.rd, a.ScanID)
}

func coverage(rd Reader, scanID string) (map[string]any, *callMeta, error) {
	entries, err := rd.Coverage(scanID)
	if err != nil {
		return nil, nil, err
	}
	if entries == nil {
		entries = []store.CoverageEntry{}
	}
	by := map[string]int{}
	for _, e := range entries {
		by[e.Status]++
	}
	out := map[string]any{"entries": entries, "by_status": by}
	if last, err := rd.LastScan(); err == nil && last != nil {
		out["last_scan"] = map[string]any{"scan_id": last.ScanID, "finished_at": last.FinishedAt, "accounts": last.Accounts, "total": last.Total}
	}
	if len(entries) == 0 {
		out["note"] = "no coverage recorded for this scan; absence of findings is not evidence of absence"
	}
	return out, nil, nil
}

// ---------------------------------------------------------------- simulate_fix

func toolSimulate(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		Fixes []struct {
			NodeID   string              `json:"node_id"`
			Weakness string              `json:"weakness"`
			Edge     *attackpath.EdgeRef `json:"edge"`
		} `json:"fixes"`
		MinFixSet bool `json:"min_fix_set"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if len(a.Fixes) == 0 && !a.MinFixSet {
		return nil, nil, errf("give fixes or min_fix_set: true")
	}
	if len(a.Fixes) > 50 {
		return nil, nil, errf("at most 50 fixes per simulation")
	}
	g, err := s.rd.LoadGraph()
	if err != nil {
		return nil, nil, err
	}
	opts := s.opts.Traversal(g)
	before := attackpath.Traverse(g, opts)
	var fixes []attackpath.Fix
	if a.MinFixSet {
		fixes = before.MinFixSet
		if len(fixes) == 0 {
			return nil, nil, errf("the analysis has no minimum fix set (no cuttable paths)")
		}
	}
	for _, f := range a.Fixes {
		if f.NodeID == "" && f.Edge == nil {
			return nil, nil, errf("each fix needs node_id+weakness or edge")
		}
		if f.NodeID != "" {
			if _, ok := g.Node(f.NodeID); !ok {
				return nil, nil, errf("unknown node %q", f.NodeID)
			}
			if f.Weakness == "" {
				return nil, nil, errf("fix on %q needs a weakness", f.NodeID)
			}
		}
		if f.Edge != nil {
			if _, ok := g.Node(f.Edge.From); !ok {
				return nil, nil, errf("unknown edge source %q", f.Edge.From)
			}
		}
		fixes = append(fixes, attackpath.Fix{NodeID: f.NodeID, Weakness: f.Weakness, Edge: f.Edge})
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	resolved, remaining := attackpath.SimulateWith(g, opts, fixes)
	applied := []map[string]any{}
	for _, f := range fixes {
		m := map[string]any{"node_id": f.NodeID, "weakness": f.Weakness}
		if f.Edge != nil {
			m["edge"] = f.Edge
		}
		if f.Command != "" {
			m["command"] = f.Command
		}
		applied = append(applied, m)
	}
	return map[string]any{
		"applied": false, "fixes": applied, "paths_before": len(before.Paths), "total_score": before.TotalScore,
		"resolves": resolved, "remaining_score": remaining,
		"note": "Simulation on an in-memory copy of the graph (traversal paths only). Nothing was changed.",
	}, nil, nil
}

// ---------------------------------------------------------------- draft_fix

func toolDraftFix(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		FindingID string `json:"finding_id"`
		Format    string `json:"format"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if a.FindingID == "" {
		return nil, nil, errf("finding_id is required")
	}
	f, err := s.rd.Finding(a.FindingID)
	if err != nil || f == nil {
		return nil, nil, errf("no finding with id %q", a.FindingID)
	}
	var format remediation.Format
	if a.Format != "" {
		if format, err = remediation.ParseFormat(a.Format); err != nil {
			return nil, nil, errf("%v", err)
		}
	} else if fs := remediation.Formats(f.CanonicalID); len(fs) > 0 {
		format = fs[0]
		for _, x := range fs {
			if x == remediation.Terraform {
				format = x
			}
		}
	} else {
		format = remediation.Terraform
	}
	fix, err := remediation.Generate(*f, format)
	if err != nil {
		return nil, nil, errf("%v", err)
	}
	return map[string]any{
		"finding_id": f.ID, "canonical_id": fix.CanonicalID, "format": fix.Format, "file_name": fix.FileName, "content": fix.Content,
		"diff": newFileDiff(fix.FileName, fix.Content), "review_command": fix.Apply, "steps": fix.Steps, "generic": fix.Generic,
		"template": fix.Template, "applied": false,
		"note": "Draft only: nothing was written or applied. Show it to a human; apply only with explicit approval, through the IaC pipeline.",
	}, nil, nil
}

// newFileDiff renders content as a unified diff creating file.
func newFileDiff(file, content string) string {
	lines := strings.SplitAfter(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", file, len(lines))
	for _, l := range lines {
		b.WriteString("+" + l)
		if !strings.HasSuffix(l, "\n") {
			b.WriteString("\n\\ No newline at end of file\n")
		}
	}
	return b.String()
}

// ---------------------------------------------------------------- who_can / prioritize

func toolWhoCan(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		Action   string `json:"action"`
		Resource string `json:"resource"`
		Depth    int    `json:"depth"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(a.Action) == "" || strings.TrimSpace(a.Resource) == "" {
		return nil, nil, errf("action and resource are required")
	}
	if a.Depth <= 0 {
		a.Depth = 4
	}
	if a.Depth > 8 {
		a.Depth = 8
	}
	g, err := s.rd.LoadGraph()
	if err != nil {
		return nil, nil, err
	}
	if id, rerr := graph.ResolveNodeName(g, a.Resource); rerr == nil { // the CLI's rule; an unknown or shared name stays as given
		a.Resource = id
	}
	res := graph.WhoCan(g, a.Action, a.Resource, a.Depth)
	if res == nil {
		res = []graph.WhoCanResult{}
	}
	return map[string]any{"action": a.Action, "resource": a.Resource, "principals": res, "count": len(res),
		"note": "From the IAM evaluator over the stored graph (identity, resource and trust policies, SCPs where collected); decision unknown means a condition could not be evaluated."}, nil, nil
}

func toolPrioritize(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		Limit    int    `json:"limit"`
		Band     string `json:"band"`
		Provider string `json:"provider"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	band := ""
	if a.Band != "" {
		b, ok := bands[strings.ToLower(a.Band)]
		if !ok {
			return nil, nil, errf("band must be one of Critical, High, Medium, Low")
		}
		band = b
	}
	if a.Limit <= 0 {
		a.Limit = 20
	}
	if a.Limit > 200 {
		a.Limit = 200
	}
	fs, err := s.rd.Findings(store.Filter{Status: string(model.Fail)})
	if err != nil {
		return nil, nil, err
	}
	paths, _ := s.rd.AttackPaths()
	g, err := s.rd.LoadGraph()
	if err != nil {
		return nil, nil, err
	}
	ranked := risk.PrioritizeWith(fs, g, paths, s.opts.RiskOptions())
	out := []map[string]any{}
	matched := 0
	for _, r := range ranked {
		if band != "" && r.Band != band {
			continue
		}
		if a.Provider != "" && !strings.EqualFold(r.Finding.Provider, a.Provider) {
			continue
		}
		matched++
		if len(out) >= a.Limit {
			continue
		}
		row := map[string]any{"rank": matched, "finding_id": r.Finding.ID, "canonical_id": r.Finding.CanonicalID, "title": r.Finding.Title,
			"score": r.Score, "band": r.Band, "severity": r.Finding.Severity, "provider": r.Finding.Provider, "account": r.Finding.Account,
			"resource_id": r.Finding.Resource.ID, "resource_name": r.Finding.Resource.Name, "attack_paths": r.AttackPaths, "reasons": r.Reasons,
			"score_version": r.ScoreVersion}
		if g != nil && r.Finding.Resource.ID != "" {
			if _, ok := g.Node(r.Finding.Resource.ID); ok {
				row["verdict"] = g.Verdict(r.Finding.Resource.ID)
			}
		}
		out = append(out, row)
	}
	return map[string]any{"findings": out, "matched": matched, "returned": len(out), "unit": "findings (evidence; Issues are the queue unit)"}, nil, nil
}

// ---------------------------------------------------------------- verify (read-only)

func toolVerify(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct {
		IssueID  string `json:"issue_id"`
		FromFile string `json:"from_file"`
	}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	if a.IssueID == "" {
		return nil, nil, errf("issue_id is required")
	}
	is, err := findIssue(s.rd, a.IssueID)
	if err != nil {
		return nil, nil, err
	}
	if is == nil {
		return nil, nil, errf("no Issue with id %q", a.IssueID)
	}
	var fileEval map[string]any
	if a.FromFile != "" {
		if s.opts.VerifyFile == nil {
			return nil, nil, errf("from_file evaluation is not available in this server (no verify engine registered)")
		}
		path, err := resolveFromFile(a.FromFile, s.opts.FileRoots)
		if err != nil {
			return nil, nil, err
		}
		if fileEval, err = s.opts.VerifyFile(ctx, s.raw, *is, path); err != nil {
			return nil, nil, errf("from_file evaluation failed: %v", err)
		}
		fileEval["file"] = filepath.Base(path)
		fileEval["recorded"] = false
	}
	type target struct {
		Resource string `json:"resource"`
		Role     string `json:"role"`
		Type     string `json:"type,omitempty"`
		// Reader is the targeted reader that would re-read it ("aws:rds", "azure:nsg", ...);
		// "" means no collector targets that type yet (verify needs --from-file for it).
		Reader string `json:"reader"`
	}
	var targets []target
	seen := map[string]bool{}
	g, _ := s.rd.LoadGraph()
	add := func(id, role string) {
		if id == "" || seen[id] || id == graph.InternetNodeID || id == model.PathEntryInternet {
			return
		}
		seen[id] = true
		t := target{Resource: id, Role: role, Reader: core.TargetReader(model.NormalizeProvider(is.Provider), id)}
		if g != nil {
			if n, ok := g.Node(id); ok {
				t.Type = n.Type
				if t.Reader == "" && n.Provider != "" {
					t.Reader = core.TargetReader(model.NormalizeProvider(n.Provider), id)
				}
			}
		}
		targets = append(targets, t)
	}
	add(is.AnchorID, "anchor")
	add(is.ResourceID, "resource")
	eval := map[string]any{"state": string(is.State)}
	if is.Kind == model.IssuePath {
		want := map[string]bool{}
		for _, pid := range is.PathIDs {
			want[pid] = true
		}
		if paths, err := s.rd.AttackPaths(); err == nil {
			for _, p := range paths {
				if !want[p.ID] {
					continue
				}
				for i, st := range p.Steps {
					role := "hop"
					if i == 0 {
						role = "entry"
					}
					add(st.Resource, role)
				}
			}
		}
		// Re-run the traversal over the stored graph in memory: does a path with this Issue's
		// entry and anchor still exist on the stored state?
		surviving, best := 0, 0.0
		if g != nil {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			an := attackpath.Traverse(g.Clone(), s.opts.Traversal(g))
			for _, p := range an.Paths {
				e, anc, _ := model.PathIssueKey(p)
				if want[p.ID] || (anc == is.AnchorID && e == firstNonEmptyStr(is.EntryID, model.PathEntryInternet)) {
					surviving++
					if p.Score > best {
						best = p.Score
					}
				}
			}
		}
		eval["surviving_paths"] = surviving
		eval["stored_evidence"] = map[bool]string{true: "present", false: "gone"}[surviving > 0]
		if surviving > 0 {
			eval["best_score"] = best
			eval["summary"] = fmt.Sprintf("the stored graph still yields %d path(s) to the anchor (best %.1f): a verification now would find it present unless the cloud changed since the last scan", surviving, best)
		} else {
			eval["summary"] = "no path to the anchor survives on the stored graph: a targeted re-read would be expected to confirm the fix"
		}
	} else {
		active := map[string]bool{}
		if fs, err := s.rd.Findings(store.Filter{Status: string(model.Fail)}); err == nil {
			for _, f := range fs {
				active[f.ID] = true
			}
		}
		failing := 0
		for _, fid := range is.FindingIDs {
			if active[fid] {
				failing++
			}
		}
		eval["failing_findings"] = failing
		eval["evidence_findings"] = len(is.FindingIDs)
		eval["stored_evidence"] = map[bool]string{true: "present", false: "gone"}[failing > 0]
		if failing > 0 {
			eval["summary"] = fmt.Sprintf("%d of %d evidence finding(s) are still FAIL in the stored state", failing, len(is.FindingIDs))
		} else {
			eval["summary"] = "no evidence finding is still FAIL in the stored state (resolved by a later scan): a targeted re-read would be expected to confirm the fix"
		}
	}
	if targets == nil {
		targets = []target{}
	}
	covered := 0
	for _, t := range targets {
		if t.Reader != "" {
			covered++
		}
	}
	method := "targeted re-collect"
	switch {
	case len(targets) == 0 || covered == 0:
		method = "no targeted reader covers these resources: verify needs --from-file <findings>"
	case covered < len(targets):
		method = "partial: hops without a reader make a targeted read inconclusive; use --from-file for them"
	}
	vs, err := s.rd.Verifications(is.ID)
	if err != nil {
		return nil, nil, err
	}
	if vs == nil {
		vs = []store.Verification{}
	}
	var last any
	if len(vs) > 0 {
		v := vs[len(vs)-1]
		last = map[string]any{"result": v.Result, "at": v.At, "reason": v.Reason, "verified_by": v.VerifiedBy, "reads": v.Reads,
			"confirmations": v.Confirmations, "required": v.Required}
	}
	res := map[string]any{
		"issue_id": is.ID, "kind": is.Kind, "state": string(is.State), "provider": is.Provider, "would_check": targets,
		"coverage":   map[string]any{"targeted": covered, "resources": len(targets), "method": method},
		"evaluation": eval, "last_verification": last, "verifications": vs,
		"command": "cloud-posture verify " + is.ID, "mutates": false,
		"note": "Read-only evaluation of the stored state: nothing was re-collected and the Issue, its history and any ticket are unchanged. Only `cloud-posture verify` (a human, with cloud read credentials or a findings file) records a result.",
	}
	if fileEval != nil {
		res["file_evaluation"] = fileEval
	}
	return res, nil, nil
}

// ---------------------------------------------------------------- summary

func toolSummary(ctx context.Context, s *session, args json.RawMessage) (any, *callMeta, error) {
	var a struct{}
	if err := decode(args, &a); err != nil {
		return nil, nil, err
	}
	out, err := summary(s.rd)
	return out, nil, err
}

// summary is store.Headline() (the one count source every surface prints) plus the last scan.
func summary(rd Reader) (map[string]any, error) {
	h, err := rd.Headline()
	if err != nil {
		return nil, err
	}
	out := map[string]any{"headline": h}
	if last, err := rd.LastScan(); err == nil && last != nil {
		out["last_scan"] = map[string]any{"scan_id": last.ScanID, "finished_at": last.FinishedAt, "accounts": last.Accounts, "total": last.Total}
	}
	return out, nil
}

// ---------------------------------------------------------------- resources

type resource struct {
	uri, name, description, tool string
	read                         func(s *session) (any, error)
}

var resources = []resource{
	{uri: "nimbus://schema", name: "schema", tool: "schema", description: "Tables and views readable by the sql tool, with columns.",
		read: func(s *session) (any, error) { return schema(s.rd) }},
	{uri: "nimbus://summary", name: "summary", tool: "summary", description: "Headline Issue counts (store.Headline) and the last scan.",
		read: func(s *session) (any, error) { return summary(s.rd) }},
	{uri: "nimbus://coverage", name: "coverage", tool: "coverage", description: "Collection coverage of the latest scan.",
		read: func(s *session) (any, error) { o, _, err := coverage(s.rd, ""); return o, err }},
}

func (s *session) listResources() []any {
	out := []any{}
	for _, r := range resources {
		if s.scope.Allows(r.tool) {
			out = append(out, map[string]any{"uri": r.uri, "name": r.name, "title": r.name, "description": r.description, "mimeType": "application/json"})
		}
	}
	return out
}

func (s *session) readResource(ctx context.Context, req request) {
	var p struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(req.Params, &p)
	rec := auditRecord{Method: "resources/read", URI: p.URI}
	var res *resource
	for i := range resources {
		if resources[i].uri == p.URI && s.scope.Allows(resources[i].tool) {
			res = &resources[i]
		}
	}
	if res == nil {
		rec.Outcome, rec.Error = "refused", "unknown resource or outside scope"
		if err := s.record(rec); err != nil {
			s.writeErr(req.ID, codeInternal, "audit log unavailable; refusing")
			return
		}
		s.writeErr(req.ID, codeInvalidParams, "unknown resource or outside this session's scope")
		return
	}
	v, err := res.read(s)
	var text []byte
	if err == nil {
		if s.red != nil {
			v, err = s.red.any(v, keyStored) // resources take no arguments: stored data only
		} else if v, err = roundTrip(v); err == nil {
			v = s.ids.MapValue(v)
		}
		if err == nil {
			text, err = json.Marshal(v)
		}
	}
	if err != nil {
		rec.Outcome, rec.Error = "error", err.Error()
	} else {
		rec.Outcome, rec.ResultBytes = "ok", len(text)
	}
	if aerr := s.record(rec); aerr != nil {
		s.writeErr(req.ID, codeInternal, "audit log unavailable; refusing")
		return
	}
	if err != nil {
		msg := err.Error()
		if s.red != nil {
			msg = s.red.text(msg, nil)
		}
		var te *toolError
		if errors.As(err, &te) {
			s.writeErr(req.ID, codeInvalidParams, msg)
		} else {
			s.writeErr(req.ID, codeInternal, msg)
		}
		return
	}
	s.write(response{ID: req.ID, Result: map[string]any{"contents": []any{map[string]any{"uri": res.uri, "mimeType": "application/json", "text": string(text)}}}})
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
