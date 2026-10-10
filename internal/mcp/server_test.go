package mcp

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var allTools = []string{"coverage", "draft_fix", "explain", "issue", "paths", "prioritize", "schema", "simulate_fix", "sql", "summary", "verify", "who_can"}

func sorted(s []string) []string { s = append([]string{}, s...); sort.Strings(s); return s }

func TestInitializeAndToolsList(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	r := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t"}})
	var init struct {
		ProtocolVersion string                `json:"protocolVersion"`
		Capabilities    map[string]any        `json:"capabilities"`
		ServerInfo      struct{ Name string } `json:"serverInfo"`
		Instructions    string                `json:"instructions"`
	}
	json.Unmarshal(r.Result, &init)
	if init.ProtocolVersion != "2025-06-18" || init.Capabilities["tools"] == nil || init.Capabilities["resources"] == nil || init.ServerInfo.Name != "nimbus" {
		t.Fatalf("initialize: %s", r.Result)
	}
	if !strings.Contains(init.Instructions, "read-only") {
		t.Errorf("instructions should state the trust boundary: %q", init.Instructions)
	}
	// unknown protocol version → server's latest
	r2 := c.call("initialize", map[string]any{"protocolVersion": "1999-01-01"})
	json.Unmarshal(r2.Result, &init)
	if init.ProtocolVersion != LatestProtocolVersion {
		t.Errorf("negotiated %q", init.ProtocolVersion)
	}

	lr := c.call("tools/list", map[string]any{})
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
			Annotations struct {
				ReadOnly    *bool `json:"readOnlyHint"`
				Destructive *bool `json:"destructiveHint"`
				OpenWorld   *bool `json:"openWorldHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(lr.Result, &list); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range list.Tools {
		names = append(names, tl.Name)
		if tl.InputSchema["type"] != "object" || tl.Description == "" {
			t.Errorf("%s: bad schema/description", tl.Name)
		}
		a := tl.Annotations
		if a.ReadOnly == nil || !*a.ReadOnly || a.Destructive == nil || *a.Destructive || a.OpenWorld == nil || *a.OpenWorld {
			t.Errorf("%s: annotations must say readOnly, not destructive, closed world", tl.Name)
		}
	}
	if !reflect.DeepEqual(sorted(names), allTools) {
		t.Fatalf("tools = %v, want %v", names, allTools)
	}
}

func TestProtocolErrors(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	if r := c.call("tools/list", map[string]any{}); r.Error == nil || r.Error.Code != codeNotInitialized {
		t.Errorf("tools/list before initialize: %+v", r.Error)
	}
	c.initialize()
	c.sendRaw("{not json")
	if r := c.read(); r.Error == nil || r.Error.Code != codeParseError || string(r.ID) != "null" {
		t.Errorf("parse error: %+v id=%s", r.Error, r.ID)
	}
	c.sendRaw(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if r := c.read(); r.Error == nil || r.Error.Code != codeInvalidRequest {
		t.Errorf("batch must be refused: %+v", r.Error)
	}
	if r := c.call("tools/write", map[string]any{}); r.Error == nil || r.Error.Code != codeMethodNotFound {
		t.Errorf("unknown method: %+v", r.Error)
	}
	if r := c.call("ping", nil); r.Error != nil || string(r.Result) != "{}" {
		t.Errorf("ping: %s %+v", r.Result, r.Error)
	}
	if _, r := c.tool("no_such_tool", nil); r.Error == nil || r.Error.Code != codeInvalidParams {
		t.Errorf("unknown tool: %+v", r.Error)
	}
	// a notification gets no response: the next response is for the ping
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	if r := c.call("ping", nil); r.Error != nil {
		t.Errorf("ping after notification: %+v", r.Error)
	}
}

func TestScopeFiltersListAndRefusesCalls(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"read"}})
	c.initialize()
	got := sorted(c.toolNames())
	want := []string{"coverage", "explain", "issue", "paths", "prioritize", "schema", "sql", "summary", "verify", "who_can"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("read scope tools = %v", got)
	}
	f := fx.hostiles[0]
	for _, name := range []string{"draft_fix", "simulate_fix"} {
		if _, r := c.tool(name, map[string]any{"finding_id": f.ID}); r.Error == nil || r.Error.Code != codeInvalidParams {
			t.Errorf("%s outside scope was not refused: %+v", name, r.Error)
		}
	}
	recs := readAudit(t, c.audit)
	refused := 0
	for _, a := range recs {
		if a.Outcome == "refused" {
			refused++
			if a.Tool != "draft_fix" && a.Tool != "simulate_fix" {
				t.Errorf("unexpected refusal %+v", a)
			}
		}
	}
	if refused != 2 {
		t.Errorf("refusals audited = %d, want 2", refused)
	}

	c2 := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"sql"}})
	c2.initialize()
	if got := sorted(c2.toolNames()); !reflect.DeepEqual(got, []string{"schema", "sql"}) {
		t.Errorf("sql scope tools = %v", got)
	}
	// resources follow the same scope
	r := c2.call("resources/read", map[string]any{"uri": "nimbus://coverage"})
	if r.Error == nil {
		t.Errorf("coverage resource readable outside scope")
	}

	if _, err := ParseScopes([]string{"read", "write"}); err == nil {
		t.Errorf("unknown scope 'write' accepted")
	}
	if s, _ := ParseScopes(nil); !reflect.DeepEqual(sorted(s.Tools()), readToolsWant) || strings.Join(s.Names(), ",") != "read" {
		t.Errorf("default scope = %v %v, want read", s.Names(), s.Tools())
	}
}

func TestSQLToolUsesHardenedPath(t *testing.T) {
	fx := newFixture(t)
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{NoRedact: true, SQLTimeout: 400 * time.Millisecond, MaxRows: 50})
	c.initialize()
	q := "SELECT id, title FROM findings WHERE account = '" + hostileAccount + "' ORDER BY id"
	res := c.toolOK("sql", map[string]any{"query": q})
	if res["sql"] != q || len(res["columns"].([]any)) != 2 || len(res["rows"].([]any)) != len(hostile) {
		t.Fatalf("sql result %v", res)
	}
	res = c.toolOK("sql", map[string]any{"query": "SELECT id FROM findings", "max_rows": 3})
	if len(res["rows"].([]any)) != 3 || res["truncated"] != true {
		t.Errorf("max_rows: %v", res)
	}
	res = c.toolOK("sql", map[string]any{"query": "SELECT id FROM findings", "max_rows": 100000})
	if len(res["rows"].([]any)) > 50 {
		t.Errorf("server row cap ignored: %d rows", len(res["rows"].([]any)))
	}
	start := time.Now()
	tr, _ := c.tool("sql", map[string]any{"query": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c"})
	if !tr.IsError || !strings.Contains(strings.ToLower(tr.Content[0].Text), "timeout") || time.Since(start) > 5*time.Second {
		t.Errorf("runaway CTE not stopped at the timeout: %v after %s", tr.Content, time.Since(start))
	}

	// internal/query/security_test.go TestReadOnlyGuardBlocksBypasses (14 payloads) plus the
	// virtual-table and lexer payloads from internal/store/readonly_test.go.
	evil := filepath.Join(t.TempDir(), "evil.db")
	corpus := []string{
		"WITH x AS (SELECT 1)\nDELETE FROM findings",
		"SELECT '--';DELETE FROM findings",
		"SELECT '--';CREATE TABLE pwned(x)",
		"ATTACH DATABASE '" + evil + "' AS evil",
		"SELECT 1; ATTACH DATABASE '" + evil + "' AS evil",
		"PRAGMA writable_schema=1",
		"SELECT * FROM pragma_table_info('findings')",
		"SELECT sql FROM sqlite_master",
		`SELECT sql FROM "sqlite_schema"`,
		"SELECT * FROM sqlite_temp_master",
		"SELECT name FROM main.sqlite_master",
		"SELECT sql FROM 'sqlite_master'",
		"REPLACE INTO findings(id) VALUES('x')",
		"SELECT 1 /* ; */ ; DELETE FROM findings",
		// store/readonly_test.go
		"", ";", "SELECT 1; SELECT 2", "SELECT * FROM [sqlite_master]", "SELECT * FROM `sqlite_schema`",
		"SELECT * FROM pragma_table_list", "SELECT 'unterminated", "EXPLAIN SELECT 1", "PRAGMA query_only=0",
		"SELECT * FROM dbstat", "SELECT * FROM dbstat AS json_each", "SELECT * FROM sqlite_dbpage", "SELECT * FROM fts5vocab",
		"VACUUM INTO '" + evil + "'",
	}
	if len(corpus) != 28 {
		t.Fatalf("corpus size %d", len(corpus))
	}
	for _, p := range corpus {
		tr, r := c.tool("sql", map[string]any{"query": p})
		if r.Error != nil {
			t.Errorf("%q: rpc error %+v (want tool error)", p, r.Error)
		} else if !tr.IsError {
			t.Errorf("payload accepted via MCP: %q -> %v", p, tr.Structured)
		}
	}
	if _, err := os.Stat(evil); err == nil {
		t.Errorf("payload created %s", evil)
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Errorf("database changed by sql tool")
	}
}

func TestPathsTool(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c.initialize()
	res := c.toolOK("paths", map[string]any{"limit": 200})
	paths := variantsOf(res)
	if len(paths) != len(fx.an.Paths)+1 {
		t.Fatalf("paths = %d, want %d", len(paths), len(fx.an.Paths)+1)
	}
	withBecause := 0
	for _, p := range paths {
		pm := p.(map[string]any)
		for _, k := range []string{"id", "name", "score", "band", "severity", "provider", "account", "hops"} {
			if _, ok := pm[k]; !ok {
				t.Fatalf("path missing %s: %v", k, pm)
			}
		}
		for _, h := range pm["hops"].([]any) {
			hm := h.(map[string]any)
			if _, ok := hm["because"]; !ok {
				t.Fatalf("hop missing because: %v", hm)
			}
			if hm["because"] != "" {
				withBecause++
			}
		}
	}
	if withBecause == 0 {
		t.Error("no hop carries a because")
	}
	// filters
	for _, tc := range []struct {
		args map[string]any
		ok   func(map[string]any) bool
	}{
		{map[string]any{"account": hostileAccount}, func(p map[string]any) bool { return p["account"] == hostileAccount }},
		{map[string]any{"band": "critical"}, func(p map[string]any) bool { return p["band"] == "Critical" }},
		{map[string]any{"severity": "HIGH"}, func(p map[string]any) bool { return p["severity"] == "HIGH" }},
		{map[string]any{"provider": "aws", "min_score": 9.0}, func(p map[string]any) bool { return p["provider"] == "aws" && p["score"].(float64) >= 9 }},
	} {
		got := variantsOf(c.toolOK("paths", tc.args))
		if len(got) == 0 {
			t.Errorf("%v: no paths", tc.args)
		}
		for _, p := range got {
			if !tc.ok(p.(map[string]any)) {
				t.Errorf("%v: filter leaked %v", tc.args, p.(map[string]any)["id"])
			}
		}
	}
	// a filter value is compared as data, never spliced into SQL
	if got := variantsOf(c.toolOK("paths", map[string]any{"account": "x' OR '1'='1"})); len(got) != 0 {
		t.Errorf("injection in filter matched %d paths", len(got))
	}
	if got := c.toolOK("paths", map[string]any{"limit": 2})["issues"].([]any); len(got) != 2 {
		t.Errorf("limit: %d", len(got))
	}
	if tr, _ := c.tool("paths", map[string]any{"band": "apocalyptic"}); !tr.IsError {
		t.Errorf("bad band accepted")
	}
}

func TestIssueExplainCoverageSchema(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c.initialize()
	issues, err := fx.st.Issues(storeIssueFilterAll())
	if err != nil {
		t.Fatal(err)
	}
	var pathIssue, single *model.Issue
	for i := range issues {
		switch issues[i].Kind {
		case model.IssuePath:
			if pathIssue == nil {
				pathIssue = &issues[i]
			}
		case model.IssueSingle:
			if single == nil {
				single = &issues[i]
			}
		}
	}
	if pathIssue == nil || single == nil {
		t.Fatalf("fixture lacks path/single issues")
	}
	res := c.toolOK("issue", map[string]any{"id": pathIssue.ID})
	if res["issue"].(map[string]any)["id"] != pathIssue.ID || len(res["history"].([]any)) == 0 || len(res["variants"].([]any)) == 0 {
		t.Errorf("path issue: %v", res)
	}
	res = c.toolOK("issue", map[string]any{"id": single.ID})
	ev := res["evidence"].([]any)
	if len(ev) == 0 {
		t.Fatalf("single issue without evidence findings")
	}
	if _, ok := ev[0].(map[string]any)["raw"]; ok {
		t.Errorf("raw provider JSON leaked in evidence")
	}
	if tr, _ := c.tool("issue", map[string]any{"id": "nope"}); !tr.IsError {
		t.Errorf("unknown issue not an error")
	}
	if tr, _ := c.tool("issue", map[string]any{}); !tr.IsError {
		t.Errorf("missing id not an error")
	}

	ex := c.toolOK("explain", map[string]any{"id": single.FindingIDs[0]})
	exps := ex["explanations"].([]any)
	if len(exps) != 1 {
		t.Fatalf("explain: %v", ex)
	}
	e0 := exps[0].(map[string]any)
	if len(e0["factors"].([]any)) == 0 || e0["band"] == "" {
		t.Errorf("explain lacks factors: %v", e0)
	}
	if ex2 := c.toolOK("explain", map[string]any{"id": single.ID}); len(ex2["explanations"].([]any)) == 0 {
		t.Errorf("explain by issue id: %v", ex2)
	}

	cov := c.toolOK("coverage", map[string]any{})
	if len(cov["entries"].([]any)) != 2 || cov["by_status"].(map[string]any)["denied"] != 1.0 {
		t.Errorf("coverage: %v", cov)
	}
	sch := c.toolOK("schema", map[string]any{})
	tables := sch["tables"].(map[string]any)
	if _, ok := tables["findings"]; !ok {
		t.Errorf("schema lacks findings: %v", tables)
	}
	for name := range tables {
		if strings.HasPrefix(name, "sqlite_") {
			t.Errorf("schema lists internal table %s", name)
		}
	}
}

func TestSimulateFixNeverApplies(t *testing.T) {
	fx := newFixture(t)
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{NoRedact: true, Traversal: labTraversal, Scopes: []string{"all"}})
	c.initialize()
	if len(fx.an.MinFixSet) == 0 {
		t.Fatal("fixture has no min fix set")
	}
	fix := fx.an.MinFixSet[0]
	res := c.toolOK("simulate_fix", map[string]any{"fixes": []any{map[string]any{"node_id": fix.NodeID, "weakness": fix.Weakness}}})
	if res["applied"] != false || res["resolves"].(float64) < 1 || res["remaining_score"].(float64) >= res["total_score"].(float64) {
		t.Errorf("simulate: %v", res)
	}
	res = c.toolOK("simulate_fix", map[string]any{"min_fix_set": true})
	if res["resolves"].(float64) < 1 {
		t.Errorf("min fix set resolves nothing: %v", res)
	}
	if tr, _ := c.tool("simulate_fix", map[string]any{"fixes": []any{map[string]any{"node_id": "nope", "weakness": "X"}}}); !tr.IsError {
		t.Errorf("unknown node accepted")
	}
	if tr, _ := c.tool("simulate_fix", map[string]any{}); !tr.IsError {
		t.Errorf("empty simulate accepted")
	}
	// a second traversal sees the same graph: nothing was applied
	again := c.toolOK("simulate_fix", map[string]any{"fixes": []any{map[string]any{"node_id": fix.NodeID, "weakness": fix.Weakness}}})
	if again["total_score"] != res["total_score"] {
		t.Errorf("graph changed between simulations")
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Errorf("simulate_fix changed the database")
	}
}

func TestDraftFixNeverWrites(t *testing.T) {
	fx := newFixture(t)
	work := t.TempDir()
	wd, _ := os.Getwd()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{NoRedact: true, AuditPath: filepath.Join(t.TempDir(), "a.jsonl"), Scopes: []string{"all"}})
	c.initialize()
	f := fx.hostiles[4] // title "'); DROP TABLE findings; --"
	for _, format := range []string{"terraform", "cloudformation", "bicep", ""} {
		res := c.toolOK("draft_fix", map[string]any{"finding_id": f.ID, "format": format})
		if res["applied"] != false || res["content"] == "" || !strings.HasPrefix(res["diff"].(string), "--- /dev/null\n+++ b/") {
			t.Errorf("%s: %v", format, res)
		}
		if _, ok := res["finding"]; ok {
			t.Errorf("draft_fix echoes the whole finding")
		}
	}
	if tr, _ := c.tool("draft_fix", map[string]any{"finding_id": f.ID, "format": "pulumi"}); !tr.IsError {
		t.Errorf("bad format accepted")
	}
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Errorf("draft_fix wrote files: %v", entries)
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Errorf("draft_fix changed the database")
	}
}

func TestResources(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c.initialize()
	r := c.call("resources/list", map[string]any{})
	var list struct {
		Resources []struct{ URI string } `json:"resources"`
	}
	json.Unmarshal(r.Result, &list)
	var uris []string
	for _, x := range list.Resources {
		uris = append(uris, x.URI)
	}
	if !reflect.DeepEqual(sorted(uris), []string{"nimbus://coverage", "nimbus://schema", "nimbus://summary"}) {
		t.Fatalf("resources %v", uris)
	}
	for _, u := range uris {
		r := c.call("resources/read", map[string]any{"uri": u})
		var rr struct {
			Contents []struct{ URI, MimeType, Text string } `json:"contents"`
		}
		json.Unmarshal(r.Result, &rr)
		if r.Error != nil || len(rr.Contents) != 1 || rr.Contents[0].MimeType != "application/json" || !json.Valid([]byte(rr.Contents[0].Text)) {
			t.Errorf("%s: %+v %s", u, r.Error, r.Result)
		}
	}
	if r := c.call("resources/read", map[string]any{"uri": "file:///etc/passwd"}); r.Error == nil {
		t.Errorf("arbitrary resource uri accepted")
	}
}

// Read-only by construction: tools see only the Reader interface, whose method set has no
// write-shaped method, and a full session over every tool leaves the database byte-identical.
func TestReadOnlyByConstruction(t *testing.T) {
	writeish := regexp.MustCompile(`^(Upsert|Apply|Replace|Rebuild|Suppress|Mark|Save|Record|Exec|Delete|Insert|Update|Set|Write|Purge|Close|DB)`)
	rt := reflect.TypeOf((*Reader)(nil)).Elem()
	for i := 0; i < rt.NumMethod(); i++ {
		if m := rt.Method(i).Name; writeish.MatchString(m) {
			t.Errorf("Reader exposes write-shaped method %s", m)
		}
	}
	fx := newFixture(t)
	before := dbDigest(t, fx.st)
	c := startServer(t, fx.st, Options{Traversal: labTraversal, Scopes: []string{"all"}}) // redaction on (default)
	c.initialize()
	issues, _ := fx.st.Issues(storeIssueFilterAll())
	f := fx.hostiles[0]
	c.toolOK("sql", map[string]any{"query": "SELECT count(*) FROM findings"})
	c.toolOK("paths", map[string]any{})
	c.toolOK("issue", map[string]any{"id": issues[0].ID})
	c.toolOK("explain", map[string]any{"id": fx.st.ExternalFindingID(f.ID)})
	c.toolOK("simulate_fix", map[string]any{"min_fix_set": true})
	c.toolOK("draft_fix", map[string]any{"finding_id": fx.st.ExternalFindingID(f.ID)})
	c.toolOK("coverage", map[string]any{})
	c.toolOK("schema", map[string]any{})
	for _, u := range []string{"nimbus://schema", "nimbus://summary", "nimbus://coverage"} {
		c.call("resources/read", map[string]any{"uri": u})
	}
	if after := dbDigest(t, fx.st); after != before {
		t.Errorf("a tool wrote to the database")
	}
}

func TestAuditJSONL(t *testing.T) {
	fx := newFixture(t)
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "mcp-audit.jsonl")
	c := startServer(t, fx.st, Options{NoRedact: true, AuditPath: path})
	c.initialize()
	c.toolOK("sql", map[string]any{"query": "SELECT 1 AS one"})
	c.tool("sql", map[string]any{"query": "DELETE FROM findings"})
	c.toolOK("coverage", map[string]any{})
	recs := readAudit(t, path)
	var calls []auditRecord
	for _, r := range recs {
		if r.Method == "tools/call" {
			calls = append(calls, r)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("audit calls = %d: %+v", len(calls), recs)
	}
	if calls[0].Tool != "sql" || calls[0].Outcome != "ok" || calls[0].SQL != "SELECT 1 AS one" || calls[0].Rows != 1 || calls[0].Session == "" {
		t.Errorf("record 0: %+v", calls[0])
	}
	if calls[1].Outcome != "error" || calls[1].Error == "" {
		t.Errorf("record 1: %+v", calls[1])
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("audit mode %v", st.Mode().Perm())
	}
	if ds, _ := os.Stat(dir); ds.Mode().Perm() != 0o700 {
		t.Errorf("audit dir mode %v", ds.Mode().Perm())
	}
	if DefaultAuditPath("/x/y/posture.db") != filepath.Join("/x/y", "mcp-audit.jsonl") {
		t.Errorf("default audit path %s", DefaultAuditPath("/x/y/posture.db"))
	}
}

func readAudit(t *testing.T, path string) []auditRecord {
	t.Helper()
	// the server writes the record before it writes the response, so it is on disk already
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []auditRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r auditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad audit line %q", sc.Text())
		}
		out = append(out, r)
	}
	return out
}

func TestOverlongLineKeepsStreamInSync(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c.initialize()
	c.sendRaw(`{"jsonrpc":"2.0","id":7,"method":"ping","params":{"pad":"` + strings.Repeat("A", maxLineBytes) + `"}}`)
	if r := c.read(); r.Error == nil || r.Error.Code != codeInvalidRequest {
		t.Errorf("overlong line: %+v", r.Error)
	}
	if r := c.call("ping", nil); r.Error != nil {
		t.Errorf("stream out of sync after overlong line: %+v", r.Error)
	}
}

func TestEscapeFormatRunes(t *testing.T) {
	in := "a\u202Eb\u200Bc\uFEFFd\U000E0001e"
	b, _ := encodeFrame(map[string]string{"s": in})
	for _, r := range string(b) {
		if r > 0x7f {
			t.Fatalf("non-ASCII rune %U left in %s", r, b)
		}
	}
	var back map[string]string
	if err := json.Unmarshal(b, &back); err != nil || back["s"] != in {
		t.Fatalf("round trip: %q %v", back["s"], err)
	}
}
