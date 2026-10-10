package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Verify-4 defects 1 and 2 (docs/sessions/2026-10-09-cwm-ui.md): placeholders must never resolve
// into text the client sees, and no SQL expression over a redacted column may yield the raw id.

// realSecrets are raw values in the fixture that redaction must hide in every form.
var realSecrets = []string{
	"111111111111", hostileAccount,
	"313131313131313131313131", // hex('111111111111')
	"111111",                   // substr halves
	"S01",                      // lab tag value (checked only where the query reads tags)
}

func noSecrets(t *testing.T, what string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	s := string(b)
	for _, sec := range realSecrets {
		// The lab also writes the scenario id into free-text description/attributes, which is
		// not a tag value and not redacted (documented residual).
		if sec == "S01" && !strings.Contains(what, "tags") {
			continue
		}
		if strings.Contains(s, sec) {
			t.Errorf("%s leaked %q: %.400s", what, sec, s)
		}
	}
}

func acctPlaceholder(t *testing.T, c *client) string {
	t.Helper()
	res := c.toolOK("sql", map[string]any{"query": "SELECT account FROM findings WHERE account != '' ORDER BY id LIMIT 1"})
	ph, _ := res["rows"].([]any)[0].([]any)[0].(string)
	if !strings.HasPrefix(ph, "ACCT_") {
		t.Fatalf("account placeholder %q", ph)
	}
	return ph
}

func TestRedactionErrorTextNeverResolvesPlaceholders(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{Scopes: []string{"all"}})
	c.initialize()
	ph := acctPlaceholder(t, c)
	calls := []struct {
		tool    string
		args    map[string]any
		mayPass bool // SQLite reads an unknown "double-quoted" name as a string literal
	}{
		{"draft_fix", map[string]any{"finding_id": ph}, false},
		{"issue", map[string]any{"id": ph}, false},
		{"explain", map[string]any{"id": "x-" + ph + "-y"}, false},
		{"simulate_fix", map[string]any{"fixes": []any{map[string]any{"node_id": "arn:aws:iam::" + ph + ":role/nope", "weakness": "X"}}}, false},
		{"simulate_fix", map[string]any{"fixes": []any{map[string]any{"edge": map[string]any{"from": "arn:aws:iam::" + ph + ":role/a", "to": "b", "kind": "k"}}}}, false},
		{"sql", map[string]any{"query": `SELECT * FROM "` + ph + `"`}, false},
		{"sql", map[string]any{"query": `SELECT "` + ph + `" FROM findings`}, true},
		{"sql", map[string]any{"query": `SELECT * FROM findings WHERE ` + ph + ` = 1`}, false},
	}
	for _, cl := range calls {
		tr, r := c.tool(cl.tool, cl.args)
		if r.Error != nil {
			noSecrets(t, cl.tool+" rpc error", r.Error)
			continue
		}
		noSecrets(t, cl.tool+" result", tr.Content)
		if !tr.IsError {
			if !cl.mayPass {
				t.Errorf("%s %v: expected an error, got %v", cl.tool, cl.args, tr.Structured)
			}
			continue
		}
		if !strings.Contains(tr.Content[0].Text, ph) {
			t.Errorf("%s: error should name the placeholder %s: %s", cl.tool, ph, tr.Content[0].Text)
		}
	}
	// the raw line on the wire, not just the decoded struct
	for _, line := range c.raw {
		for _, sec := range realSecrets[:2] {
			if strings.Contains(line, sec) {
				t.Errorf("wire leaked %q: %.300s", sec, line)
			}
		}
	}
}

// The verifier's bypass corpus (scratchpad/verify-4/probes/mcp_redact.py).
var bypassQueries = []string{
	"SELECT account, resource_id FROM findings WHERE account!='' LIMIT 1",
	"SELECT hex(account) AS h FROM findings WHERE account!='' LIMIT 1",
	"SELECT substr(account,1,6) AS a, substr(account,7) AS b FROM findings WHERE account!='' LIMIT 1",
	"SELECT CAST(account AS INTEGER) AS n FROM findings WHERE account!='' LIMIT 1",
	"SELECT account || 'x' AS s FROM findings WHERE account!='' LIMIT 1",
	"SELECT 'x' || account AS s FROM findings WHERE account!='' LIMIT 1",
	"SELECT replace(account,'1','1 ') AS s FROM findings WHERE account!='' LIMIT 1",
	"SELECT unicode(substr(account,1,1)) AS c, unicode(substr(account,2,1)) AS d FROM findings WHERE account!='' LIMIT 1",
	"SELECT instr(resource_id,'111111111111') AS p FROM findings WHERE account!='' LIMIT 1",
	"SELECT group_concat(account,'') AS g FROM (SELECT account FROM findings WHERE account!='' LIMIT 2)",
	"SELECT account+0 AS n FROM findings WHERE account!='' LIMIT 1",
	"SELECT quote(account) AS q FROM findings WHERE account!='' LIMIT 1",
	"SELECT tags AS t FROM findings WHERE tags NOT IN ('','{}','null') LIMIT 1",
	"SELECT tags AS x FROM findings WHERE tags NOT IN ('','{}','null') LIMIT 1",
	"SELECT json_extract(tags,'$') AS j FROM findings WHERE tags NOT IN ('','{}','null') LIMIT 1",
	"SELECT j.value AS v FROM findings, json_each(findings.tags) j WHERE tags NOT IN ('','{}','null') LIMIT 5",
	"SELECT upper(resource_id) AS r FROM findings WHERE resource_id LIKE 'arn:aws:iam::%' LIMIT 1",
	"SELECT replace(resource_id,':','/') AS r FROM findings WHERE resource_id LIKE 'arn:aws:%' LIMIT 1",
	"SELECT replace(resource_id,':','') AS r FROM findings LIMIT 50",
	"SELECT account AS acc FROM findings WHERE account!='' LIMIT 1",
	"SELECT a AS title FROM (SELECT hex(account) AS a FROM findings LIMIT 1)",
	"SELECT f.account || '' AS t FROM findings AS f LIMIT 1",
	"WITH x AS (SELECT account FROM findings) SELECT substr(account, 1, 12) AS t FROM x LIMIT 1",
	"WITH RECURSIVE x(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM x WHERE n<2) SELECT substr(f.account,n,11) AS t FROM x, findings f LIMIT 2",
	"SELECT account || '' AS t FROM 'findings' LIMIT 1",
	"SELECT substr(doc, 1, 400) AS t FROM scans",
	"SELECT json_extract(doc, '$.accounts') AS t, json_extract(doc, '$.accounts[0]') || '' AS u FROM scans",
	"SELECT substr(account,1,12) AS t FROM coverage LIMIT 1",
	"SELECT substr(id, 1, 200) AS t FROM graph_nodes WHERE id LIKE 'arn:aws:iam::%' LIMIT 1",
	"SELECT replace(doc, ':', '') AS t FROM graph_nodes LIMIT 5",
	"SELECT replace(attr, ':', '') AS t FROM graph_edges LIMIT 5",
	"SELECT substr(account,1,12) || '' AS t FROM attack_paths LIMIT 1",
	"SELECT substr(account,1,12) || '' AS t FROM issues WHERE account != '' LIMIT 1",
	"SELECT * FROM findings LIMIT 3",
	"SELECT tags, json_extract(doc, '$.tags') AS t2 FROM findings WHERE tags LIKE '%lab%' LIMIT 3",
}

func TestRedactionSurvivesComputedSQL(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{Scopes: []string{"all"}})
	c.initialize()
	ok := 0
	for _, q := range bypassQueries {
		tr, r := c.tool("sql", map[string]any{"query": q})
		if r.Error != nil {
			noSecrets(t, q, r.Error)
			continue
		}
		if tr.IsError {
			noSecrets(t, q, tr.Content)
			continue
		}
		ok++
		noSecrets(t, q, tr.Structured)
		noSecrets(t, q, tr.Content)
		// unicode() of the first two characters must not be digits of the id
		if strings.HasPrefix(q, "SELECT unicode") {
			row := tr.Structured["rows"].([]any)[0].([]any)
			if row[0] == float64('1') && row[1] == float64('1') {
				t.Errorf("unicode() oracle reads the raw id: %v", row)
			}
		}
	}
	if ok < len(bypassQueries) {
		t.Errorf("only %d/%d bypass queries ran; redaction must not break ordinary SQL", ok, len(bypassQueries))
	}
	// schema-qualified access to the raw table is refused
	for _, q := range []string{"SELECT account FROM main.findings", `SELECT account FROM "main"."findings"`,
		"SELECT account FROM 'main'.findings", "SELECT account FROM [main].findings", "SELECT nimbus_redact('a','b','c')"} {
		tr, r := c.tool("sql", map[string]any{"query": q})
		if r.Error == nil && !tr.IsError {
			t.Errorf("%q accepted: %v", q, tr.Structured)
		}
		noSecrets(t, q, tr)
	}
}

// A LIKE yes/no oracle returns the same answer for every guess.
func TestRedactionLikeOracleIsBlind(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{Scopes: []string{"all"}})
	c.initialize()
	count := func(q string) float64 {
		res := c.toolOK("sql", map[string]any{"query": q})
		return res["rows"].([]any)[0].([]any)[0].(float64)
	}
	var answers []float64
	for _, g := range []string{"1111%", "2222%", "9%", "%1111%", "%2222%", "1%"} {
		answers = append(answers, count("SELECT count(*) FROM findings WHERE account LIKE '"+g+"'"))
		answers = append(answers, count("SELECT count(*) FROM coverage WHERE account LIKE '"+g+"'"))
	}
	// ids embedded in ARNs / node ids: a guess of the full id or a long prefix never matches
	for _, g := range []string{"111111111111", "222233334444", "1111111", "::1111", "::2222"} {
		answers = append(answers, count("SELECT count(*) FROM findings WHERE resource_id LIKE '%"+g+"%'"))
		answers = append(answers, count("SELECT count(*) FROM graph_nodes WHERE id LIKE '%"+g+"%' OR doc LIKE '%"+g+"%'"))
		answers = append(answers, count("SELECT count(*) FROM graph_edges WHERE from_id LIKE '%"+g+"%' OR attr LIKE '%"+g+"%'"))
	}
	for i, a := range answers {
		if a != 0 {
			t.Errorf("guess %d matched %v rows: a LIKE oracle over a redacted id must not match raw digits", i, a)
		}
	}
	if n := count("SELECT count(*) FROM findings WHERE account = '111111111111'"); n != 0 {
		t.Errorf("raw equality oracle matched %v", n)
	}
	// A raw id passed to a non-sql tool would be compared with real data (an oracle): refused.
	for _, raw := range []string{"111111111111", hostileAccount, "arn:aws:iam::111111111111:role/x"} {
		tr, r := c.tool("paths", map[string]any{"account": raw})
		if r.Error == nil && !tr.IsError {
			t.Errorf("paths account=%q accepted in a redacted session: matched=%v", raw, tr.Structured["matched"])
		}
		tr, r = c.tool("simulate_fix", map[string]any{"fixes": []any{map[string]any{"node_id": raw, "weakness": "X"}}})
		if r.Error == nil && !tr.IsError {
			t.Errorf("simulate_fix node %q accepted", raw)
		}
		noSecrets(t, "raw arg refusal", tr.Content)
	}
	// placeholders still work as inputs
	ph := acctPlaceholder(t, c)
	if n := count("SELECT count(*) FROM findings WHERE account = '" + ph + "'"); n == 0 {
		t.Errorf("placeholder equality matched nothing")
	}
	if ps := variantsOf(c.toolOK("paths", map[string]any{"account": ph})); len(ps) == 0 {
		t.Errorf("placeholder account filter matched nothing")
	}
}

// The audit file must not follow a symlink planted at its path (verify-4 LOW).
func TestAuditRefusesSymlink(t *testing.T) {
	fx := newFixture(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "mcp-audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, err := openAudit(link); err == nil {
		t.Errorf("openAudit followed a symlink")
	}
	_ = fx
	b, _ := os.ReadFile(target)
	st, _ := os.Stat(target)
	if string(b) != "keep\n" || st.Mode().Perm() != 0o644 {
		t.Errorf("symlink target modified: %q %v", b, st.Mode().Perm())
	}
}
