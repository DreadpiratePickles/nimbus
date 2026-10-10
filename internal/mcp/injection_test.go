package mcp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
)

// TestInjectionCorpus: cloud-controlled strings (titles, names, tags, descriptions, path text)
// containing prompt-injection text, tool markers, JSON-RPC frames and unicode tricks pass through
// as data. They never add a message to the stream, never appear as raw markup, never change the
// tool list or the SQL that runs, and the audit log shows only the calls the client made.
func TestInjectionCorpus(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{NoRedact: true, Scopes: []string{"all"}})
	c.initialize()
	listBefore := c.call("tools/list", map[string]any{}).Result

	requested := []string{}
	call := func(name string, args map[string]any) map[string]any {
		requested = append(requested, name)
		return c.toolOK(name, args)
	}

	// 1. sql: the hostile strings come back byte-for-byte; the SQL echoed is the SQL sent.
	q := "SELECT title, description, resource_name, tags FROM findings WHERE account = '" + hostileAccount + "' ORDER BY check_id"
	res := call("sql", map[string]any{"query": q})
	if res["sql"] != q {
		t.Errorf("sql changed: %q", res["sql"])
	}
	got := map[string]bool{}
	for _, r := range res["rows"].([]any) {
		row := r.([]any)
		got[row[0].(string)] = true
		if row[0] != row[1] || row[0] != row[2] {
			t.Errorf("hostile title/description/name altered: %q", row)
		}
	}
	for _, h := range hostile {
		if !got[h] {
			t.Errorf("hostile title not returned verbatim: %q", h)
		}
	}

	// 2. paths: hostile name/impact/narrative/hop text are returned as data.
	// (the traversal also builds real paths over the hostile buckets, so their generated
	// narrative and because text embed the hostile names too)
	ps := variantsOf(call("paths", map[string]any{"account": hostileAccount, "limit": 200}))
	var hp map[string]any
	for _, p := range ps {
		if p.(map[string]any)["id"] == "hostile-path" {
			hp = p.(map[string]any)
		}
	}
	if len(ps) < 2 || hp == nil || hp["name"] != hostile[0] {
		t.Fatalf("hostile path: %v", ps)
	}
	hop0 := hp["hops"].([]any)[0].(map[string]any)
	if hop0["because"] != hostile[5] || hop0["title"] != hostile[0] {
		t.Errorf("hop text altered: %v", hop0)
	}

	// 3. issue / explain / draft_fix over each hostile finding.
	for _, f := range fx.hostiles {
		ex := call("explain", map[string]any{"id": f.ID})
		e := ex["explanations"].([]any)[0].(map[string]any)
		if e["title"] != f.Title {
			t.Errorf("explain title altered: %q", e["title"])
		}
		d := call("draft_fix", map[string]any{"finding_id": f.ID})
		if d["applied"] != false {
			t.Errorf("draft_fix applied")
		}
	}

	// The stream: one line per response, valid JSON, with no raw markup or line terminators from
	// the data (encoding/json escapes <, >, &, U+2028, U+2029; the server escapes format runes).
	for _, line := range c.raw {
		body := strings.TrimSuffix(line, "\n")
		if strings.ContainsAny(body, "\n\r<>") || strings.Contains(body, "\u2028") || strings.Contains(body, "\u2029") {
			t.Errorf("raw markup or line break in stream: %.200q", body)
		}
		for _, r := range body {
			if unicode.Is(unicode.Cf, r) {
				t.Errorf("unescaped format rune %U in stream", r)
				break
			}
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Errorf("invalid frame: %v", err)
		}
		if v["method"] != nil {
			t.Errorf("server emitted a request/notification: %.200q", body)
		}
	}
	// text content repeats the data under an untrusted-data banner
	tr, _ := c.tool("sql", map[string]any{"query": q})
	requested = append(requested, "sql")
	if !strings.HasPrefix(tr.Content[0].Text, untrustedBanner) {
		t.Errorf("text content lacks the untrusted-data banner: %.120q", tr.Content[0].Text)
	}

	// Tool selection is unchanged and the audit holds exactly what the client asked for.
	if listAfter := c.call("tools/list", map[string]any{}).Result; string(listAfter) != string(listBefore) {
		t.Errorf("tools/list changed after reading hostile data")
	}
	var audited []string
	for _, r := range readAudit(t, c.audit) {
		if r.Method == "tools/call" {
			audited = append(audited, r.Tool)
		}
	}
	if !reflect.DeepEqual(audited, requested) {
		t.Errorf("audited tools %v != requested %v", audited, requested)
	}
	if n := countFindings(t, fx); n != len(labFindings(t))+len(hostile) {
		t.Errorf("findings count %d after hostile session", n)
	}
}

func countFindings(t *testing.T, fx *fixture) int {
	t.Helper()
	var n int
	if err := fx.st.DB().QueryRow("SELECT count(*) FROM findings").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRedaction: by default account ids, ARN account segments, IPv4 addresses and tag values
// leave the server as stable session placeholders. Placeholders the client sends back work as
// inputs: in SQL they match the redacted columns (SQL is never re-hydrated, sqlview.go); in tool
// filters they are re-hydrated before the tool runs.
func TestRedaction(t *testing.T) {
	fx := newFixture(t)
	c := startServer(t, fx.st, Options{Scopes: []string{"all"}})
	c.initialize()
	if n := c.toolOK("sql", map[string]any{"query": "SELECT count(*) FROM findings WHERE account = '111111111111'"})["rows"].([]any)[0].([]any)[0].(float64); n != 0 {
		t.Errorf("a raw id in SQL must match nothing (columns are redacted), matched %v", n)
	}
	res := c.toolOK("sql", map[string]any{"query": "SELECT account, resource_id, '10.1.2.3' AS ip, tags FROM findings WHERE resource_id LIKE 'arn:aws:iam::%' LIMIT 3"})
	blob, _ := json.Marshal(res)
	for _, secret := range []string{"111111111111", "10.1.2.3", "S01"} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("%q leaked: %s", secret, blob)
		}
	}
	row := res["rows"].([]any)[0].([]any)
	ph := row[0].(string)
	if !strings.HasPrefix(ph, "ACCT_") {
		t.Fatalf("account placeholder %q", ph)
	}
	if !strings.Contains(row[1].(string), ph) && !strings.HasPrefix(row[1].(string), "arn:aws:s3:::") {
		t.Errorf("ARN account segment not redacted consistently: %q", row[1])
	}
	// the placeholder works as an input
	res2 := c.toolOK("sql", map[string]any{"query": "SELECT count(*) AS n FROM findings WHERE account = '" + ph + "'"})
	if n := res2["rows"].([]any)[0].([]any)[0].(float64); n == 0 {
		t.Errorf("placeholder not re-hydrated in SQL")
	}
	if res2["sql"] != "SELECT count(*) AS n FROM findings WHERE account = '"+ph+"'" {
		t.Errorf("echoed SQL must be what the client sent (redacted form): %q", res2["sql"])
	}
	ps := variantsOf(c.toolOK("paths", map[string]any{"account": ph}))
	if len(ps) == 0 {
		t.Errorf("placeholder not re-hydrated in filters")
	}
	// same value → same placeholder within a session
	res3 := c.toolOK("sql", map[string]any{"query": "SELECT account FROM findings WHERE resource_id LIKE 'arn:aws:iam::%' LIMIT 1"})
	if res3["rows"].([]any)[0].([]any)[0] != ph {
		t.Errorf("placeholder not stable")
	}
}
