package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/mcp"
)

// W7-VERIFY r5 #14 (bar: Sysdig's remote MCP server, tools filtered by the token's permissions):
// `serve` mounts MCP over streamable HTTP at /mcp, behind the same Host and cross-site rules as the
// API; every request needs a bearer token (never a cookie or ?token=); each token carries its own
// scopes, and a session's tool list is what those scopes grant. stdio stays the default transport.

type mcpClient struct {
	t      *testing.T
	ts     *httptest.Server
	token  string
	sid    string
	origin string
}

func (c *mcpClient) post(body string) (int, http.Header, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, resp.Header, m
}

func (c *mcpClient) initialize() {
	c.t.Helper()
	code, h, m := c.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)
	if code != 200 || m["result"] == nil || h.Get("Mcp-Session-Id") == "" {
		c.t.Fatalf("initialize: %d %v %v", code, h, m)
	}
	c.sid = h.Get("Mcp-Session-Id")
	if code, _, _ := c.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != http.StatusAccepted {
		c.t.Fatalf("notification: %d, want 202", code)
	}
}

func (c *mcpClient) tools() []string {
	c.t.Helper()
	_, _, m := c.post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var out []string
	r, _ := m["result"].(map[string]any)
	ts, _ := r["tools"].([]any)
	for _, x := range ts {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return out
}

func mcpServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, _ := seedLifecycle(t)
	h, err := mcp.NewHTTPHandler(s.st, mcp.HTTPOptions{Options: mcp.Options{AuditPath: filepath.Join(t.TempDir(), "audit.jsonl")}})
	if err != nil {
		t.Fatal(err)
	}
	s.MCP = h
	s.Token = "api-token"
	s.MCPTokens = []MCPToken{{Name: "reader", Token: "reader-token", Scopes: []string{"read"}},
		{Name: "fixer", Token: "fixer-token", Scopes: []string{"read", "fix"}}, {Name: "sql-only", Token: "sql-token", Scopes: []string{"sql"}}}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestMCPOverHTTPAuthAndScopes(t *testing.T) {
	_, ts := mcpServer(t)

	// Unauthenticated: 401, nothing else said; a cookie or ?token= is not a bearer token.
	anon := &mcpClient{t: t, ts: ts}
	if code, h, _ := anon.post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 401 || !strings.Contains(h.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("unauthenticated initialize: %d %v", code, h)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp?token=api-token", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.AddCookie(&http.Cookie{Name: tokenCookie, Value: "api-token"})
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Errorf("cookie / ?token= accepted on /mcp: %d", resp.StatusCode)
	}
	bad := &mcpClient{t: t, ts: ts, token: "nope"}
	if code, _, _ := bad.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 401 {
		t.Errorf("wrong token: %d", code)
	}

	// Scope-filtered sessions.
	reader := &mcpClient{t: t, ts: ts, token: "reader-token"}
	reader.initialize()
	rt := strings.Join(reader.tools(), ",")
	if strings.Contains(rt, "draft_fix") || !strings.Contains(rt, "sql") || !strings.Contains(rt, "verify") {
		t.Errorf("read-scope tools = %s", rt)
	}
	if _, _, m := reader.post(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"draft_fix","arguments":{"finding_id":"x"}}}`); m["error"] == nil {
		if r, _ := m["result"].(map[string]any); r == nil || r["isError"] != true {
			t.Errorf("draft_fix outside the read scope ran: %v", m)
		}
	}
	fixer := &mcpClient{t: t, ts: ts, token: "fixer-token"}
	fixer.initialize()
	if ft := strings.Join(fixer.tools(), ","); !strings.Contains(ft, "draft_fix") {
		t.Errorf("read+fix tools = %s", ft)
	}
	sqlOnly := &mcpClient{t: t, ts: ts, token: "sql-token"}
	sqlOnly.initialize()
	st := sqlOnly.tools()
	sort.Strings(st)
	if strings.Join(st, ",") != "schema,sql" {
		t.Errorf("sql-scope tools = %v", st)
	}
	// The API token defaults to the read scope.
	api := &mcpClient{t: t, ts: ts, token: "api-token"}
	api.initialize()
	if at := strings.Join(api.tools(), ","); strings.Contains(at, "draft_fix") || !strings.Contains(at, "summary") {
		t.Errorf("api-token tools = %s", at)
	}

	// A session belongs to its token: another token cannot use it (404, as for an unknown id).
	thief := &mcpClient{t: t, ts: ts, token: "fixer-token", sid: reader.sid}
	if code, _, _ := thief.post(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); code != 404 {
		t.Errorf("another token used the reader's session: %d", code)
	}
	noSession := &mcpClient{t: t, ts: ts, token: "reader-token"}
	if code, _, _ := noSession.post(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); code != 400 {
		t.Errorf("a non-initialize request without a session: %d, want 400", code)
	}

	// Cross-site and DNS-rebinding rules of the API apply.
	evil := &mcpClient{t: t, ts: ts, token: "reader-token", sid: reader.sid, origin: "https://evil.example"}
	if code, _, _ := evil.post(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); code != 403 {
		t.Errorf("cross-origin MCP request: %d, want 403", code)
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	req.Host = "rebind.example"
	req.Header.Set("Authorization", "Bearer reader-token")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("foreign Host: %d", resp.StatusCode)
	}

	// GET (no server-initiated stream) and DELETE (end the session).
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /mcp: %d, want 405", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer reader-token")
	req.Header.Set("Mcp-Session-Id", reader.sid)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 204 {
		t.Errorf("DELETE session: %d", resp.StatusCode)
	}
	if code, _, _ := reader.post(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`); code != 404 {
		t.Errorf("a deleted session still answers: %d", code)
	}
}

// Without any token the transport is off: /mcp never runs unauthenticated, even on loopback.
func TestMCPOverHTTPNeedsAToken(t *testing.T) {
	s, _ := seedLifecycle(t)
	h, _ := mcp.NewHTTPHandler(s.st, mcp.HTTPOptions{Options: mcp.Options{AuditPath: filepath.Join(t.TempDir(), "a.jsonl")}})
	s.MCP = h
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	c := &mcpClient{t: t, ts: ts}
	if code, _, _ := c.post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 401 && code != 403 {
		t.Fatalf("tokenless /mcp: %d", code)
	}
	plain := httptest.NewServer(newTestServer(t).Handler())
	defer plain.Close()
	c = &mcpClient{t: t, ts: plain, token: "x"}
	if code, _, _ := c.post(`{}`); code != 404 {
		t.Errorf("serve without --mcp exposes /mcp: %d", code)
	}
}
