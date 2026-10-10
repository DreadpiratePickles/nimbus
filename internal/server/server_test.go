package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/gorilla/websocket"
)

func TestAPI(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "s.db"))
	defer st.Close()
	f := model.Finding{Source: "prowler", CheckID: "x", CanonicalID: "S3_PUBLIC_BUCKET", Title: "public", Severity: model.High, Status: model.Fail, Provider: "aws", Account: "1",
		Resource: model.Resource{ID: "arn:aws:s3:::pii", Type: "aws_s3_bucket", Name: "pii"}, Weaknesses: []string{"PUBLIC_DATA_STORE"}, Compliance: map[string][]string{"cis_aws": {"2.1.4"}}}
	f.Finalize(time.Now())
	st.UpsertFindings([]model.Finding{f})
	st.RebuildIssues(time.Now()) // /api/summary counts Issues (Track G)
	st.ReplaceAttackPaths("s", []model.AttackPath{{ID: "p", Score: 6, Severity: model.High, FindingIDs: []string{f.ID}, Steps: []model.Step{{Resource: "arn:aws:s3:::pii"}}}})
	s := New(st, func() ([]byte, error) { return []byte("<html>dash</html>"), nil })
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	get := func(p string, v any) int {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if v != nil {
			json.NewDecoder(resp.Body).Decode(v)
		}
		return resp.StatusCode
	}
	var sum map[string]any
	if get("/api/summary", &sum) != 200 || sum["open"].(float64) != 1 || sum["attack_paths"].(float64) != 1 {
		t.Errorf("summary: %v", sum)
	}
	var fs []model.Finding
	if get("/api/findings?status=FAIL&min_severity=high", &fs) != 200 || len(fs) != 1 {
		t.Errorf("findings: %v", fs)
	}
	var one map[string]any
	if get("/api/findings/"+f.ID, &one) != 200 || len(one["attack_paths"].([]any)) != 1 {
		t.Errorf("finding: %v", one)
	}
	var ranked []map[string]any
	if get("/api/risk/top?n=5", &ranked) != 200 || len(ranked) != 1 || ranked[0]["risk_score"].(float64) < 4 {
		t.Errorf("risk: %v", ranked)
	}
	var rep map[string]any
	if get("/api/compliance/cis?provider=aws", &rep) != 200 || rep["failing"].(float64) != 1 {
		t.Errorf("compliance: %v", rep)
	}
	resp, _ := http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(`{"sql":"SELECT name FROM aws_s3_buckets"}`))
	var qr map[string]any
	json.NewDecoder(resp.Body).Decode(&qr)
	if resp.StatusCode != 200 || len(qr["rows"].([]any)) != 1 {
		t.Errorf("query: %d %v", resp.StatusCode, qr)
	}
	resp, _ = http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(`{"sql":"DELETE FROM findings"}`))
	if resp.StatusCode != 400 {
		t.Errorf("write query should be rejected")
	}
	if get("/", nil) != 200 || get("/api/graph", nil) != 200 || get("/api/schema", nil) != 200 {
		t.Errorf("static endpoints")
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var hello Event
	ws.ReadJSON(&hello)
	s.Broadcast(Event{Type: "findings_updated"})
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ev Event
	if err := ws.ReadJSON(&ev); err != nil || ev.Type != "findings_updated" {
		t.Errorf("ws broadcast: %v %+v", err, ev)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, func() ([]byte, error) { return []byte("<html>dash</html>"), nil })
}

func doReq(t *testing.T, ts *httptest.Server, method, path, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(`{"sql":"SELECT 1"}`))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// A local `serve` must not be scriptable from arbitrary websites (no ACAO wildcard).
func TestCORSRejectsForeignOrigin(t *testing.T) {
	ts := httptest.NewServer(newTestServer(t).Handler())
	defer ts.Close()
	for _, m := range []string{"GET", "POST"} {
		p := "/api/summary"
		if m == "POST" {
			p = "/api/query"
		}
		if v := doReq(t, ts, m, p, "https://evil.example").Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s %s from evil origin: ACAO = %q, want none", m, p, v)
		}
		if v := doReq(t, ts, m, p, "").Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("%s %s without Origin: ACAO = %q, want none", m, p, v)
		}
	}
	if r := doReq(t, ts, "OPTIONS", "/api/query", "https://evil.example"); r.StatusCode != 403 || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("preflight from evil origin: %d ACAO=%q, want 403 and none", r.StatusCode, r.Header.Get("Access-Control-Allow-Origin"))
	}
	// a foreign origin that merely shares the hostname but not the port is foreign
	host := strings.TrimPrefix(ts.URL, "http://")
	hostOnly := host[:strings.LastIndex(host, ":")]
	if r := doReq(t, ts, "OPTIONS", "/api/query", "http://"+hostOnly+":1"); r.StatusCode != 403 {
		t.Errorf("preflight from other port: %d, want 403", r.StatusCode)
	}
}

func TestCORSAllowsSameHostAndAllowlist(t *testing.T) {
	s := newTestServer(t)
	s.CORSOrigins = []string{"https://console.example:8443"}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	for _, origin := range []string{"http://" + host, "https://" + host, "https://console.example:8443"} {
		r := doReq(t, ts, "GET", "/api/summary", origin)
		if got := r.Header.Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("GET from %s: ACAO = %q, want echoed origin", origin, got)
		}
		if !strings.Contains(r.Header.Get("Vary"), "Origin") {
			t.Errorf("GET from %s: missing Vary: Origin", origin)
		}
		r = doReq(t, ts, "OPTIONS", "/api/query", origin)
		if r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != origin {
			t.Errorf("preflight from %s: %d ACAO=%q, want 204 and echo", origin, r.StatusCode, r.Header.Get("Access-Control-Allow-Origin"))
		}
	}
	if r := doReq(t, ts, "OPTIONS", "/api/query", "https://console.example"); r.StatusCode != 403 {
		t.Errorf("allowlist must match host:port exactly; got %d", r.StatusCode)
	}
}

func TestDashboardCSP(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Handler())
	csp := doReq(t, ts, "GET", "/", "").Header.Get("Content-Security-Policy")
	ts.Close()
	if csp == "" || strings.Contains(csp, "cdnjs") {
		t.Errorf("CSP must exist and not allow cdnjs: %q", csp)
	}
	s.CopilotURL = "http://localhost:8081/some/path"
	ts = httptest.NewServer(s.Handler())
	defer ts.Close()
	csp = doReq(t, ts, "GET", "/", "").Header.Get("Content-Security-Policy")
	var connect string
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(d, "connect-src ") {
			connect = d
		}
	}
	if !strings.Contains(connect, " http://localhost:8081") || strings.Contains(connect, "/some/path") {
		t.Errorf("connect-src must include the copilot origin: %q", connect)
	}
	if strings.Contains(csp, "cdnjs") {
		t.Errorf("CSP allows cdnjs: %q", csp)
	}
}

// TestWebSocketOriginCheck pins that /ws, like /api/*, only accepts browsers on the
// server's own host or an allowlisted origin, so a hostile website cannot read live events.
func TestWebSocketOriginCheck(t *testing.T) {
	s := newTestServer(t)
	s.CORSOrigins = []string{"https://console.example:8443"}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	dial := func(origin string) error {
		h := http.Header{}
		if origin != "" {
			h.Set("Origin", origin)
		}
		c, _, err := websocket.DefaultDialer.Dial(wsURL, h)
		if c != nil {
			c.Close()
		}
		return err
	}
	if err := dial("https://evil.example"); err == nil {
		t.Fatal("foreign origin was allowed to open /ws")
	}
	if err := dial(ts.URL); err != nil {
		t.Fatalf("same-host origin rejected: %v", err)
	}
	if err := dial("https://console.example:8443"); err != nil {
		t.Fatalf("allowlisted origin rejected: %v", err)
	}
	if err := dial(""); err != nil {
		t.Fatalf("non-browser client (no Origin) rejected: %v", err)
	}
}
