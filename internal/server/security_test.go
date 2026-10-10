package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func port(ts *httptest.Server) string { return ts.URL[strings.LastIndex(ts.URL, ":")+1:] }

func send(t *testing.T, method, url, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// DNS rebinding: a request whose Host is not the bound host / loopback / --allowed-host gets 421.
func TestHostHeaderAllowlist(t *testing.T) {
	s := newTestServer(t)
	s.AllowedHosts = []string{"dash.corp.example"}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	p := port(ts)
	for host, want := range map[string]int{
		"evil.example:" + p:      421,
		"attacker.test":          421,
		"localhost:" + p:         200,
		"127.0.0.1:" + p:         200,
		"[::1]:" + p:             200,
		"dash.corp.example:8443": 200,
		"DASH.corp.example":      200,
	} {
		if got := send(t, "GET", ts.URL+"/api/summary", "", map[string]string{"Host": host}).StatusCode; got != want {
			t.Errorf("Host %q: status %d, want %d", host, got, want)
		}
	}
	// the WebSocket upgrade is covered too
	if resp := send(t, "GET", ts.URL+"/ws", "", map[string]string{"Host": "evil.example", "Connection": "Upgrade", "Upgrade": "websocket"}); resp.StatusCode != 421 {
		t.Errorf("ws with foreign Host: %d, want 421", resp.StatusCode)
	}
}

func TestTokenEnforcedOnAPIAndWebSocket(t *testing.T) {
	s := newTestServer(t)
	s.Token = "s3cret-token"
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	bearer := map[string]string{"Authorization": "Bearer s3cret-token"}
	for _, p := range []string{"/api/summary", "/api/findings", "/api/graph", "/api/schema", "/api/risk/top", "/"} {
		if got := send(t, "GET", ts.URL+p, "", nil).StatusCode; got != 401 {
			t.Errorf("GET %s without token: %d, want 401", p, got)
		}
		if got := send(t, "GET", ts.URL+p, "", map[string]string{"Authorization": "Bearer wrong"}).StatusCode; got != 401 {
			t.Errorf("GET %s with wrong token: %d, want 401", p, got)
		}
		if got := send(t, "GET", ts.URL+p, "", bearer).StatusCode; got != 200 {
			t.Errorf("GET %s with token: %d, want 200", p, got)
		}
	}
	if got := send(t, "POST", ts.URL+"/api/query", `{"sql":"SELECT 1"}`, nil).StatusCode; got != 401 {
		t.Errorf("POST /api/query without token: %d", got)
	}
	if got := send(t, "POST", ts.URL+"/api/query?token=s3cret-token", `{"sql":"SELECT 1"}`, nil).StatusCode; got != 401 {
		t.Errorf("?token= must only work for /ws, got %d on /api/query", got)
	}
	if got := send(t, "POST", ts.URL+"/api/query", `{"sql":"SELECT 1"}`, bearer).StatusCode; got != 200 {
		t.Errorf("POST /api/query with token: %d", got)
	}
	if got := send(t, "GET", ts.URL+"/healthz", "", nil).StatusCode; got != 200 {
		t.Errorf("/healthz must stay open: %d", got)
	}
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	if c, _, err := websocket.DefaultDialer.Dial(wsURL, nil); err == nil {
		c.Close()
		t.Error("/ws accepted without token")
	}
	if c, _, err := websocket.DefaultDialer.Dial(wsURL+"?token=wrong", nil); err == nil {
		c.Close()
		t.Error("/ws accepted a wrong token")
	}
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?token=s3cret-token", nil)
	if err != nil {
		t.Fatalf("/ws?token=: %v", err)
	}
	c.Close()
	h := http.Header{}
	h.Set("Authorization", "Bearer s3cret-token")
	c, _, err = websocket.DefaultDialer.Dial(wsURL, h)
	if err != nil {
		t.Fatalf("/ws with bearer: %v", err)
	}
	c.Close()
}

// CSRF: a cross-site page must not be able to drive state-changing endpoints with a simple POST.
func TestCrossSitePostRejected(t *testing.T) {
	s := newTestServer(t)
	s.CORSOrigins = []string{"https://console.example:8443"}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	q := `{"sql":"SELECT 1"}`
	cases := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, 403},
		{"same-site but other origin", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:1"}, 403},
		{"text/plain simple POST, old browser", map[string]string{"Origin": "https://evil.example", "Content-Type": "text/plain"}, 403},
		{"null origin", map[string]string{"Origin": "null"}, 403},
		{"same-origin dashboard", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": ts.URL}, 200},
		{"user-typed / non-browser", map[string]string{"Sec-Fetch-Site": "none"}, 200},
		{"curl (no browser headers)", nil, 200},
		{"allowlisted console", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://console.example:8443"}, 200},
	}
	for _, c := range cases {
		if got := send(t, "POST", ts.URL+"/api/query", q, c.hdr).StatusCode; got != c.want {
			t.Errorf("%s: POST /api/query = %d, want %d", c.name, got, c.want)
		}
	}
	if got := send(t, "POST", ts.URL+"/api/scan", "", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}).StatusCode; got != 403 {
		t.Errorf("cross-site POST /api/scan = %d, want 403", got)
	}
}

func TestServerTimeoutsAndBodyLimit(t *testing.T) {
	s := newTestServer(t)
	srv := s.HTTPServer("127.0.0.1:0")
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 30*time.Second || srv.IdleTimeout != 60*time.Second || srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("http.Server limits: rht=%s rt=%s it=%s mhb=%d", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	big := `{"sql":"SELECT 1","pad":"` + strings.Repeat("a", 2<<20) + `"}`
	if got := send(t, "POST", ts.URL+"/api/query", big, nil).StatusCode; got != http.StatusRequestEntityTooLarge {
		t.Errorf("2 MiB POST body: %d, want 413", got)
	}
}

func TestQueryEndpointTimeout(t *testing.T) {
	s := newTestServer(t)
	s.QueryTimeout = 300 * time.Millisecond
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	start := time.Now()
	body := `{"sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x FROM c WHERE x = 1 OR x < 0"}`
	done := make(chan *http.Response, 1)
	go func() {
		resp, err := http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(body))
		if err != nil {
			done <- nil
			return
		}
		done <- resp
	}()
	select {
	case resp := <-done:
		if resp == nil {
			t.Fatal("request failed")
		}
		var e map[string]string
		json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if resp.StatusCode == 200 || !strings.Contains(e["error"], "timeout") {
			t.Errorf("runaway query: %d %v", resp.StatusCode, e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("/api/query ignored its timeout")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %s with a 300ms query timeout", el)
	}
}

func TestBindRequiresTokenOffLoopback(t *testing.T) {
	for _, c := range []struct {
		addr, token string
		ok          bool
	}{
		{"127.0.0.1:8080", "", true},
		{"localhost:8080", "", true},
		{"[::1]:8080", "", true},
		{":8080", "", false},
		{"0.0.0.0:8080", "", false},
		{"[::]:8080", "", false},
		{"192.168.1.10:8080", "", false},
		{"0.0.0.0:8080", "tok", true},
	} {
		err := ValidateBind(c.addr, c.token)
		if (err == nil) != c.ok {
			t.Errorf("ValidateBind(%q, token=%q) = %v, want ok=%v", c.addr, c.token, err, c.ok)
		}
	}
}

// TestQueryEndpointBusyIs429 pins that the per-database concurrency cap surfaces as 429, not 400,
// so clients can distinguish "retry later" from "bad SQL".
func TestQueryEndpointBusyIs429(t *testing.T) {
	s := newTestServer(t)
	s.QueryTimeout = 2 * time.Second
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	slow := `{"sql":"WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT x FROM c WHERE x = 1 OR x < 0"}`
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() {
			resp, err := http.Post(ts.URL+"/api/query", "application/json", strings.NewReader(slow))
			if err != nil {
				codes <- -1
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	saw429, saw400 := false, false
	for i := 0; i < 8; i++ {
		switch <-codes {
		case http.StatusTooManyRequests:
			saw429 = true
		case 400:
			saw400 = true
		}
	}
	if !saw429 {
		t.Fatal("expected at least one 429 when more than the concurrency cap of queries run at once")
	}
	if saw400 {
		t.Fatal("busy queries must not be reported as 400 bad request")
	}
}
