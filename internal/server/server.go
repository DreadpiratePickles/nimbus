// Package server serves the dashboard, a JSON API over the posture database and a WebSocket
// that pushes live updates (new scans, monitor events) to connected dashboards.
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/compliance"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/query"
	"github.com/DreadpiratePickles/nimbus/internal/risk"
	"github.com/DreadpiratePickles/nimbus/internal/store"
	"github.com/gorilla/websocket"
)

type Server struct {
	st        *store.Store
	dashboard func() ([]byte, error) // renders the single-file dashboard
	upgrader  websocket.Upgrader
	mu        sync.Mutex
	clients   map[*websocket.Conn]bool
	Logf      func(string, ...any)
	Rescan    func(ctx context.Context) error // optional: triggered by POST /api/scan
	Token     string                          // optional bearer token for write endpoints
	// CORSOrigins are extra origins (scheme://host[:port]) allowed to call the API from a
	// browser; the server's own host is always allowed. Empty by default.
	CORSOrigins []string
	// CopilotURL is the Python copilot API the dashboard fetches; its origin is added to
	// the dashboard CSP connect-src.
	CopilotURL string
	// AllowedHosts are extra Host-header names accepted besides the bound host, localhost,
	// 127.0.0.1 and [::1] (DNS-rebinding protection). Matched by hostname, case-insensitively.
	AllowedHosts []string
	// QueryTimeout bounds each POST /api/query (DefaultQueryTimeout when zero).
	QueryTimeout time.Duration
	// ids keys stored digest ids in responses (withKeyedIDs); built on first use.
	idsMu sync.Mutex
	ids   *store.IDMapper
	// BindHost is the host part of the listen address; set by ListenAndServe.
	BindHost string
	// RiskOptions supplies the intel feed and config crown jewels for /api/risk/top (the
	// CLI wires the same options as `prioritize`); nil uses the embedded snapshot.
	RiskOptions func() risk.Options
	// Traversal supplies the attack-path traversal options (config crown jewels, trusted
	// CIDRs) for /api/attack-paths/analysis, /api/risk/top and the Issue page; nil uses
	// attackpath.DefaultTraversalOptions.
	Traversal func(g *graph.Graph) attackpath.TraversalOptions
}

// traversalOptions are s.Traversal(g) or the defaults.
func (s *Server) traversalOptions(g *graph.Graph) attackpath.TraversalOptions {
	if s.Traversal != nil {
		return s.Traversal(g)
	}
	return attackpath.DefaultTraversalOptions()
}

// riskInputs are the published score's inputs over the stored state: the risk options with
// Analysis set to a traversal of the stored graph whose Paths are the stored (merged rule
// chain + traversal) paths, so the off-path cap reads the same verdict as `prioritize`.
func (s *Server) riskInputs(g *graph.Graph, paths []model.AttackPath) risk.Options {
	var o risk.Options
	if s.RiskOptions != nil {
		o = s.RiskOptions()
	}
	if g != nil && o.Analysis == nil {
		an := attackpath.Traverse(g, s.traversalOptions(g))
		an.Paths = paths
		o.Analysis = an
	}
	return o
}

const (
	DefaultQueryTimeout = 10 * time.Second
	maxBodyBytes        = 1 << 20
	tokenCookie         = "nimbus_token"
)

func New(st *store.Store, dashboard func() ([]byte, error)) *Server {
	s := &Server{st: st, dashboard: dashboard, clients: map[*websocket.Conn]bool{}, Logf: log.Printf}
	// Browsers always send Origin on WebSocket upgrades; accept only our own host or the
	// --cors-origin allowlist. Non-browser clients (no Origin) are allowed, as with /api/*.
	s.upgrader = websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool {
		o := r.Header.Get("Origin")
		return o == "" || s.originAllowed(o, r.Host)
	}}
	return s
}

// Event is pushed to every connected dashboard.
type Event struct {
	Type    string    `json:"type"` // findings_updated | monitor_event | scan_started | scan_finished
	Time    time.Time `json:"time"`
	Payload any       `json:"payload,omitempty"`
}

func (s *Server) Broadcast(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	data, _ := json.Marshal(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
			c.Close()
			delete(s.clients, c)
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /ws", s.handleWS)
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("GET /api/findings/{id}", s.handleFinding)
	mux.HandleFunc("GET /api/issues", s.handleIssues)
	mux.HandleFunc("GET /api/issues/{id}", s.handleIssue)
	mux.HandleFunc("GET /api/issues/{id}/history", s.handleIssueHistory)
	mux.HandleFunc("POST /api/issues/{id}/suppress", s.handleIssueSuppress)
	mux.HandleFunc("POST /api/issues/{id}/pending", s.handleIssuePending)
	mux.HandleFunc("GET /api/governance/metrics", s.handleGovernanceMetrics)
	mux.HandleFunc("GET /api/coverage", s.handleCoverage)
	mux.HandleFunc("GET /api/scans", s.handleScans)
	mux.HandleFunc("GET /api/attack-paths", s.handleAttackPaths)
	mux.HandleFunc("GET /api/attack-paths/analysis", s.handleAnalysis)
	mux.HandleFunc("GET /api/attack-paths/issues", s.handleAttackPathIssues)
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/graph/blast-radius/{id...}", s.handleBlastRadius)
	mux.HandleFunc("GET /api/risk/top", s.handleRisk)
	mux.HandleFunc("GET /api/compliance/{framework}", s.handleCompliance)
	mux.HandleFunc("GET /api/schema", s.handleSchema)
	mux.HandleFunc("POST /api/query", s.handleQuery)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	return s.withHostCheck(s.withCORS(s.withRequestGuards(s.withKeyedIDs(mux))))
}

// withHostCheck answers 421 to any Host that is not this server's (DNS rebinding: a hostile
// name resolving to 127.0.0.1 must not reach the API with the victim browser's same-origin rights).
func (s *Server) withHostCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			writeErr(w, http.StatusMisdirectedRequest, fmt.Errorf("host %q is not served here (use --allowed-host)", r.Host))
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	case "":
		return false
	}
	if b := strings.ToLower(strings.Trim(s.BindHost, "[]")); b != "" && !isUnspecified(b) && b == host {
		return true
	}
	for _, a := range s.AllowedHosts {
		a = strings.TrimSpace(a)
		if h, _, err := net.SplitHostPort(a); err == nil {
			a = h
		}
		if strings.EqualFold(strings.Trim(a, "[]"), host) {
			return true
		}
	}
	return false
}

func isUnspecified(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// withRequestGuards applies, in order: cross-site rejection for state-changing methods (CSRF),
// the bearer token on /, /ws and /api/* when one is configured, and a 1 MiB body cap.
func (s *Server) withRequestGuards(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.crossSiteRejected(r) {
			writeErr(w, http.StatusForbidden, fmt.Errorf("cross-site request rejected"))
			return
		}
		if s.Token != "" && r.URL.Path != "/healthz" {
			if r.URL.Path == "/" && r.Method == http.MethodGet && tokenEqual(r.URL.Query().Get("token"), s.Token) {
				// Browser bootstrap: exchange ?token= for a same-site-only cookie and drop it from the URL.
				http.SetCookie(w, &http.Cookie{Name: tokenCookie, Value: s.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			if !s.authorized(r) {
				writeErr(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
				return
			}
		}
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		h.ServeHTTP(w, r)
	})
}

// crossSiteRejected: a state-changing request is accepted only when the browser marks it
// same-origin / user-initiated (Sec-Fetch-Site), or its Origin is our host or an allowlisted
// origin. Clients that send neither header (curl, scripts) are not browsers and cannot be
// CSRF vectors; they still need the token when one is set.
func (s *Server) crossSiteRejected(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	origin := r.Header.Get("Origin")
	originOK := origin != "" && s.originAllowed(origin, r.Host)
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return false
	case "":
		return origin != "" && !originOK
	default:
		return !originOK
	}
}

// authorized accepts the bearer header everywhere, ?token= on /ws only (browsers cannot set
// headers on WebSocket upgrades), and the cookie set by the / bootstrap.
func (s *Server) authorized(r *http.Request) bool {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") && tokenEqual(strings.TrimPrefix(a, "Bearer "), s.Token) {
		return true
	}
	if r.URL.Path == "/ws" && tokenEqual(r.URL.Query().Get("token"), s.Token) {
		return true
	}
	if c, err := r.Cookie(tokenCookie); err == nil && tokenEqual(c.Value, s.Token) {
		return true
	}
	return false
}

func tokenEqual(got, want string) bool {
	return got != "" && want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ValidateBind refuses to expose the API beyond loopback without a token.
func ValidateBind(addr, token string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if isLoopbackHost(host) || strings.TrimSpace(token) != "" {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q without a token: bind 127.0.0.1 or set --token / CLOUD_POSTURE_TOKEN", addr)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// withCORS never sends a wildcard: Access-Control-Allow-Origin is echoed only for the
// server's own host (scheme-agnostic host:port match) or an origin in s.CORSOrigins, so an
// arbitrary website the user visits cannot drive a local `serve` (e.g. POST /api/query).
// Preflights from any other origin get 403.
func (s *Server) withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin != "" && s.originAllowed(origin, r.Host)
		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			if allowed {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		h.ServeHTTP(w, r)
	})
}

// originAllowed reports whether origin's host:port equals the request host or matches an
// entry of s.CORSOrigins (compared by host:port, case-insensitively).
func (s *Server) originAllowed(origin, host string) bool {
	oh := originHost(origin)
	if oh == "" {
		return false
	}
	if strings.EqualFold(oh, host) {
		return true
	}
	for _, a := range s.CORSOrigins {
		if ah := originHost(a); ah != "" && strings.EqualFold(oh, ah) {
			return true
		}
	}
	return false
}

// originHost returns the host[:port] of an origin or URL ("" when it has none).
func originHost(o string) string {
	u, err := url.Parse(strings.TrimSpace(o))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// dashboardCSP is the dashboard's Content-Security-Policy. All scripts are inlined
// (Cytoscape is embedded), so no script CDN is allowed; the copilot origin, when
// configured, is added to connect-src.
func (s *Server) dashboardCSP() string {
	connect := "connect-src 'self' ws: wss:"
	if u, err := url.Parse(strings.TrimSpace(s.CopilotURL)); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		connect += " " + u.Scheme + "://" + u.Host
	}
	return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " + connect + "; img-src 'self' data:"
}

// withKeyedIDs (r4 #15) rewrites every stored finding / attack-path digest id in the API's JSON
// and in the dashboard page the server renders to its external keyed form (store/extid.go), so
// the API, the served dashboard and MCP show the same ids and none shows a raw fingerprint (an
// account oracle next to redacted data). WebSocket upgrades and non-JSON bodies pass through.
func (s *Server) withKeyedIDs(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" || (r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/api/")) {
			h.ServeHTTP(w, r)
			return
		}
		m := s.idMapper()
		if m == nil {
			h.ServeHTTP(w, r)
			return
		}
		bw := &bufferedWriter{header: http.Header{}, code: http.StatusOK}
		h.ServeHTTP(bw, r)
		body := bw.buf.Bytes()
		ct := bw.header.Get("Content-Type")
		if strings.Contains(ct, "json") || strings.Contains(ct, "html") {
			body = []byte(m.MapString(string(body)))
			bw.header.Del("Content-Length")
		}
		for k, v := range bw.header {
			w.Header()[k] = v
		}
		w.WriteHeader(bw.code)
		w.Write(body)
	})
}

func (s *Server) idMapper() *store.IDMapper {
	s.idsMu.Lock()
	defer s.idsMu.Unlock()
	if s.ids == nil {
		if m, err := s.st.IDMapper(); err == nil {
			s.ids = m
		}
	}
	return s.ids
}

type bufferedWriter struct {
	header http.Header
	code   int
	buf    bytes.Buffer
	wrote  bool
}

func (b *bufferedWriter) Header() http.Header { return b.header }
func (b *bufferedWriter) WriteHeader(code int) {
	if !b.wrote {
		b.code, b.wrote = code, true
	}
}
func (b *bufferedWriter) Write(p []byte) (int, error) {
	b.wrote = true
	return b.buf.Write(p)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html, err := s.dashboard()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", s.dashboardCSP())
	w.Write(html)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(4096) // clients only send pings/close frames
	s.mu.Lock()
	s.clients[c] = true
	c.WriteJSON(Event{Type: "hello", Time: time.Now().UTC()})
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.clients, c)
			s.mu.Unlock()
			c.Close()
		}()
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// handleSummary: the header counts are Issues (one per canonical check × resource, so two
// tools reporting the same problem count once); the raw finding counts stay under "findings".
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	fs, err := s.st.Findings(store.Filter{})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	ic, err := s.st.IssueCounts()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	paths, _ := s.st.AttackPaths()
	last, _ := s.st.LastScan()
	doc := SummarizeIssues(ic, fs, paths, last)
	h, err := s.st.Headline()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	doc["headline"] = h
	writeJSON(w, doc)
}

// SummarizeIssues is the /api/summary document: Issue counts at the top level, the legacy
// finding counts (Summarize) under "findings".
func SummarizeIssues(ic *store.IssueCounts, fs []model.Finding, paths []model.AttackPath, last *model.ScanSummary) map[string]any {
	legacy := Summarize(fs, paths)
	if ic == nil {
		ic = &store.IssueCounts{BySeverity: map[string]int{}, ByProvider: map[string]int{}, ByAccount: map[string]int{},
			Paths: store.PathIssueCounts{BySeverity: map[string]int{}, ByBand: map[string]int{}}}
	}
	return map[string]any{
		"unit": "issues", "total": ic.Total, "open": ic.Open, "resolved": ic.Resolved, "combinations": ic.Combinations,
		"by_severity": ic.BySeverity, "by_provider": ic.ByProvider, "by_account": ic.ByAccount,
		"suppressed": ic.Suppressed, "paths": ic.Paths,
		"attack_paths": legacy["attack_paths"], "critical_paths": legacy["critical_paths"],
		"findings": legacy, "last_scan": last,
	}
}

// Summarize builds the dashboard header numbers.
func Summarize(fs []model.Finding, paths []model.AttackPath) map[string]any {
	bySev := map[string]int{}
	byProv := map[string]map[string]int{}
	byAcct := map[string]int{}
	open := 0
	for _, f := range fs {
		if f.Status != model.Fail {
			continue
		}
		open++
		bySev[string(f.Severity)]++
		if byProv[f.Provider] == nil {
			byProv[f.Provider] = map[string]int{}
		}
		byProv[f.Provider][string(f.Severity)]++
		byAcct[f.Provider+"/"+f.Account]++
	}
	critPaths := 0
	for _, p := range paths {
		if p.Severity == model.Critical {
			critPaths++
		}
	}
	return map[string]any{"total": len(fs), "open": open, "by_severity": bySev, "by_provider": byProv, "by_account": byAcct, "attack_paths": len(paths), "critical_paths": critPaths}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	fl := store.Filter{Status: q.Get("status"), Provider: q.Get("provider"), Account: q.Get("account"), CanonicalID: q.Get("canonical_id"), Source: q.Get("source"), Limit: limit,
		IncludeResolved: truthy(q.Get("include_resolved"))}
	if ms := q.Get("min_severity"); ms != "" {
		fl.MinSeverity = model.ParseSeverity(ms)
	}
	fs, err := s.st.Findings(fl)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	for i := range fs {
		fs[i].Raw = nil
	}
	writeJSON(w, fs)
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// issueStates maps the ?state= filter to the stored states it selects.
var issueStates = map[string][]string{
	"open":       {model.StateOpen, model.StateReopened}, // active
	"active":     {model.StateOpen, model.StateReopened},
	"new":        {model.StateOpen},
	"reopened":   {model.StateReopened},
	"resolved":   {model.StateResolved},
	"suppressed": {model.StateSuppressed},
	// closure sub-states (W5-ISSUES)
	"pending_verification": {model.StatePendingVerification},
	"pending":              {model.StatePendingVerification},
	"verified_fixed":       {model.StateVerifiedFixed},
	"verified":             {model.StateVerifiedFixed},
	"closed":               {model.StateResolved, model.StateVerifiedFixed},
	"all":                  nil,
	"":                     nil,
}

// handleIssues lists Issues; filters: state (open|reopened|resolved|suppressed|all),
// severity (exact, or min_severity), provider, account, kind (single|combination|path), band
// (path score band: Critical|High|Medium|Low), owner (governance owner, case-insensitive;
// "(unassigned)" for none) and overdue=1 (open Issues past their governance due date).
func (s *Server) handleIssues(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := strings.ToLower(strings.TrimSpace(q.Get("state")))
	states, ok := issueStates[state]
	if !ok {
		writeErr(w, 400, fmt.Errorf("state must be one of open, new, reopened, pending_verification, verified_fixed, resolved, closed, suppressed, all"))
		return
	}
	kind := strings.ToLower(strings.TrimSpace(q.Get("kind")))
	if kind != "" && kind != model.IssueSingle && kind != model.IssueCombination && kind != model.IssuePath {
		writeErr(w, 400, fmt.Errorf("kind must be single, combination or path"))
		return
	}
	band := strings.TrimSpace(q.Get("band"))
	if band != "" && store.BandSeverity(band) == "" {
		writeErr(w, 400, fmt.Errorf("band must be one of Critical, High, Medium, Low"))
		return
	}
	var sev, minSev model.Severity
	if v := q.Get("severity"); v != "" {
		sev = model.ParseSeverity(v)
	}
	if v := q.Get("min_severity"); v != "" {
		minSev = model.ParseSeverity(v)
		// ParseSeverity maps anything unknown to INFO, which would silently drop the filter.
		if minSev == model.Info && !infoSeverityWords[strings.ToLower(strings.TrimSpace(v))] {
			writeErr(w, 400, fmt.Errorf("min_severity must be one of critical, high, medium, low, info"))
			return
		}
	}
	overdue := false
	switch strings.ToLower(strings.TrimSpace(q.Get("overdue"))) {
	case "", "0", "false", "no":
	case "1", "true", "yes":
		overdue = true
	default:
		writeErr(w, 400, fmt.Errorf("overdue must be 1 or 0"))
		return
	}
	issues, err := s.st.Issues(store.IssueFilter{Kind: kind, Provider: q.Get("provider"), Account: q.Get("account"),
		Owner: q.Get("owner"), OverdueOnly: overdue})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	out := []model.Issue{}
	for _, is := range issues {
		if states != nil && !containsStr(states, is.State) {
			continue
		}
		if sev != "" && is.Severity != sev {
			continue
		}
		if minSev != "" && is.Severity.Rank() < minSev.Rank() {
			continue
		}
		if band != "" && !strings.EqualFold(is.Band, band) {
			continue
		}
		out = append(out, is)
	}
	if limit, _ := strconv.Atoi(q.Get("limit")); limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, out)
}

// infoSeverityWords are the inputs model.ParseSeverity deliberately maps to INFO.
var infoSeverityWords = map[string]bool{"info": true, "informational": true, "1": true, "note": true, "none": true}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// handleIssue returns one Issue's page (BuildIssuePage: evidence, hops with because, score
// explanation, confidence, owner/SLA, linked Issues, fixes with phases, tickets, timeline,
// suppression); the "issue" and "findings" keys keep their earlier shape.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	id := s.st.ResolveIssueID(r.PathValue("id"))
	if ok, err := s.issueExists(id); err != nil {
		writeErr(w, 500, err)
		return
	} else if !ok {
		writeErr(w, 404, fmt.Errorf("issue not found"))
		return
	}
	g, err := s.loadGraph()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	paths, err := s.st.AttackPaths()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	ro := s.riskInputs(g, paths)
	pg, err := BuildIssuePage(s.st, id, IssuePageOptions{Risk: ro, Graph: g, Paths: paths, Analysis: ro.Analysis})
	if errors.Is(err, store.ErrIssueNotFound) {
		writeErr(w, 404, fmt.Errorf("issue not found"))
		return
	}
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, pg)
}

// handleIssueHistory returns a path Issue's transitions and hop-list changes, oldest first
// (an empty list for finding-derived Issues).
func (s *Server) handleIssueHistory(w http.ResponseWriter, r *http.Request) {
	id := s.st.ResolveIssueID(r.PathValue("id"))
	if ok, err := s.issueExists(id); err != nil {
		writeErr(w, 500, err)
		return
	} else if !ok {
		writeErr(w, 404, fmt.Errorf("issue not found"))
		return
	}
	h, err := s.st.PathIssueHistory(id)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if h == nil {
		h = []store.PathIssueHistoryEntry{}
	}
	q := r.URL.Query()
	if q.Get("scores") != "1" && q.Get("scores") != "true" {
		writeJSON(w, h) // the transitions array (unchanged shape)
		return
	}
	// ?scores=1 (W7-VERIFY r5 #11): the transitions plus the per-scan score journey, optionally
	// since a lookback (?since=90d | YYYY-MM-DD | RFC 3339).
	since, err := store.ParseSince(q.Get("since"), time.Now().UTC())
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	pts, err := s.st.IssueScoreHistory(id, since)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if pts == nil {
		pts = []store.IssueScorePoint{}
	}
	doc := map[string]any{"issue_id": id, "transitions": h, "scores": pts, "line": store.ScoreJourneyLine(pts)}
	if !since.IsZero() {
		doc["since"] = since
	}
	writeJSON(w, doc)
}

func (s *Server) issueExists(id string) (bool, error) {
	var n int
	err := s.st.DB().QueryRow("SELECT COUNT(*) FROM issues WHERE id = ?", id).Scan(&n)
	return n > 0, err
}

// suppressRequest is the POST /api/issues/{id}/suppress body.
type suppressRequest struct {
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
	ApprovedBy string    `json:"approved_by"` // refused when set: the approver is the authenticated principal
}

// maxActorLen caps the X-Nimbus-Actor header.
const maxActorLen = 128

// suppressApprover is the authenticated principal of a suppress request. The endpoint only
// runs with a server token, so the principal is "api token"; a caller holding the token may
// name the person acting with X-Nimbus-Actor (printable, at most maxActorLen bytes), recorded
// as "<actor> (api token)" so the record never claims more than the token proves.
func suppressApprover(r *http.Request) (string, error) {
	a := strings.TrimSpace(r.Header.Get("X-Nimbus-Actor"))
	if a == "" {
		return "api token", nil
	}
	if len(a) > maxActorLen {
		return "", fmt.Errorf("X-Nimbus-Actor longer than %d bytes", maxActorLen)
	}
	for _, c := range a {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("X-Nimbus-Actor contains control characters")
		}
	}
	return a + " (api token)", nil
}

// handleIssueSuppress accepts the risk of one Issue until expires_at (reason and a future
// expiry required). Accepting risk is a write that must be attributable, so the endpoint is
// refused outright on a server started without a token; the request guards (CSRF, bearer
// token, body cap) apply as to every state-changing request.
func (s *Server) handleIssueSuppress(w http.ResponseWriter, r *http.Request) {
	if s.Token == "" {
		writeErr(w, http.StatusForbidden, fmt.Errorf("suppression over the API needs a server token (serve --token / CLOUD_POSTURE_TOKEN); use `cloud-posture issues suppress` locally"))
		return
	}
	var req suppressRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, fmt.Errorf("invalid body: %w", err))
		return
	}
	if strings.TrimSpace(req.ApprovedBy) != "" {
		writeErr(w, 400, fmt.Errorf("approved_by is taken from the authenticated principal (the server token, named by the X-Nimbus-Actor header), not from the request body"))
		return
	}
	approver, err := suppressApprover(r)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	id := s.st.ResolveIssueID(r.PathValue("id"))
	err = s.st.SuppressIssue(id, store.Suppression{Reason: req.Reason, ExpiresAt: req.ExpiresAt, ApprovedBy: approver}, time.Now().UTC())
	var se *store.SuppressionError
	switch {
	case errors.As(err, &se):
		writeErr(w, 400, err)
		return
	case errors.Is(err, store.ErrIssueNotFound):
		writeErr(w, 404, fmt.Errorf("issue not found"))
		return
	case err != nil:
		writeErr(w, 500, err)
		return
	}
	s.Broadcast(Event{Type: "findings_updated"})
	writeJSON(w, map[string]any{"id": id, "state": model.StateSuppressed, "expires_at": req.ExpiresAt.UTC()})
}

// handleCoverage returns the coverage rows (ok / denied / skipped / error / timeout per API
// call) of ?scan_id=, or of the latest scan that recorded coverage.
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	cov, err := s.st.Coverage(r.URL.Query().Get("scan_id"))
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if cov == nil {
		cov = []store.CoverageEntry{}
	}
	writeJSON(w, cov)
}

// ScanRow is one /api/scans row: the stored scan summary plus its Issue trend (null when the
// scan predates the trend columns or another writer saved it).
type ScanRow struct {
	model.ScanSummary
	IssueTrend *store.ScanTrend `json:"issue_trend"`
}

// ScanRows is ScanHistory joined with the per-scan Issue trend (r4 #12).
func ScanRows(st *store.Store, limit int) ([]ScanRow, error) {
	scans, err := ScanHistory(st, limit)
	if err != nil {
		return nil, err
	}
	trends, err := st.ScanTrends(len(scans) + 50)
	if err != nil {
		return nil, err
	}
	by := map[string]*store.ScanTrend{}
	for _, t := range trends {
		by[t.ScanID] = t.Trend
	}
	out := make([]ScanRow, 0, len(scans))
	for _, sc := range scans {
		out = append(out, ScanRow{ScanSummary: sc, IssueTrend: by[sc.ScanID]})
	}
	return out, nil
}

// handleScans returns the scan history, newest first, with per-severity counts and the Issue
// trend of each scan (?limit=, default 100).
func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	scans, err := ScanRows(s.st, limit)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, scans)
}

// ScanHistory reads stored scan summaries, newest first (limit <= 0 → 100). Each summary
// carries total, failed, by_severity and by_provider as recorded when the scan finished.
func ScanHistory(st *store.Store, limit int) ([]model.ScanSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := st.DB().Query("SELECT doc FROM scans ORDER BY started_at DESC, finished_at DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ScanSummary{}
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var sum model.ScanSummary
		if json.Unmarshal([]byte(doc), &sum) == nil {
			if sum.BySeverity == nil {
				sum.BySeverity = map[model.Severity]int{}
			}
			out = append(out, sum)
		}
	}
	return out, rows.Err()
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	// The external (keyed) id or an old raw fingerprint (store.ResolveFindingID).
	id, _ := s.st.ResolveFindingID(r.PathValue("id"))
	f, err := s.st.Finding(id)
	if err != nil {
		writeErr(w, 404, fmt.Errorf("finding not found"))
		return
	}
	paths, _ := s.st.AttackPaths()
	var related []model.AttackPath
	for _, p := range paths {
		for _, id := range p.FindingIDs {
			if id == f.ID {
				related = append(related, p)
			}
		}
	}
	writeJSON(w, map[string]any{"finding": f, "attack_paths": related})
}

func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := s.st.AttackPaths()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, paths)
}

// handleAttackPathIssues lists the stored paths one row per path Issue (attackpath.GroupPaths:
// entry | impact anchor | rule, best variant first, "variants" = the other hop variants) — the
// rows of `paths` and the dashboard's paths view. /api/attack-paths keeps every variant.
func (s *Server) handleAttackPathIssues(w http.ResponseWriter, r *http.Request) {
	paths, err := s.st.AttackPaths()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	groups := attackpath.GroupPaths(paths)
	if groups == nil {
		groups = []attackpath.PathGroup{}
	}
	for i := range groups { // the stored (keyed) Issue id, never the unkeyed digest (MCP-1)
		groups[i].IssueID = s.st.KeyID(groups[i].IssueID)
	}
	writeJSON(w, groups)
}

func (s *Server) loadGraph() (*graph.Graph, error) {
	nodes, edges, err := s.st.LoadGraph()
	if err != nil {
		return nil, err
	}
	g := graph.New()
	for _, n := range nodes {
		var gn graph.Node
		if json.Unmarshal(n.Doc, &gn) == nil {
			g.AddNode(&gn)
		}
	}
	for _, e := range edges {
		var attr map[string]any
		json.Unmarshal(e.Attr, &attr)
		g.AddEdge(e.From, e.To, e.Kind, attr)
	}
	return g, nil
}

func (s *Server) handleAnalysis(w http.ResponseWriter, r *http.Request) {
	g, err := s.loadGraph()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	an := attackpath.Traverse(g, s.traversalOptions(g))
	// Exposures and suppressed exposure are always arrays (never null) for API clients.
	if an.Exposures == nil {
		an.Exposures = []attackpath.Exposure{}
	}
	if an.Suppressed == nil {
		an.Suppressed = []attackpath.Suppressed{}
	}
	writeJSON(w, an)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	g, err := s.loadGraph()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, g.JSON())
}

func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	g, err := s.loadGraph()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	id := r.PathValue("id")
	reach, sens := attackpath.BlastRadius(g, id, 4, nil)
	writeJSON(w, map[string]any{"node": id, "reachable": reach, "sensitive": sens})
}

func (s *Server) handleRisk(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n == 0 {
		n = 50
	}
	fs, err := s.st.Findings(store.Filter{Status: "FAIL"})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	paths, _ := s.st.AttackPaths()
	g, _ := s.loadGraph()
	o := s.riskInputs(g, paths)
	o.Top = n
	ranked := risk.PrioritizeWith(fs, g, paths, o)
	for i := range ranked {
		ranked[i].Finding.Raw = nil
	}
	// One due date: owner / sla_days / due_at come from the finding's Issue (governance).
	if is, err := s.st.Issues(store.IssueFilter{}); err == nil {
		GovernRanked(ranked, is)
	}
	writeJSON(w, ranked)
}

// handleGovernanceMetrics returns MTTR by severity (hours), on-time rate and open / overdue
// Issues by owner, computed from the stored lifecycle history (BuildGovernanceMetrics).
func (s *Server) handleGovernanceMetrics(w http.ResponseWriter, r *http.Request) {
	m, err := BuildGovernanceMetrics(s.st, time.Now().UTC())
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, m)
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	fs, err := s.st.Findings(store.Filter{})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	key := compliance.ResolveKey(r.PathValue("framework"), r.URL.Query().Get("provider"))
	rep, err := compliance.Build(key, fs, r.URL.Query().Get("account"))
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, rep)
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	schema, err := query.Schema(s.st)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, schema)
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SQL) == "" {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body exceeds %d bytes", tooBig.Limit))
			return
		}
		writeErr(w, 400, fmt.Errorf("body must be {\"sql\": \"SELECT ...\"}"))
		return
	}
	timeout := s.QueryTimeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	res, err := query.RunWith(ctx, s.st, body.SQL, "local", query.Options{Timeout: timeout})
	if err != nil {
		code := 400
		switch {
		case errors.Is(err, store.ErrQueryTimeout):
			code = http.StatusRequestTimeout
		case errors.Is(err, store.ErrQueryBusy):
			code = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "1")
		}
		writeErr(w, code, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.Rescan == nil {
		writeErr(w, 501, fmt.Errorf("rescan not configured"))
		return
	}
	go func() {
		s.Broadcast(Event{Type: "scan_started"})
		if err := s.Rescan(context.Background()); err != nil {
			s.Logf("rescan: %v", err)
		}
		s.Broadcast(Event{Type: "findings_updated"})
	}()
	w.WriteHeader(202)
	writeJSON(w, map[string]string{"status": "started"})
}

// WatchDB polls the DB file and broadcasts findings_updated when it changes (covers scans run from another process).
func (s *Server) WatchDB(ctx context.Context, path string, every time.Duration) {
	var last time.Time
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if st, err := os.Stat(path); err == nil {
				if !last.IsZero() && st.ModTime().After(last) {
					s.Broadcast(Event{Type: "findings_updated"})
				}
				last = st.ModTime()
			}
		}
	}
}

// Schedule runs fn on an interval (continuous compliance monitoring) and broadcasts results.
func (s *Server) Schedule(ctx context.Context, every time.Duration, fn func(context.Context) error) {
	if every <= 0 || fn == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Broadcast(Event{Type: "scan_started"})
			if err := fn(ctx); err != nil {
				s.Logf("scheduled scan: %v", err)
			}
			s.Broadcast(Event{Type: "findings_updated"})
		}
	}
}

// HTTPServer returns the configured http.Server (timeouts and header cap) for addr.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if err := ValidateBind(addr, s.Token); err != nil {
		return err
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && s.BindHost == "" {
		s.BindHost = host
	}
	srv := s.HTTPServer(addr)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// pendingRequest is the POST /api/issues/{id}/pending body: what moved the Issue to
// pending_verification (a fix PR URL, a ticket key); optional.
type pendingRequest struct {
	By string `json:"by"`
}

// handleIssuePending moves an open / reopened Issue to pending_verification (a fix was merged or
// applied; the next scan or `verify` settles it). Like suppression it is an attributable write:
// refused without a server token; the recorded source is "<by> via <principal>".
func (s *Server) handleIssuePending(w http.ResponseWriter, r *http.Request) {
	if s.Token == "" {
		writeErr(w, http.StatusForbidden, fmt.Errorf("marking a fix pending over the API needs a server token (serve --token / CLOUD_POSTURE_TOKEN); use `cloud-posture issues mark-pending` locally"))
		return
	}
	var req pendingRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, 400, fmt.Errorf("invalid body: %w", err))
		return
	}
	for _, c := range req.By {
		if c < 0x20 || c == 0x7f {
			writeErr(w, 400, fmt.Errorf("by contains control characters"))
			return
		}
	}
	actor, err := suppressApprover(r)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	by := actor
	if b := strings.TrimSpace(req.By); b != "" {
		by = b + " via " + actor
	}
	id := s.st.ResolveIssueID(r.PathValue("id"))
	err = s.st.MarkPendingVerification(id, by, time.Now().UTC())
	switch {
	case errors.Is(err, store.ErrIssueNotFound):
		writeErr(w, 404, fmt.Errorf("issue not found"))
		return
	case errors.Is(err, store.ErrNotPendable):
		writeErr(w, 409, err)
		return
	case err != nil:
		writeErr(w, 400, err)
		return
	}
	s.Broadcast(Event{Type: "findings_updated"})
	writeJSON(w, map[string]any{"id": id, "state": model.StatePendingVerification, "by": by})
}
