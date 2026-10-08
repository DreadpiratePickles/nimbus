// Package server serves the dashboard, a JSON API over the posture database and a WebSocket
// that pushes live updates (new scans, monitor events) to connected dashboards.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	Token     string                           // optional bearer token for write endpoints
}

func New(st *store.Store, dashboard func() ([]byte, error)) *Server {
	return &Server{st: st, dashboard: dashboard, clients: map[*websocket.Conn]bool{},
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}, Logf: log.Printf}
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
	mux.HandleFunc("GET /api/attack-paths", s.handleAttackPaths)
	mux.HandleFunc("GET /api/attack-paths/analysis", s.handleAnalysis)
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/graph/blast-radius/{id...}", s.handleBlastRadius)
	mux.HandleFunc("GET /api/risk/top", s.handleRisk)
	mux.HandleFunc("GET /api/compliance/{framework}", s.handleCompliance)
	mux.HandleFunc("GET /api/schema", s.handleSchema)
	mux.HandleFunc("POST /api/query", s.handleQuery)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	return withCORS(mux)
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:")
	w.Write(html)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
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

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	fs, err := s.st.Findings(store.Filter{})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	paths, _ := s.st.AttackPaths()
	last, _ := s.st.LastScan()
	sum := Summarize(fs, paths)
	sum["last_scan"] = last
	writeJSON(w, sum)
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
	fl := store.Filter{Status: q.Get("status"), Provider: q.Get("provider"), Account: q.Get("account"), CanonicalID: q.Get("canonical_id"), Source: q.Get("source"), Limit: limit}
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

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	f, err := s.st.Finding(r.PathValue("id"))
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
	an := attackpath.Traverse(g, attackpath.DefaultTraversalOptions())
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
	ranked := risk.Prioritize(fs, g, paths, risk.DefaultWeights, n, time.Now())
	for i := range ranked {
		ranked[i].Finding.Raw = nil
	}
	writeJSON(w, ranked)
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
		writeErr(w, 400, fmt.Errorf("body must be {\"sql\": \"SELECT ...\"}"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := query.Run(ctx, s.st, body.SQL, "local")
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.Token {
		writeErr(w, 401, fmt.Errorf("unauthorized"))
		return
	}
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

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
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
