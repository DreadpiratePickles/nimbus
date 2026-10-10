package mcp

// Streamable HTTP transport (W7-VERIFY r5 #14; bar: Sysdig's remote MCP server, tools filtered by
// the token's permissions). `cloud-posture serve --mcp` mounts it at /mcp behind the server's Host
// check, cross-site rejection and body cap (internal/server); the server authenticates the bearer
// token and passes the token's name and scopes here. stdio (`cloud-posture mcp`) stays the
// default transport.
//
// Protocol (MCP 2025-06-18 "Streamable HTTP"): every JSON-RPC message is one POST to /mcp; a
// request is answered with application/json (no SSE stream is needed: no tool streams), a
// notification with 202. initialize creates a session and returns its id in Mcp-Session-Id; every
// later request must carry it. A session belongs to the token that created it (another token gets
// 404, exactly as for an unknown id); its tool list is fixed by that token's scopes at creation.
// GET is 405 (no server-initiated messages); DELETE with the session id ends the session. Idle
// sessions expire. Everything a session does is audited (transport "http", principal = the
// token's name, never the token).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// HTTPOptions configures the HTTP transport. Options.Scopes is ignored (scopes come per token).
type HTTPOptions struct {
	Options
	SessionTTL  time.Duration // idle expiry (default 30 min)
	MaxSessions int           // default 64; the oldest idle session is dropped beyond it
}

// HTTPHandler serves MCP sessions over HTTP for an already authenticated principal.
type HTTPHandler struct {
	st    *store.Store
	opts  HTTPOptions
	audit *auditLog
	mu    sync.Mutex
	sess  map[string]*httpSession
}

type httpSession struct {
	mu        sync.Mutex
	s         *session
	cleanup   func()
	principal string
	last      time.Time
}

// NewHTTPHandler opens the audit log (default beside the database) and returns the handler.
func NewHTTPHandler(st *store.Store, o HTTPOptions) (*HTTPHandler, error) {
	if o.AuditPath == "" {
		o.AuditPath = DefaultAuditPath(st.Path())
	}
	if len(o.FileRoots) == 0 {
		o.FileRoots = DefaultFileRoots(st.Path())
	}
	if o.SessionTTL <= 0 {
		o.SessionTTL = 30 * time.Minute
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = 64
	}
	o.Scopes = nil
	if _, _, err := prepareOptions(o.Options); err != nil {
		return nil, err
	}
	audit, err := openAudit(o.AuditPath)
	if err != nil {
		return nil, err
	}
	return &HTTPHandler{st: st, opts: o, audit: audit, sess: map[string]*httpSession{}}, nil
}

// Close ends every session and closes the audit log.
func (h *HTTPHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, hs := range h.sess {
		hs.cleanup()
		delete(h.sess, id)
	}
	return h.audit.close()
}

const maxMCPBody = 1 << 20

// ServeMCP handles one HTTP request of principal (the token's name) holding scopes.
func (h *HTTPHandler) ServeMCP(w http.ResponseWriter, r *http.Request, principal string, scopes []string) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		h.mu.Lock()
		hs, ok := h.sess[r.Header.Get("Mcp-Session-Id")]
		if ok && hs.principal == principal {
			hs.cleanup()
			delete(h.sess, r.Header.Get("Mcp-Session-Id"))
		}
		h.mu.Unlock()
		if !ok || hs.principal != principal {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed: this server sends no server-initiated messages (POST JSON-RPC to /mcp)", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPBody+1))
	if err != nil || len(body) > maxMCPBody {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	var probe struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(body, &probe)
	sid := r.Header.Get("Mcp-Session-Id")
	var hs *httpSession
	if probe.Method == "initialize" && sid == "" {
		if hs, sid, err = h.create(principal, scopes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if sid == "" {
			http.Error(w, "missing Mcp-Session-Id: send initialize first", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		hs = h.sess[sid]
		h.mu.Unlock()
		if hs == nil || hs.principal != principal {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.last = time.Now()
	var out bytes.Buffer
	hs.s.outMu.Lock()
	hs.s.out = &out
	hs.s.outMu.Unlock()
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	hs.s.handle(ctx, body)
	w.Header().Set("Mcp-Session-Id", sid)
	resp := bytes.TrimSpace(out.Bytes())
	if len(resp) == 0 {
		w.WriteHeader(http.StatusAccepted) // a notification
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(resp)
}

func (h *HTTPHandler) create(principal string, scopes []string) (*httpSession, string, error) {
	o := h.opts.Options
	o.Scopes = scopes
	o, scope, err := prepareOptions(o)
	if err != nil {
		return nil, "", err
	}
	s, cleanup, err := newSession(NewReader(h.st), o, scope, h.audit)
	if err != nil {
		return nil, "", err
	}
	s.principal = principal
	hs := &httpSession{s: s, cleanup: cleanup, principal: principal, last: time.Now()}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for id, x := range h.sess {
		if now.Sub(x.last) > h.opts.SessionTTL {
			x.cleanup()
			delete(h.sess, id)
		}
	}
	for len(h.sess) >= h.opts.MaxSessions {
		oldest := ""
		for id, x := range h.sess {
			if oldest == "" || x.last.Before(h.sess[oldest].last) {
				oldest = id
			}
		}
		h.sess[oldest].cleanup()
		delete(h.sess, oldest)
	}
	id := s.id + randHex(8) // 24 hex: unguessable, distinct from the audit session id prefix
	h.sess[id] = hs
	return hs, id, nil
}

// ParseTokenScopes reads "name=scope1,scope2" (the --mcp-token flag form: the token value itself
// comes from the environment variable name, never from the command line).
func ParseTokenScopes(spec string) (name string, scopes []string, err error) {
	name, list, ok := strings.Cut(spec, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.TrimSpace(list) == "" {
		return "", nil, errors.New("want ENV_VAR=scope[,scope...]")
	}
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	if _, err := ParseScopes(scopes); err != nil {
		return "", nil, err
	}
	return name, scopes, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
