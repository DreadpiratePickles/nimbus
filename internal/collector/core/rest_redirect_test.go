package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Verify-3 defect 6: a redirect to another origin must not carry Authorization or
// the configured credential headers, and an https→http redirect is refused.

type seenHeaders struct {
	mu   sync.Mutex
	hits []http.Header
}

func (s *seenHeaders) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, r.Header.Clone())
}

func (s *seenHeaders) leaked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, h := range s.hits {
		for _, k := range []string{"Authorization", "X-Api-Key"} {
			if v := h.Get(k); v != "" {
				out = append(out, k+"="+v)
			}
		}
	}
	return out
}

func TestRESTRedirectToOtherOriginStripsCredentials(t *testing.T) {
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusMovedPermanently, http.StatusPermanentRedirect} {
		other := &seenHeaders{}
		evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			other.record(r)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		}))
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, evil.URL+"/steal", code)
		}))
		rc := &REST{BaseURL: origin.URL, Client: origin.Client(), Backoff: 1,
			Headers: map[string]string{"Authorization": "SSWS SECRET-TOKEN", "X-Api-Key": "SECRET-KEY"}}
		var out map[string]any
		_, err := rc.Get(context.Background(), "/api/v1/users", &out)
		if err != nil {
			t.Errorf("%d: cross-origin redirect without credentials should still be followed: %v", code, err)
		}
		if l := other.leaked(); len(l) > 0 {
			t.Errorf("%d: credentials leaked to the redirect target: %v", code, l)
		}
		if len(other.hits) == 0 {
			t.Errorf("%d: redirect target never reached", code)
		}
		evil.Close()
		origin.Close()
	}
}

func TestRESTRedirectSameOriginKeepsCredentials(t *testing.T) {
	seen := &seenHeaders{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, srv.URL+"/new", http.StatusFound)
			return
		}
		seen.record(r)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	rc := &REST{BaseURL: srv.URL, Client: srv.Client(), Backoff: 1, Headers: map[string]string{"Authorization": "SSWS T", "X-Api-Key": "K"}}
	if _, err := rc.Get(context.Background(), "/old", nil); err != nil {
		t.Fatal(err)
	}
	if l := seen.leaked(); len(l) != 2 {
		t.Errorf("same-origin redirect should keep credentials, saw %v", l)
	}
}

func TestRESTRedirectHTTPSToHTTPRefused(t *testing.T) {
	plain := &seenHeaders{}
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain.record(r)
		w.Write([]byte(`{}`))
	}))
	defer insecure.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecure.URL+"/x", http.StatusFound)
	}))
	defer tlsSrv.Close()
	rc := &REST{BaseURL: tlsSrv.URL, Client: tlsSrv.Client(), Backoff: 1, MaxRetries: 1, Headers: map[string]string{"Authorization": "SSWS T"}}
	_, err := rc.Get(context.Background(), "/a", nil)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("https→http redirect must be refused, err=%v", err)
	}
	if len(plain.hits) != 0 {
		t.Errorf("plain-http target was contacted %d time(s)", len(plain.hits))
	}
}

// A redirect chain origin → other → origin: the hop to "other" carries nothing.
func TestRESTRedirectChainStripsOnEveryForeignHop(t *testing.T) {
	foreign := &seenHeaders{}
	var origin *httptest.Server
	mid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign.record(r)
		http.Redirect(w, r, origin.URL+"/final", http.StatusTemporaryRedirect)
	}))
	defer mid.Close()
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, mid.URL+"/hop", http.StatusFound)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer origin.Close()
	rc := &REST{BaseURL: origin.URL, Client: origin.Client(), Backoff: 1, Headers: map[string]string{"Authorization": "Bearer X", "X-Api-Key": "K"}}
	if _, err := rc.Get(context.Background(), "/start", nil); err != nil {
		t.Fatal(err)
	}
	if l := foreign.leaked(); len(l) > 0 {
		t.Errorf("credentials leaked on the foreign hop: %v", l)
	}
}
