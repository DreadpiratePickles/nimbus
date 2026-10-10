package saas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
)

// Integration pass 2 item 6: the token POST carries the client secret in its body, and a
// 307/308 makes net/http resend that body to the Location. A redirect to another origin
// must never receive it, and an https → http downgrade is refused (core/rest.go rule).
func TestM365TokenRedirectNeverLeaksSecret(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		var leaked atomic.Bool
		var hits atomic.Int32
		evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "SUPER-SECRET") || strings.Contains(r.URL.RawQuery, "SUPER-SECRET") || r.Header.Get("Authorization") != "" {
				leaked.Store(true)
			}
			w.Write([]byte(`{"access_token":"stolen"}`))
		}))
		login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, evil.URL+"/collect", code)
		}))
		c := &M365{LoginURL: login.URL}
		tok, err := c.token(context.Background(), "tenant", "client", "SUPER-SECRET")
		if leaked.Load() {
			t.Errorf("%d: client secret sent to the redirect target", code)
		}
		if err == nil || tok != "" {
			t.Errorf("%d: cross-origin redirect of the token request must fail, got token %q", code, tok)
		}
		login.Close()
		evil.Close()
	}
}

func TestM365TokenRefusesHTTPSDowngrade(t *testing.T) {
	var hit atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer tls.Close()
	c := &M365{LoginURL: tls.URL, HTTP: tls.Client()}
	_, err := c.token(context.Background(), "tenant", "client", "SUPER-SECRET")
	if !errors.Is(err, core.ErrInsecureRedirect) || hit.Load() {
		t.Fatalf("https → http redirect must be refused with ErrInsecureRedirect (err %v, followed %v)", err, hit.Load())
	}
}

// A same-origin redirect (e.g. a path normalisation on the login host) still works.
func TestM365TokenSameOriginRedirectWorks(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, srv.URL+"/final", http.StatusTemporaryRedirect)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "client_secret=SUPER-SECRET") {
			http.Error(w, "no secret", 400)
			return
		}
		w.Write([]byte(`{"access_token":"ok"}`))
	}))
	defer srv.Close()
	c := &M365{LoginURL: srv.URL}
	if tok, err := c.token(context.Background(), "tenant", "client", "SUPER-SECRET"); err != nil || tok != "ok" {
		t.Fatalf("same-origin redirect: %q %v", tok, err)
	}
}
