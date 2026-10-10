package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// V2 defect 8: credential headers must never follow a pagination link to another host.
func TestRESTCrossHostLinkDropsCredentials(t *testing.T) {
	var leakedAuth, leakedKey atomic.Value
	var evilHits int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&evilHits, 1)
		leakedAuth.Store(r.Header.Get("Authorization"))
		leakedKey.Store(r.Header.Get("X-Api-Key"))
		fmt.Fprint(w, `[]`)
	}))
	defer evil.Close()
	var sameAuth atomic.Value
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/x" {
			w.Header().Set("Link", `<`+srv.URL+`/page2>; rel="next"`)
		} else {
			sameAuth.Store(r.Header.Get("Authorization"))
			w.Header().Set("Link", `<`+evil.URL+`/page3>; rel="next"`)
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	c := &REST{BaseURL: srv.URL, Backoff: time.Millisecond, Headers: map[string]string{"Authorization": "SSWS S3CR3T", "X-Api-Key": "k"}}
	_ = c.GetAll(context.Background(), "/x", func(_ json.RawMessage) error { return nil })
	if v, _ := sameAuth.Load().(string); v != "SSWS S3CR3T" {
		t.Errorf("same-host pagination must keep the Authorization header, got %q", v)
	}
	if v, _ := leakedAuth.Load().(string); v != "" {
		t.Errorf("Authorization header sent to a cross-host pagination URL: %q", v)
	}
	if v, _ := leakedKey.Load().(string); v != "" {
		t.Errorf("configured credential header sent cross-host: %q", v)
	}
}
