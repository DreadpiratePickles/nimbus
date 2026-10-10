package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Verify-4 LOW (page loop): a server that repeats its rel="next" link (or @odata.nextLink)
// must stop the walk with an error, not loop to the page cap and report success.
func TestRESTGetAllStopsOnRepeatedNextLink(t *testing.T) {
	for _, style := range []string{"link", "odata"} {
		var n int64
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&n, 1)
			next := srv.URL + "/items?page=2"
			if style == "link" {
				w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", next))
				json.NewEncoder(w).Encode([]int{1})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"value": []int{1}, "@odata.nextLink": next})
		}))
		c := &REST{BaseURL: srv.URL, Client: srv.Client()}
		items := 0
		err := c.GetAll(context.Background(), "/items", func(json.RawMessage) error { items++; return nil })
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "repeated") || atomic.LoadInt64(&n) > 3 {
			t.Errorf("%s: %d requests, %d items, err=%v; want a stop with an error", style, n, items, err)
		}
	}
}
