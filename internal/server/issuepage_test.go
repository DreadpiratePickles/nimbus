package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Integration pass 3 item 2: GET /api/issues/{id} serves the full Issue page (same builder as
// `issues show`), keeping the "issue" and "findings" keys of the old shape.
func TestIssueAPIServesIssuePage(t *testing.T) {
	s, _ := seedLifecycle(t)
	id := seedPathIssue(t, s)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/issues/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	var page map[string]json.RawMessage
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"issue", "findings", "hops", "paths", "score", "confidence", "owner", "linked_issues", "fixes", "tickets", "timeline", "suppression"} {
		if _, ok := page[k]; !ok {
			t.Errorf("GET /api/issues/{id} lacks %q: %s", k, b)
		}
	}
	var tl []map[string]any
	json.Unmarshal(page["timeline"], &tl)
	if len(tl) == 0 {
		t.Errorf("timeline empty: %s", page["timeline"])
	}
	if resp, _ := http.Get(ts.URL + "/api/issues/nope"); resp.StatusCode != 404 {
		t.Errorf("unknown issue: %d", resp.StatusCode)
	}
}
