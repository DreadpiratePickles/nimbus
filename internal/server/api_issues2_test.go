package server

// Integration pass 2: path Issues, history, suppression and exposures over the API.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/attackpath"
	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

func seedPathIssue(t *testing.T, s *Server) string {
	t.Helper()
	p := model.AttackPath{ID: "p1", RuleID: "GRAPH_TRAVERSAL", Name: "internet → role/admin", Provider: "aws", Account: "111", Score: 7.6, Severity: model.Critical,
		Steps: []model.Step{{Stage: 1, Relation: "exposes", Resource: "i-web"}, {Stage: 2, Relation: "runs_as", Resource: "role/admin"}}}
	res, err := s.st.RebuildPathIssues("scan-2", &attackpath.Analysis{Paths: []model.AttackPath{p}}, time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC))
	if err != nil || len(res.IDs) != 1 {
		t.Fatalf("seed path issue: %v %+v", err, res)
	}
	return res.IDs[0]
}

func post(t *testing.T, ts *httptest.Server, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPathIssuesAPIHistoryAndSuppress(t *testing.T) {
	s, _ := seedLifecycle(t)
	id := seedPathIssue(t, s)
	s.Token = "tok"
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	auth := map[string]string{"Authorization": "Bearer tok"}
	get := func(path string, v any) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if v != nil && resp.StatusCode == 200 {
			if err := json.Unmarshal(b, v); err != nil {
				t.Fatalf("%s: %v %s", path, err, b)
			}
		}
		return resp.StatusCode
	}
	var paths []model.Issue
	if code := get("/api/issues?kind=path", &paths); code != 200 || len(paths) != 1 || paths[0].ID != id || paths[0].Band != "High" {
		t.Fatalf("kind=path: %d %+v", code, paths)
	}
	var banded []model.Issue
	if code := get("/api/issues?kind=path&band=Critical", &banded); code != 200 || len(banded) != 0 {
		t.Errorf("band filter: %d %+v", code, banded)
	}
	var sum map[string]any
	if get("/api/summary", &sum) != 200 {
		t.Fatal("summary")
	}
	pc, _ := sum["paths"].(map[string]any)
	if pc == nil || pc["open"].(float64) != 1 {
		t.Errorf("/api/summary must include IssueCounts().Paths: %v", sum["paths"])
	}

	body := `{"reason":"compensated by WAF","expires_at":"` + suppressUntilRFC + `"}`
	// CSRF: a cross-site browser request is refused even with the token cookie.
	if code, _ := post(t, ts, "/api/issues/"+url.PathEscape(id)+"/suppress", body, map[string]string{"Authorization": "Bearer tok", "Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}); code != 403 {
		t.Errorf("cross-site suppress: %d, want 403", code)
	}
	if code, _ := post(t, ts, "/api/issues/"+url.PathEscape(id)+"/suppress", body, nil); code != 401 {
		t.Errorf("suppress without token: %d, want 401", code)
	}
	if code, out := post(t, ts, "/api/issues/"+url.PathEscape(id)+"/suppress", `{"reason":""}`, auth); code != 400 {
		t.Errorf("suppress without reason/expiry: %d %s, want 400", code, out)
	}
	if code, _ := post(t, ts, "/api/issues/nope/suppress", body, auth); code != 404 {
		t.Errorf("suppress unknown issue: %d, want 404", code)
	}
	if code, out := post(t, ts, "/api/issues/"+url.PathEscape(id)+"/suppress", body, map[string]string{"Authorization": "Bearer tok", "X-Nimbus-Actor": "alice"}); code != 200 {
		t.Fatalf("suppress: %d %s", code, out)
	}
	var sup []model.Issue
	if get("/api/issues?kind=path&state=suppressed", &sup) != 200 || len(sup) != 1 || sup[0].Reason != "compensated by WAF" || sup[0].ApprovedBy != "alice (api token)" {
		t.Errorf("suppressed listing: %+v", sup)
	}
	var hist []store.PathIssueHistoryEntry
	if code := get("/api/issues/"+url.PathEscape(id)+"/history", &hist); code != 200 || len(hist) != 2 || hist[1].State != model.StateSuppressed {
		t.Errorf("history: %d %+v", code, hist)
	}
	if code := get("/api/issues/nope/history", nil); code != 404 {
		t.Errorf("history of unknown issue: %d", code)
	}
}

// Without a configured token the suppress endpoint is refused: accepting risk is a write
// that must be attributable, so it is never open on an unauthenticated server.
func TestSuppressNeedsServerToken(t *testing.T) {
	s, _ := seedLifecycle(t)
	id := seedPathIssue(t, s)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if code, _ := post(t, ts, "/api/issues/"+url.PathEscape(id)+"/suppress", `{"reason":"r","expires_at":"`+suppressUntilRFC+`"}`, nil); code != 403 {
		t.Errorf("suppress on a token-less server: %d, want 403", code)
	}
}

func TestAnalysisIncludesExposuresAndSuppressed(t *testing.T) {
	s, _ := seedLifecycle(t)
	nodes := []store.GraphNode{
		{ID: "internet", Type: "internet", Doc: []byte(`{"id":"internet","type":"internet"}`)},
		{ID: "i-web", Type: "aws_instance", Provider: "aws", Account: "111", Doc: []byte(`{"id":"i-web","type":"aws_instance","name":"web","provider":"aws","account":"111"}`)},
	}
	edges := []store.GraphEdge{{From: "internet", To: "i-web", Kind: "exposes", Attr: []byte(`{"exposure":"wide","exposure_cidrs":["0.0.0.0/0"],"ports":"443"}`)}}
	if err := s.st.ReplaceGraph(nodes, edges); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	var raw map[string]json.RawMessage
	if getJSON(t, ts, "/api/attack-paths/analysis", &raw) != 200 {
		t.Fatal("analysis")
	}
	var exp []attackpath.Exposure
	if err := json.Unmarshal(raw["exposures"], &exp); err != nil || len(exp) != 1 || exp[0].NodeID != "i-web" {
		t.Errorf("exposures: %s (%v)", raw["exposures"], err)
	}
	if string(raw["suppressed"]) != "[]" {
		t.Errorf("suppressed must be a JSON array: %s", raw["suppressed"])
	}
}
