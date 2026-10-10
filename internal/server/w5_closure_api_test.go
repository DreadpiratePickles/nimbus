package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// W5-ISSUES items 1–2 over the API: /api/summary carries the store Headline, the closure states
// filter, POST /api/issues/{id}/pending (token-only) moves an Issue to pending_verification, and
// /api/governance/metrics reports verified vs resolved and regressions after verify.
func TestClosureAndHeadlineAPI(t *testing.T) {
	s, _ := seedLifecycle(t)
	id := seedPathIssue(t, s)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	getJSON := func(path string, v any) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if s.Token != "" {
			req.Header.Set("Authorization", "Bearer "+s.Token)
		}
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
	var sum struct {
		Headline store.Headline `json:"headline"`
	}
	if code := getJSON("/api/summary", &sum); code != 200 {
		t.Fatalf("summary %d", code)
	}
	want, _ := s.st.Headline()
	if sum.Headline.Unit != "issues" || sum.Headline.Issues != want.Issues || sum.Headline.PathIssues != 1 || sum.Headline.Critical != want.Critical {
		t.Fatalf("summary headline %+v, store %+v", sum.Headline, want)
	}
	// Without a token the write is refused.
	if code, _ := post(t, ts, "/api/issues/"+id+"/pending", `{"by":"pr:https://github.com/acme/infra/pull/7"}`, nil); code != http.StatusForbidden {
		t.Fatalf("pending without token: %d", code)
	}
	s.Token = "tok"
	auth := map[string]string{"Authorization": "Bearer tok"}
	if code, body := post(t, ts, "/api/issues/"+id+"/pending", `{"by":"pr:https://github.com/acme/infra/pull/7"}`, auth); code != 200 {
		t.Fatalf("pending: %d %s", code, body)
	}
	var pend []model.Issue
	if code := getJSON("/api/issues?state=pending_verification", &pend); code != 200 || len(pend) != 1 || pend[0].ID != id || pend[0].PendingBy == "" {
		t.Fatalf("state=pending_verification: %d %+v", code, pend)
	}
	if code, _ := post(t, ts, "/api/issues/"+id+"/pending", `{}`, auth); code != 200 {
		t.Errorf("pending is idempotent: %d", code)
	}
	if code, _ := post(t, ts, "/api/issues/nope/pending", `{}`, auth); code != 404 {
		t.Errorf("unknown id: %d", code)
	}
	if err := s.st.RecordVerification(store.Verification{IssueID: id, Result: store.VerifyFixed, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	var vf []model.Issue
	if code := getJSON("/api/issues?state=verified_fixed", &vf); code != 200 || len(vf) != 1 {
		t.Fatalf("state=verified_fixed: %d %+v", code, vf)
	}
	var m GovernanceMetrics
	if code := getJSON("/api/governance/metrics", &m); code != 200 || m.Closure == nil || m.Closure.VerifiedFixed != 1 {
		t.Fatalf("metrics closure: %d %+v", code, m.Closure)
	}
}
