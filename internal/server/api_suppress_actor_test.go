package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
	"github.com/DreadpiratePickles/nimbus/internal/store"
)

// Item 13 (verify-4 LOW: client-asserted approved_by): the approver of a suppression comes from
// the authenticated principal — the server token, named by X-Nimbus-Actor when the caller sets
// it — never from the request body. A body that asserts approved_by is refused.
func TestSuppressApproverComesFromPrincipal(t *testing.T) {
	s, _ := seedLifecycle(t)
	id := seedPathIssue(t, s)
	s.Token = "tok"
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	p := "/api/issues/" + url.PathEscape(id) + "/suppress"
	approver := func() string {
		var sup []model.Issue
		for _, is := range mustIssues(t, s) {
			if is.ID == id {
				sup = append(sup, is)
			}
		}
		if len(sup) != 1 {
			t.Fatalf("issue %s not found", id)
		}
		return sup[0].ApprovedBy
	}
	spoof := `{"reason":"waf","expires_at":"` + suppressUntilRFC + `","approved_by":"ciso"}`
	if code, out := post(t, ts, p, spoof, map[string]string{"Authorization": "Bearer tok"}); code != 400 || !strings.Contains(out, "approved_by") {
		t.Fatalf("body approved_by must be refused: %d %s", code, out)
	}
	body := `{"reason":"waf","expires_at":"` + suppressUntilRFC + `"}`
	if code, out := post(t, ts, p, body, map[string]string{"Authorization": "Bearer tok", "X-Nimbus-Actor": "alice@example.com"}); code != 200 {
		t.Fatalf("suppress: %d %s", code, out)
	}
	if got := approver(); got != "alice@example.com (api token)" {
		t.Errorf("approved_by = %q, want the actor of the token", got)
	}
	if code, out := post(t, ts, p, body, map[string]string{"Authorization": "Bearer tok"}); code != 200 {
		t.Fatalf("suppress: %d %s", code, out)
	}
	if got := approver(); got != "api token" {
		t.Errorf("approved_by without an actor = %q, want the token principal", got)
	}
	bad := strings.Repeat("x", 200)
	if code, _ := post(t, ts, p, body, map[string]string{"Authorization": "Bearer tok", "X-Nimbus-Actor": bad}); code != 400 {
		t.Errorf("oversized actor header must be refused: %d", code)
	}
}

func mustIssues(t *testing.T, s *Server) []model.Issue {
	t.Helper()
	is, err := s.st.Issues(store.IssueFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return is
}
