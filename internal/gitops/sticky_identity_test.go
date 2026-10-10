package gitops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Verify-4 defect 5 (TestZZV4StickyHumanMarker): with no --bot-login, the sticky comment must be
// the token's own comment; a human comment that starts with the marker is never edited.
func TestStickyDefaultsToTokenIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, userStatus, actions string
		wantErr                   bool
		wantPatched               int64
	}{
		{name: "PAT identity from /user", userStatus: "nimbus-bot", wantPatched: 9},
		{name: "Actions token: /user is 403, identity is github-actions[bot]", userStatus: "403", actions: "true", wantPatched: 8},
		{name: "unknown identity outside Actions: refuse", userStatus: "403", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_ACTIONS", tc.actions)
			comments := []map[string]any{
				{"id": 7, "body": PlanDiffMarker + "\nI am a human, all good", "user": map[string]any{"login": "mallory"}},
				{"id": 8, "body": PlanDiffMarker + "\nold", "user": map[string]any{"login": "github-actions[bot]"}},
				{"id": 9, "body": PlanDiffMarker + "\nold", "user": map[string]any{"login": "nimbus-bot"}},
			}
			var patched []string
			userCalls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/user":
					userCalls++
					if tc.userStatus == "403" {
						w.WriteHeader(403)
						w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"login": tc.userStatus})
				case r.Method == http.MethodGet:
					json.NewEncoder(w).Encode(comments)
				case r.Method == http.MethodPatch:
					patched = append(patched, r.URL.Path)
					w.Write([]byte("{}"))
				default:
					w.WriteHeader(201)
					w.Write([]byte("{}"))
				}
			}))
			defer srv.Close()
			act, err := StickyComment(context.Background(), StickyOptions{BaseURL: srv.URL, HTTP: srv.Client(), OwnerRepo: "o/r", PR: 1, Token: "tok", Marker: PlanDiffMarker}, "body")
			for _, p := range patched {
				if strings.HasSuffix(p, "/7") {
					t.Fatalf("human comment 7 (mallory) was PATCHed")
				}
			}
			if tc.wantErr {
				if err == nil || len(patched) > 0 {
					t.Fatalf("want an error and no edit, got act=%s err=%v patched=%v", act, err, patched)
				}
				return
			}
			if err != nil || act != "updated" || len(patched) != 1 || !strings.HasSuffix(patched[0], "/"+jsonNum(tc.wantPatched)) {
				t.Fatalf("act=%s err=%v patched=%v, want comment %d", act, err, patched, tc.wantPatched)
			}
			if userCalls != 1 {
				t.Errorf("/user fetched %d times, want once", userCalls)
			}
		})
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }
