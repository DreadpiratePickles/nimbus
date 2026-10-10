package gitops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/iac"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// fakeIssues is a GitHub issue-comments API with pagination (Link rel="next").
type fakeIssues struct {
	mu       sync.Mutex
	comments []map[string]any
	posts    int
	patches  int
	pageSize int
	auth     []string
}

func (f *fakeIssues) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/user":
			json.NewEncoder(w).Encode(map[string]any{"login": "github-actions[bot]"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			page := 1
			fmt.Sscan(r.URL.Query().Get("page"), &page)
			lo, hi := (page-1)*f.pageSize, page*f.pageSize
			if hi > len(f.comments) {
				hi = len(f.comments)
			}
			if lo > hi {
				lo = hi
			}
			if hi < len(f.comments) {
				next := fmt.Sprintf("http://%s%s?per_page=%d&page=%d", r.Host, r.URL.Path, f.pageSize, page+1)
				w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"next\"", next))
			}
			json.NewEncoder(w).Encode(f.comments[lo:hi])
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			f.posts++
			id := 1000 + len(f.comments)
			f.comments = append(f.comments, map[string]any{"id": id, "body": b["body"], "user": map[string]any{"login": "github-actions[bot]"}})
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"id": id})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/comments/"):
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			f.patches++
			for _, c := range f.comments {
				if fmt.Sprint(c["id"]) == r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
					c["body"] = b["body"]
				}
			}
			json.NewEncoder(w).Encode(map[string]any{})
		default:
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(404)
		}
	})
}

func TestStickyCommentEditsNeverDuplicates(t *testing.T) {
	f := &fakeIssues{pageSize: 2}
	for i := 0; i < 5; i++ { // the marker sits on page 3
		f.comments = append(f.comments, map[string]any{"id": i + 1, "body": fmt.Sprintf("human comment %d", i), "user": map[string]any{"login": "dev"}})
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	o := StickyOptions{BaseURL: srv.URL, HTTP: srv.Client(), OwnerRepo: "acme/infra", PR: 7, Token: "t0k", Marker: PlanDiffMarker}
	ctx := context.Background()
	act, err := StickyComment(ctx, o, "first body")
	if err != nil || act != "created" || f.posts != 1 {
		t.Fatalf("first: %s %v posts=%d", act, err, f.posts)
	}
	f.comments = append(f.comments, map[string]any{"id": 99, "body": "later human comment", "user": map[string]any{"login": "dev"}})
	act, err = StickyComment(ctx, o, "second body")
	if err != nil || act != "updated" || f.posts != 1 || f.patches != 1 {
		t.Fatalf("second: %s %v posts=%d patches=%d", act, err, f.posts, f.patches)
	}
	n := 0
	for _, c := range f.comments {
		if strings.Contains(fmt.Sprint(c["body"]), PlanDiffMarker) {
			n++
			if !strings.Contains(fmt.Sprint(c["body"]), "second body") {
				t.Errorf("sticky body not updated: %v", c["body"])
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d sticky comments, want exactly 1", n)
	}
	for _, a := range f.auth {
		if a != "Bearer t0k" {
			t.Fatalf("auth header %q", a)
		}
	}
	// A human comment that quotes the marker is never edited: only bot-authored comments are.
	f2 := &fakeIssues{pageSize: 100, comments: []map[string]any{{"id": 5, "body": "quoting " + PlanDiffMarker, "user": map[string]any{"login": "dev"}}}}
	srv2 := httptest.NewServer(f2.handler(t))
	defer srv2.Close()
	o.BaseURL, o.HTTP, o.BotLogin = srv2.URL, srv2.Client(), "github-actions[bot]"
	if act, err := StickyComment(ctx, o, "x"); err != nil || act != "created" || f2.patches != 0 {
		t.Fatalf("human marker comment edited: %s %v", act, err)
	}
}

func TestStickyCommentErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/user" {
			w.Write([]byte(`{"login":"github-actions[bot]"}`))
			return
		}
		if r.Method == http.MethodGet {
			w.Write([]byte("[]"))
			return
		}
		w.WriteHeader(403) // fork PR: read-only token
	}))
	defer srv.Close()
	_, err := StickyComment(context.Background(), StickyOptions{BaseURL: srv.URL, HTTP: srv.Client(), OwnerRepo: "a/b", PR: 7, Token: "x", Marker: PlanDiffMarker}, "b")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403 error, got %v", err)
	}
	if _, err := StickyComment(context.Background(), StickyOptions{OwnerRepo: "../x", PR: 7, Marker: PlanDiffMarker}, "b"); err == nil {
		t.Fatal("invalid repo accepted")
	}
}

// RM2 / plan §8: every generated fix PR body carries the north-star footer.
func TestPRFooterPresent(t *testing.T) {
	ps := []iac.Patch{{CanonicalID: "S3_PUBLIC_BUCKET", Address: "aws_s3_bucket.x", File: "main.tf", Explanation: "e", Diff: "d"}}
	for _, paths := range [][]model.AttackPath{nil, {{Name: "a", Impact: "b", Score: 7}, {Name: "c", Impact: "d", Score: 5}}} {
		body := PRBody(ps, nil, paths)
		if !strings.Contains(body, fmt.Sprintf("nimbus-closes-paths: %d", len(paths))) {
			t.Errorf("footer missing for %d paths:\n%s", len(paths), body)
		}
	}
}
