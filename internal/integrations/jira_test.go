package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestJiraDeliver(t *testing.T) {
	f := sampleFinding(model.Critical)
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("bot@example.com:tok"))
	tests := []struct {
		name       string
		searchCode int    // status for /search/jql
		searchBody string // body for search
		createCode int
		wantRef    string
		wantPost   bool
		wantErr    bool
	}{
		{"existing issue", 200, `{"issues":[{"key":"SEC-7"}]}`, 201, "/browse/SEC-7", false, false},
		{"create new", 200, `{"issues":[]}`, 201, "/browse/SEC-42", true, false},
		{"fallback legacy search", 404, `{"issues":[]}`, 201, "/browse/SEC-42", true, false},
		{"create fails", 200, `{"issues":[]}`, 400, "", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/rest/api/3/search/jql":
					w.WriteHeader(tc.searchCode)
					_, _ = w.Write([]byte(tc.searchBody))
				case r.URL.Path == "/rest/api/3/search":
					_, _ = w.Write([]byte(tc.searchBody))
				case r.URL.Path == "/rest/api/3/issue" && r.Method == http.MethodPost:
					w.WriteHeader(tc.createCode)
					_, _ = w.Write([]byte(`{"id":"1","key":"SEC-42"}`))
				default:
					w.WriteHeader(500)
				}
			})
			j := NewJira(srv.URL+"/", "bot@example.com", "tok", "SEC", "")
			j.Labels = []string{"team-sec"}
			ref, err := j.Deliver(context.Background(), f, samplePaths())
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if !tc.wantErr && ref != srv.URL+tc.wantRef {
				t.Fatalf("ref %q", ref)
			}
			reqs := rec.all()
			var posted *captured
			for i, r := range reqs {
				if r.Header.Get("Authorization") != wantAuth {
					t.Fatalf("bad auth %q", r.Header.Get("Authorization"))
				}
				if strings.HasPrefix(r.Path, "/rest/api/3/search") {
					q, _ := url.ParseQuery(r.Query)
					if q.Get("jql") != `project = "SEC" AND labels = "cp-`+f.ID+`"` || q.Get("maxResults") != "1" {
						t.Fatalf("bad jql %q", q.Get("jql"))
					}
				}
				if r.Method == http.MethodPost {
					posted = &reqs[i]
				}
			}
			if (posted != nil) != tc.wantPost {
				t.Fatalf("post = %v want %v", posted != nil, tc.wantPost)
			}
			if posted == nil {
				return
			}
			var body struct {
				Fields struct {
					Project     map[string]string `json:"project"`
					IssueType   map[string]string `json:"issuetype"`
					Summary     string            `json:"summary"`
					Labels      []string          `json:"labels"`
					Description map[string]any    `json:"description"`
				} `json:"fields"`
			}
			if err := json.Unmarshal(posted.Body, &body); err != nil {
				t.Fatal(err)
			}
			fl := body.Fields
			if fl.Project["key"] != "SEC" || fl.IssueType["name"] != "Task" || !strings.HasPrefix(fl.Summary, "[CRITICAL] S3_PUBLIC_BUCKET") {
				t.Fatalf("bad fields %+v", fl)
			}
			want := []string{"cloud-posture", "cp-" + f.ID, "severity-critical", "provider-aws", "team-sec"}
			if strings.Join(fl.Labels, ",") != strings.Join(want, ",") {
				t.Fatalf("labels %v", fl.Labels)
			}
			if fl.Description["type"] != "doc" || fl.Description["version"] != float64(1) {
				t.Fatalf("not ADF: %v", fl.Description)
			}
			adf := string(posted.Body)
			for _, w := range []string{`"heading"`, `"bulletList"`, `"codeBlock"`, "cloud-posture fix --finding S3_PUBLIC_BUCKET", "Public bucket data theft"} {
				if !strings.Contains(adf, w) {
					t.Errorf("ADF missing %s", w)
				}
			}
		})
	}
}

func TestJiraRequiresConfig(t *testing.T) {
	if _, err := NewJira("", "", "", "", "").Deliver(context.Background(), sampleFinding(model.High), nil); err == nil {
		t.Fatal("expected error")
	}
}
