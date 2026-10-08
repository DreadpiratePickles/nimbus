package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

func TestCheckFinding(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name, check, alias, canonical string
		pass                          bool
		wantStatus                    model.Status
		wantSev                       model.Severity
	}{
		{"prowler fail", "s3_bucket_public_access", "", "S3_PUBLIC_BUCKET", false, model.Fail, model.High},
		{"prowler pass", "ec2_instance_imdsv2_enabled", "", "EC2_IMDSV1", true, model.Pass, model.High},
		{"steampipe okta", "okta_admin_user_mfa_enrolled", "steampipe", "OKTA_ADMIN_NO_MFA", false, model.Fail, model.Critical},
		{"steampipe fallback", "okta_sign_on_policy_require_mfa", "", "OKTA_NO_MFA_POLICY", false, model.Fail, model.Critical},
		{"unknown check", "made_up_check", "", "NIMBUS:made_up_check", false, model.Fail, model.Info},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Check{CheckID: tc.check, AliasSource: tc.alias, Provider: "aws", Account: "1", AccountLabel: "prod", Resource: model.Resource{ID: "r1"}, Pass: tc.pass, Detail: "d"}.Finding(now)
			if f.Source != Source || f.CanonicalID != tc.canonical || f.Status != tc.wantStatus || f.Severity != tc.wantSev {
				t.Fatalf("got source=%s canonical=%s status=%s sev=%s", f.Source, f.CanonicalID, f.Status, f.Severity)
			}
			if f.ID == "" || f.ID != f.Fingerprint() || f.Description != "d" || f.Tags["account_label"] != "prod" || f.Title == "" {
				t.Fatalf("not finalized: %+v", f)
			}
			if tc.canonical != "NIMBUS:made_up_check" && (len(f.Weaknesses) == 0 || f.Resource.Type == "") {
				t.Fatalf("not enriched: %+v", f)
			}
		})
	}
}

func TestAttachFindingKeepsNodeShape(t *testing.T) {
	g := graph.New()
	id := EnsureAccount(g, "aws", "1", "prod")
	f := Check{CheckID: "iam_root_mfa_enabled", Provider: "aws", Account: "1", Resource: model.Resource{ID: id}}.Finding(time.Now())
	AttachFinding(g, f)
	pass := Check{CheckID: "iam_root_mfa_enabled", Provider: "aws", Account: "1", Resource: model.Resource{ID: "other"}, Pass: true}.Finding(time.Now())
	AttachFinding(g, pass)
	n, _ := g.Node(id)
	if n.Class != graph.ClassAccount || n.Type != "aws_account" || n.Name != "prod" || !n.HasWeakness("NO_MFA") || len(n.FindingIDs) != 1 {
		t.Fatalf("node = %+v", n)
	}
	if _, ok := g.Node("other"); ok {
		t.Fatal("PASS findings must not create nodes")
	}
}

func TestResNodeContext(t *testing.T) {
	cases := []struct {
		name      string
		res       Res
		sensitive bool
		crit      string
		owner     string
	}{
		{"pii tag", Res{Resource: model.Resource{ID: "b", Type: "aws_s3_bucket", Name: "assets"}, Tags: map[string]string{"DataClassification": "PII", "Owner": "data-team"}}, true, "unknown", "data-team"},
		{"name hint on datastore", Res{Resource: model.Resource{ID: "b", Type: "aws_s3_bucket", Name: "customer-exports"}, Tags: map[string]string{"env": "staging"}}, true, "staging", ""},
		{"name hint ignored on compute", Res{Resource: model.Resource{ID: "i", Type: "aws_instance", Name: "payment-api"}, Tags: map[string]string{"Environment": "production", "team": "pay"}}, false, "production", "pay"},
		{"forced", Res{Resource: model.Resource{ID: "s", Type: "aws_secretsmanager_secret", Name: "x"}, ForceSensitive: true}, true, "unknown", ""},
		{"dev from name", Res{Resource: model.Resource{ID: "v", Type: "azure_virtual_machine", Name: "dev-box"}}, false, "dev", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.res.Created = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
			n := tc.res.Node()
			if n.Sensitive != tc.sensitive || n.Criticality != tc.crit || n.Owner != tc.owner || n.ModifiedAt != "2025-01-02T03:04:05Z" {
				t.Fatalf("got sensitive=%v crit=%s owner=%s mod=%s", n.Sensitive, n.Criticality, n.Owner, n.ModifiedAt)
			}
			if len(tc.res.Tags) > 0 {
				if _, ok := n.Attributes["tags"].(map[string]any); !ok {
					t.Fatal("tags attribute missing")
				}
			}
		})
	}
}

func TestAddResourceContainsEdge(t *testing.T) {
	g := graph.New()
	id := AddResource(g, Res{Provider: "gcp", Account: "proj", Resource: model.Resource{ID: "x", Type: "gcp_storage_bucket"}})
	acct := AccountNodeID("gcp", "proj")
	found := false
	for _, e := range g.Out(acct) {
		found = found || (e.To == id && e.Kind == graph.EdgeContains)
	}
	if !found {
		t.Fatal("missing contains edge")
	}
	if n, _ := g.Node(acct); n.Type != "gcp_project" {
		t.Fatalf("account type = %s", n.Type)
	}
	if AddResource(g, Res{}) != "" {
		t.Fatal("empty resource should be ignored")
	}
}

func TestPortsHelpers(t *testing.T) {
	if Ports(22, 22) != "22" || Ports(0, 65535) != "all" || Ports(1000, 2000) != "1000-2000" || Ports(-1, -1) != "all" {
		t.Fatal("Ports")
	}
	cases := []struct {
		port, from, to int32
		want           bool
	}{{22, 22, 22, true}, {22, 0, 1024, true}, {3389, 22, 22, false}, {22, -1, -1, true}, {22, 0, 0, true}}
	for _, c := range cases {
		if PortInRange(c.port, c.from, c.to) != c.want {
			t.Errorf("PortInRange(%d,%d,%d)", c.port, c.from, c.to)
		}
	}
	for s, want := range map[string]bool{"0.0.0.0/0": true, "::/0": true, "Internet": true, "*": true, "10.0.0.0/8": false} {
		if IsOpenCIDR(s) != want {
			t.Errorf("IsOpenCIDR(%s)", s)
		}
	}
}

func TestRunTasks(t *testing.T) {
	var acc Acc
	var inFlight, maxSeen int32
	var tasks []Task
	for i := 0; i < 10; i++ {
		tasks = append(tasks, Task{Name: fmt.Sprintf("t%d", i), Fn: func(ctx context.Context) error {
			n := atomic.AddInt32(&inFlight, 1)
			defer atomic.AddInt32(&inFlight, -1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			switch i {
			case 3:
				return errors.New("bad")
			case 5:
				panic("oops")
			}
			acc.Finding(model.Finding{ID: fmt.Sprint(i)})
			return nil
		}})
	}
	RunTasks(context.Background(), 2, &acc, tasks)
	r := acc.Result()
	if len(r.Findings) != 8 || len(r.Errors) != 2 || maxSeen > 2 {
		t.Fatalf("findings=%d errors=%v max=%d", len(r.Findings), r.Errors, maxSeen)
	}
	if !strings.Contains(r.Err().Error(), "t3: bad") || !strings.Contains(r.Err().Error(), "t5: panic") {
		t.Fatalf("err = %v", r.Err())
	}
}

func TestRESTPagination(t *testing.T) {
	var srv *httptest.Server
	var hits int32
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/link":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/link?page=2>; rel="next", <%s/link?page=2>; rel="last"`, srv.URL, srv.URL))
				json.NewEncoder(w).Encode([]map[string]int{{"n": 1}, {"n": 2}})
				return
			}
			json.NewEncoder(w).Encode([]map[string]int{{"n": 3}})
		case "/odata":
			if r.URL.Query().Get("skip") == "" {
				json.NewEncoder(w).Encode(map[string]any{"value": []map[string]int{{"n": 1}}, "@odata.nextLink": srv.URL + "/odata?skip=1"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]int{{"n": 2}}})
		case "/flaky":
			if atomic.AddInt32(&hits, 1) < 3 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
		case "/missing":
			w.WriteHeader(404)
			w.Write([]byte(`{"message":"Not Found"}`))
		}
	}))
	defer srv.Close()
	c := &REST{BaseURL: srv.URL, Headers: map[string]string{"Authorization": "Bearer tok"}, Backoff: time.Millisecond}
	for _, tc := range []struct {
		path string
		want int
	}{{"/link", 3}, {"odata", 2}} {
		n := 0
		if err := c.GetAll(context.Background(), tc.path, func(json.RawMessage) error { n++; return nil }); err != nil || n != tc.want {
			t.Errorf("%s: n=%d err=%v", tc.path, n, err)
		}
	}
	var out map[string]string
	if _, err := c.Get(context.Background(), "/flaky", &out); err != nil || out["ok"] != "yes" {
		t.Errorf("retry: %v %v", out, err)
	}
	_, err := c.Get(context.Background(), "/missing", nil)
	if StatusOf(err) != 404 {
		t.Errorf("status = %d (%v)", StatusOf(err), err)
	}
	bad := &REST{BaseURL: srv.URL, Backoff: time.Millisecond}
	if _, err := bad.Get(context.Background(), "/link", nil); StatusOf(err) != 401 {
		t.Errorf("unauthorized: %v", err)
	}
}

func TestNextLink(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<https://x/a?page=1>; rel="prev", <https://x/a?page=3>; rel="next"`)
	if got := NextLink(h); got != "https://x/a?page=3" {
		t.Fatalf("NextLink = %q", got)
	}
	if NextLink(http.Header{}) != "" {
		t.Fatal("empty header")
	}
}

func TestSpecLabelAndToken(t *testing.T) {
	if (AccountSpec{Provider: "aws", Profile: "p"}).Label() != "p" || (AccountSpec{Name: "n", Profile: "p"}).Label() != "n" {
		t.Fatal("Label")
	}
	t.Setenv("CUSTOM_TOK", "abc")
	t.Setenv("GITHUB_TOKEN", "def")
	if Token(AccountSpec{TokenEnv: "CUSTOM_TOK"}, "GITHUB_TOKEN") != "abc" || Token(AccountSpec{}, "GITHUB_TOKEN") != "def" {
		t.Fatal("Token")
	}
}
