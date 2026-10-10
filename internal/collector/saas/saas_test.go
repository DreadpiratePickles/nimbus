package saas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// statuses indexes findings by checkID|resourceID -> status.
func statuses(r core.Result) map[string]model.Status {
	out := map[string]model.Status{}
	for _, f := range r.Findings {
		out[f.CheckID+"|"+f.Resource.ID] = f.Status
	}
	return out
}

func hasEdge(g *graph.Graph, from, to, kind string) bool {
	for _, e := range g.Out(from) {
		if e.To == to && e.Kind == kind {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- GitHub

func githubServer(t *testing.T, twoFA any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gh-tok" {
			t.Errorf("auth header = %q", got)
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("missing api version header")
		}
		switch {
		case r.URL.Path == "/orgs/acme":
			writeJSON(w, map[string]any{"login": "acme", "two_factor_requirement_enabled": twoFA, "created_at": "2020-01-01T00:00:00Z"})
		case r.URL.Path == "/orgs/acme/repos" && r.URL.Query().Get("page") == "":
			if r.URL.Query().Get("per_page") != "100" || r.URL.Query().Get("type") != "all" {
				t.Errorf("bad repo query %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?per_page=100&type=all&page=2>; rel="next", <%s/orgs/acme/repos?page=2>; rel="last"`, srv.URL, srv.URL))
			writeJSON(w, []map[string]any{
				{"name": "api", "full_name": "acme/api", "private": false, "visibility": "public", "default_branch": "main", "topics": []string{"prod"},
					"security_and_analysis": map[string]any{"secret_scanning": map[string]any{"status": "enabled"}}},
				{"name": "web", "full_name": "acme/web", "private": true, "visibility": "private", "default_branch": "main",
					"security_and_analysis": map[string]any{"secret_scanning": map[string]any{"status": "disabled"}}},
			})
		case r.URL.Path == "/orgs/acme/repos":
			writeJSON(w, []map[string]any{{"name": "infra", "full_name": "acme/infra", "private": true, "default_branch": "trunk"}})
		case r.URL.Path == "/repos/acme/api/branches/main/protection":
			writeJSON(w, map[string]any{"url": "x"})
		case r.URL.Path == "/repos/acme/web/branches/main/protection":
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "Branch not protected"})
		case r.URL.Path == "/repos/acme/infra/branches/trunk/protection":
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, map[string]any{"message": "Upgrade to GitHub Pro"})
		case r.URL.Path == "/repos/acme/infra":
			writeJSON(w, map[string]any{"name": "infra", "security_and_analysis": map[string]any{"secret_scanning": map[string]any{"status": "enabled"}}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubCollect(t *testing.T) {
	cases := []struct {
		name     string
		twoFA    any
		want     map[string]model.Status
		warnings int
	}{
		{"2fa enforced", true, map[string]model.Status{
			"organization_members_mfa_required|github:org/acme":                 model.Pass,
			"repository_default_branch_protection_enabled|github:repo/acme/api": model.Pass,
			"repository_default_branch_protection_enabled|github:repo/acme/web": model.Fail,
			"repository_secret_scanning_enabled|github:repo/acme/api":           model.Pass,
			"repository_secret_scanning_enabled|github:repo/acme/web":           model.Fail,
			"repository_secret_scanning_enabled|github:repo/acme/infra":         model.Pass,
		}, 1},
		{"2fa not enforced", false, map[string]model.Status{"organization_members_mfa_required|github:org/acme": model.Fail}, 1},
		{"2fa invisible", nil, map[string]model.Status{}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_TOKEN", "gh-tok")
			srv := githubServer(t, tc.twoFA)
			c := &GitHub{BaseURL: srv.URL, Now: fixedNow, Concurrency: 2, Backoff: time.Millisecond}
			g := graph.New()
			res, err := c.Collect(context.Background(), core.AccountSpec{Provider: "github", Org: "acme"}, g)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Errors) != 0 {
				t.Fatalf("errors: %v", res.Errors)
			}
			got := statuses(res)
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("%s = %q, want %q", k, got[k], want)
				}
			}
			if _, ok := got["organization_members_mfa_required|github:org/acme"]; tc.twoFA == nil && ok {
				t.Errorf("2FA finding emitted without visibility")
			}
			if len(res.Warnings) != tc.warnings {
				t.Errorf("warnings = %v, want %d", res.Warnings, tc.warnings)
			}
			for _, f := range res.Findings {
				if f.Source != "nimbus" || f.CanonicalID == "" || f.CanonicalID == "NIMBUS:"+f.CheckID {
					t.Errorf("finding not enriched: %+v", f)
				}
			}
			if !hasEdge(g, "github:org/acme", "github:repo/acme/infra", graph.EdgeContains) {
				t.Error("missing org->repo contains edge (page 2)")
			}
			if !hasEdge(g, graph.InternetNodeID, "github:repo/acme/api", graph.EdgeExposes) {
				t.Error("missing internet->public repo edge")
			}
			if hasEdge(g, graph.InternetNodeID, "github:repo/acme/web", graph.EdgeExposes) {
				t.Error("private repo exposed")
			}
			if n, _ := g.Node("github:repo/acme/web"); tc.twoFA == true && (n == nil || len(n.FindingIDs) == 0) {
				t.Error("fail findings not attached to repo node")
			}
		})
	}
}

func TestGitHubMissingConfig(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	c := NewGitHub()
	if _, err := c.Collect(context.Background(), core.AccountSpec{}, graph.New()); err == nil || !strings.Contains(err.Error(), "Org") {
		t.Errorf("want org error, got %v", err)
	}
	if _, err := c.Collect(context.Background(), core.AccountSpec{Org: "x"}, graph.New()); err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("want token error, got %v", err)
	}
}

func TestGitHubRetriesServerErrors(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-tok")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			writeJSON(w, map[string]any{"login": "acme", "two_factor_requirement_enabled": true})
		case "/orgs/acme/repos":
			writeJSON(w, []any{})
		}
	}))
	defer srv.Close()
	c := &GitHub{BaseURL: srv.URL, Backoff: time.Millisecond}
	res, err := c.Collect(context.Background(), core.AccountSpec{Org: "acme"}, graph.New())
	if err != nil || len(res.Findings) != 1 || calls.Load() != 3 {
		t.Fatalf("err=%v findings=%d calls=%d", err, len(res.Findings), calls.Load())
	}
}

// ---------------------------------------------------------------- Okta

func TestOktaCollect(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "SSWS okta-tok" {
			t.Errorf("auth header = %q", got)
		}
		switch r.URL.Path {
		case "/api/v1/users":
			if r.URL.Query().Get("after") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/users?limit=200>; rel="self", <%s/api/v1/users?after=u2&limit=200>; rel="next"`, srv.URL, srv.URL))
				writeJSON(w, []map[string]any{
					{"id": "u1", "status": "ACTIVE", "profile": map[string]any{"login": "alice@acme.io"}},
					{"id": "u2", "status": "ACTIVE", "profile": map[string]any{"login": "bob@acme.io"}},
				})
				return
			}
			writeJSON(w, []map[string]any{{"id": "u3", "status": "ACTIVE", "profile": map[string]any{"login": "carol@acme.io"}}})
		case "/api/v1/users/u1/roles":
			writeJSON(w, []map[string]any{{"type": "SUPER_ADMIN", "status": "ACTIVE"}})
		case "/api/v1/users/u2/roles":
			writeJSON(w, []map[string]any{{"type": "ORG_ADMIN", "status": "ACTIVE"}})
		case "/api/v1/users/u3/roles":
			writeJSON(w, []any{})
		case "/api/v1/users/u1/factors":
			writeJSON(w, []map[string]any{{"factorType": "token:software:totp", "status": "ACTIVE"}})
		case "/api/v1/users/u2/factors":
			writeJSON(w, []map[string]any{{"factorType": "sms", "status": "PENDING_ACTIVATION"}})
		case "/api/v1/users/u3/factors":
			t.Error("factors fetched for non-admin")
		case "/api/v1/policies":
			if r.URL.Query().Get("type") != "OKTA_SIGN_ON" {
				t.Errorf("policy type %q", r.URL.Query().Get("type"))
			}
			writeJSON(w, []map[string]any{
				{"id": "p1", "name": "Default", "status": "ACTIVE"},
				{"id": "p2", "name": "Strict", "status": "ACTIVE"},
				{"id": "p3", "name": "Old", "status": "INACTIVE"},
			})
		case "/api/v1/policies/p1/rules":
			writeJSON(w, []map[string]any{{"name": "r", "status": "ACTIVE", "actions": map[string]any{"signon": map[string]any{"access": "ALLOW", "requireFactor": false}}}})
		case "/api/v1/policies/p2/rules":
			writeJSON(w, []map[string]any{{"name": "r", "status": "ACTIVE", "actions": map[string]any{"signon": map[string]any{"access": "ALLOW", "requireFactor": true}}}})
		default:
			t.Errorf("unexpected %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("OKTA_API_TOKEN", "okta-tok")
	c := &Okta{OrgURL: srv.URL, Now: fixedNow, Backoff: time.Millisecond}
	g := graph.New()
	res, err := c.Collect(context.Background(), core.AccountSpec{Provider: "okta"}, g)
	if err != nil || len(res.Errors) > 0 {
		t.Fatalf("err=%v errors=%v", err, res.Errors)
	}
	want := map[string]model.Status{
		"okta_admin_user_mfa_enrolled|okta:user/u1":      model.Pass,
		"okta_admin_user_mfa_enrolled|okta:user/u2":      model.Fail,
		"okta_sign_on_policy_require_mfa|okta:policy/p1": model.Fail,
		"okta_sign_on_policy_require_mfa|okta:policy/p2": model.Pass,
	}
	got := statuses(res)
	if len(got) != len(want) {
		t.Errorf("got %d findings %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q want %q", k, got[k], v)
		}
	}
	for _, f := range res.Findings {
		if f.CanonicalID != "OKTA_ADMIN_NO_MFA" && f.CanonicalID != "OKTA_NO_MFA_POLICY" {
			t.Errorf("canonical id %q", f.CanonicalID)
		}
	}
	n, ok := g.Node("okta:user/u3")
	if !ok || n.Type != "okta_user" || n.Name != "carol@acme.io" {
		t.Errorf("paginated user node missing: %+v", n)
	}
	if a, _ := g.Node("okta:user/u1"); a == nil || a.Attributes["admin"] != true {
		t.Errorf("admin attr missing")
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	if !hasEdge(g, core.AccountNodeID("okta", host), "okta:policy/p3", graph.EdgeContains) {
		t.Error("account->policy contains edge missing")
	}
}

// Defect 15(f): Okta evaluates sign-on rules in priority order and the first match
// wins, so an earlier allow-without-MFA rule (or a catch-all without MFA) is a bypass
// even when some other rule requires MFA.
func TestOktaSignOnRule(t *testing.T) {
	parse := func(js string) []oktaRule {
		var rs []oktaRule
		if err := json.Unmarshal([]byte(js), &rs); err != nil {
			t.Fatal(err)
		}
		return rs
	}
	const (
		mfaAll     = `{"name":"mfa-all","status":"ACTIVE","priority":%d,"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`
		noMFAAll   = `{"name":"no-mfa-all","status":"ACTIVE","priority":%d,"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}`
		defaultNo  = `{"name":"Default Rule","status":"ACTIVE","priority":99,"system":true,"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}`
		defaultMFA = `{"name":"Default Rule","status":"ACTIVE","priority":99,"system":true,"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`
		onNetNoMFA = `{"name":"on-network","status":"ACTIVE","priority":%d,"conditions":{"network":{"connection":"ZONE","include":["corp"]}},"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}`
		groupMFA   = `{"name":"admins-mfa","status":"ACTIVE","priority":%d,"conditions":{"people":{"groups":{"include":["g-admins"]}}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`
		denyAll    = `{"name":"deny","status":"ACTIVE","priority":%d,"actions":{"signon":{"access":"DENY"}}}`
	)
	cases := []struct {
		name  string
		rules string
		want  bool
	}{
		{"none", `[]`, false},
		{"catch-all requires mfa", "[" + fmt.Sprintf(mfaAll, 1) + "]", true},
		{"inactive mfa", `[{"name":"x","status":"INACTIVE","actions":{"signon":{"access":"ALLOW","requireFactor":true}}}]`, false},
		{"deny only", "[" + fmt.Sprintf(denyAll, 1) + "]", false},
		// The old "any rule" logic passed these:
		{"group rule mfa but default rule allows without mfa", "[" + fmt.Sprintf(groupMFA, 1) + "," + defaultNo + "]", false},
		{"higher-priority no-mfa catch-all shadows mfa rule", "[" + fmt.Sprintf(mfaAll, 2) + "," + fmt.Sprintf(noMFAAll, 1) + "]", false},
		{"on-network bypass before mfa catch-all", "[" + fmt.Sprintf(onNetNoMFA, 1) + "," + defaultMFA + "]", false},
		// Positive: an mfa catch-all ahead of a no-mfa default makes the default unreachable.
		{"mfa catch-all before no-mfa default", "[" + defaultNo + "," + fmt.Sprintf(mfaAll, 1) + "]", true},
		{"group mfa then default mfa", "[" + fmt.Sprintf(groupMFA, 1) + "," + defaultMFA + "]", true},
		{"deny catch-all after group mfa", "[" + fmt.Sprintf(groupMFA, 1) + "," + fmt.Sprintf(denyAll, 2) + "]", true},
	}
	for _, tc := range cases {
		got, why := signOnRequiresMFA(parse(tc.rules))
		if got != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.name, got, why, tc.want)
		}
		if why == "" {
			t.Errorf("%s: empty explanation", tc.name)
		}
	}
}

func TestOktaMissingConfig(t *testing.T) {
	t.Setenv("OKTA_ORG_URL", "")
	t.Setenv("OKTA_API_TOKEN", "")
	if _, err := NewOkta().Collect(context.Background(), core.AccountSpec{}, graph.New()); err == nil || !strings.Contains(err.Error(), "OKTA_ORG_URL") {
		t.Errorf("got %v", err)
	}
	if _, err := NewOkta().Collect(context.Background(), core.AccountSpec{Domain: "acme.okta.com"}, graph.New()); err == nil || !strings.Contains(err.Error(), "OKTA_API_TOKEN") {
		t.Errorf("got %v", err)
	}
}

// ---------------------------------------------------------------- M365

type m365Fixture struct {
	regStatus int
	policies  []map[string]any
	groups    map[string][]string // user id -> transitive group ids
}

const (
	roleGlobalAdmin   = "62e90394-69f5-4237-9190-012177145e10"
	roleSecurityAdmin = "194ae4cb-b126-40b2-bd5b-6091b380977d"
	roleDirReaders    = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
)

func m365Server(t *testing.T, fx m365Fixture) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "sec" ||
				r.Form.Get("scope") != "https://graph.microsoft.com/.default" {
				t.Errorf("bad token form %v", r.Form)
			}
			writeJSON(w, map[string]any{"access_token": "graph-tok"})
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer graph-tok" {
			t.Errorf("auth header %q on %s", got, r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1.0/users":
			if r.URL.Query().Get("$skiptoken") == "" {
				writeJSON(w, map[string]any{"value": []map[string]any{
					{"id": "a1", "userPrincipalName": "admin1@acme.io"},
					{"id": "a2", "userPrincipalName": "admin2@acme.io"},
				}, "@odata.nextLink": srv.URL + "/v1.0/users?$skiptoken=p2"})
				return
			}
			writeJSON(w, map[string]any{"value": []map[string]any{{"id": "u3", "userPrincipalName": "user@acme.io"}}})
		case "/v1.0/directoryRoles":
			writeJSON(w, map[string]any{"value": []map[string]any{
				{"displayName": "Global Administrator", "roleTemplateId": roleGlobalAdmin, "members": []map[string]any{{"id": "a1"}}},
				{"displayName": "Security Administrator", "roleTemplateId": roleSecurityAdmin, "members": []map[string]any{{"id": "a2"}}},
				{"displayName": "Directory Readers", "roleTemplateId": roleDirReaders, "members": []map[string]any{{"id": "u3"}}},
			}})
		case "/v1.0/reports/authenticationMethods/userRegistrationDetails":
			if fx.regStatus != 0 {
				w.WriteHeader(fx.regStatus)
				return
			}
			writeJSON(w, map[string]any{"value": []map[string]any{
				{"id": "a1", "isMfaRegistered": true}, {"id": "a2", "isMfaRegistered": false}, {"id": "u3", "isMfaRegistered": false},
			}})
		case "/v1.0/identity/conditionalAccess/policies":
			writeJSON(w, map[string]any{"value": fx.policies})
		case "/v1.0/users/a1/transitiveMemberOf", "/v1.0/users/a2/transitiveMemberOf":
			id := strings.Split(r.URL.Path, "/")[3]
			var vals []map[string]any
			for _, gid := range fx.groups[id] {
				vals = append(vals, map[string]any{"id": gid})
			}
			writeJSON(w, map[string]any{"value": vals})
		default:
			t.Errorf("unexpected %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func caMFAAll(state string) map[string]any {
	return map[string]any{"displayName": "MFA all", "state": state,
		"conditions": map[string]any{"users": map[string]any{"includeUsers": []string{"All"}},
			"applications": map[string]any{"includeApplications": []string{"All"}}}, // Graph always returns applications
		"grantControls": map[string]any{"builtInControls": []string{"mfa"}}}
}

func caBlockLegacy(state string) map[string]any {
	return map[string]any{"displayName": "Block legacy", "state": state,
		"conditions": map[string]any{"clientAppTypes": []string{"exchangeActiveSync", "other"}, "users": map[string]any{"includeUsers": []string{"All"}},
			"applications": map[string]any{"includeApplications": []string{"All"}}},
		"grantControls": map[string]any{"builtInControls": []string{"block"}}}
}

func TestM365Collect(t *testing.T) {
	cases := []struct {
		name     string
		fx       m365Fixture
		want     map[string]model.Status
		warnings int
	}{
		{"no CA", m365Fixture{}, map[string]model.Status{
			"entra_admin_users_mfa_enabled|m365:user/a1":               model.Pass,
			"entra_admin_users_mfa_enabled|m365:user/a2":               model.Fail,
			"entra_legacy_authentication_blocked|m365:tenant/tenant-1": model.Fail,
		}, 0},
		{"CA covers", m365Fixture{policies: []map[string]any{caMFAAll("enabled"), caBlockLegacy("enabled")}}, map[string]model.Status{
			"entra_admin_users_mfa_enabled|m365:user/a1":               model.Pass,
			"entra_admin_users_mfa_enabled|m365:user/a2":               model.Pass,
			"entra_legacy_authentication_blocked|m365:tenant/tenant-1": model.Pass,
		}, 0},
		{"report-only CA ignored", m365Fixture{policies: []map[string]any{caMFAAll("enabledForReportingButNotEnforced"), caBlockLegacy("disabled")}}, map[string]model.Status{
			"entra_admin_users_mfa_enabled|m365:user/a2":               model.Fail,
			"entra_legacy_authentication_blocked|m365:tenant/tenant-1": model.Fail,
		}, 0},
		{"registration forbidden", m365Fixture{regStatus: http.StatusForbidden, policies: []map[string]any{caMFAAll("enabled")}}, map[string]model.Status{
			"entra_admin_users_mfa_enabled|m365:user/a1": model.Pass,
			"entra_admin_users_mfa_enabled|m365:user/a2": model.Pass,
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := m365Server(t, tc.fx)
			c := &M365{TenantID: "tenant-1", ClientID: "cid", ClientSecret: "sec", GraphURL: srv.URL + "/v1.0", LoginURL: srv.URL, Now: fixedNow, Backoff: time.Millisecond}
			g := graph.New()
			res, err := c.Collect(context.Background(), core.AccountSpec{Provider: "m365"}, g)
			if err != nil || len(res.Errors) > 0 {
				t.Fatalf("err=%v errors=%v", err, res.Errors)
			}
			got := statuses(res)
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %q want %q (all %v)", k, got[k], v, got)
				}
			}
			if _, ok := got["entra_admin_users_mfa_enabled|m365:user/u3"]; ok {
				t.Error("non-admin evaluated")
			}
			if len(res.Warnings) != tc.warnings {
				t.Errorf("warnings %v", res.Warnings)
			}
			if n, ok := g.Node("m365:user/u3"); !ok || n.Name != "user@acme.io" {
				t.Error("nextLink page not followed")
			}
			if !hasEdge(g, core.AccountNodeID("m365", "tenant-1"), "m365:user/a1", graph.EdgeContains) {
				t.Error("tenant contains edge missing")
			}
		})
	}
}

func TestM365MissingConfig(t *testing.T) {
	for _, k := range []string{"M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"} {
		t.Setenv(k, "")
	}
	_, err := NewM365().Collect(context.Background(), core.AccountSpec{}, graph.New())
	if err == nil || !strings.Contains(err.Error(), "M365_TENANT_ID") {
		t.Errorf("got %v", err)
	}
	_, err = NewM365().Collect(context.Background(), core.AccountSpec{TenantID: "t"}, graph.New())
	if err == nil || !strings.Contains(err.Error(), "M365_CLIENT_ID") {
		t.Errorf("got %v", err)
	}
}

func TestM365TokenFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()
	c := &M365{TenantID: "t", ClientID: "c", ClientSecret: "s", LoginURL: srv.URL, GraphURL: srv.URL}
	if _, err := c.Collect(context.Background(), core.AccountSpec{}, graph.New()); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("got %v", err)
	}
}

// Defect 20: a GitHub rate-limit 403 must surface as a rate_limited collection error,
// not a silent "check skipped" warning.
func TestGitHubRateLimitIsCollectionError(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			writeJSON(w, map[string]any{"login": "acme", "two_factor_requirement_enabled": true})
		case "/orgs/acme/repos":
			writeJSON(w, []map[string]any{{"name": "api", "full_name": "acme/api", "visibility": "private", "default_branch": "main"}})
		default:
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", fmt.Sprint(time.Now().Add(time.Hour).Unix()))
			w.WriteHeader(http.StatusForbidden)
			writeJSON(w, map[string]any{"message": "API rate limit exceeded"})
		}
	}))
	defer srv.Close()
	c := &GitHub{BaseURL: srv.URL, Now: fixedNow, Concurrency: 1, Backoff: time.Millisecond}
	res, err := c.Collect(context.Background(), core.AccountSpec{Provider: "github", Org: "acme"}, graph.New())
	if err != nil {
		t.Fatal(err)
	}
	ces := res.CollectErrors()
	if len(ces) != 1 || ces[0].Reason != core.ReasonRateLimited || !strings.Contains(ces[0].API, "acme/api") {
		t.Fatalf("collect errors = %+v (warnings %v)", ces, res.Warnings)
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "acme/api") {
			t.Errorf("rate limit still reported as a skip warning: %q", w)
		}
	}
	if _, ok := statuses(res)["repository_default_branch_protection_enabled|github:repo/acme/api"]; ok {
		t.Error("no branch-protection verdict may be emitted when rate limited")
	}
}

// Defect 15(e): conditional access must target the admin (all users, the admin's own
// role, or a group they are in) and must not exclude them.
func TestM365ConditionalAccessTargetsAndExclusions(t *testing.T) {
	mfaPolicy := func(users map[string]any) map[string]any {
		return map[string]any{"displayName": "MFA", "state": "enabled", "conditions": map[string]any{"users": users,
			"applications": map[string]any{"includeApplications": []string{"All"}}},
			"grantControls": map[string]any{"builtInControls": []string{"mfa"}}}
	}
	cases := []struct {
		name string
		fx   m365Fixture
		want model.Status // for a2 (Security Administrator, no MFA registered)
	}{
		{"policy on an unrelated role is not coverage", m365Fixture{policies: []map[string]any{mfaPolicy(map[string]any{"includeRoles": []string{roleDirReaders}})}}, model.Fail},
		{"policy on the admin's role covers", m365Fixture{policies: []map[string]any{mfaPolicy(map[string]any{"includeRoles": []string{roleGlobalAdmin, roleSecurityAdmin}})}}, model.Pass},
		{"all users but admin excluded by user", m365Fixture{policies: []map[string]any{mfaPolicy(map[string]any{"includeUsers": []string{"All"}, "excludeUsers": []string{"a2"}})}}, model.Fail},
		{"admin role excluded", m365Fixture{policies: []map[string]any{mfaPolicy(map[string]any{"includeUsers": []string{"All"}, "excludeRoles": []string{roleSecurityAdmin}})}}, model.Fail},
		{"admin in excluded group", m365Fixture{groups: map[string][]string{"a2": {"g-bypass"}}, policies: []map[string]any{mfaPolicy(map[string]any{"includeUsers": []string{"All"}, "excludeGroups": []string{"g-bypass"}})}}, model.Fail},
		{"excluded group without the admin still covers", m365Fixture{groups: map[string][]string{"a2": {"g-other"}}, policies: []map[string]any{mfaPolicy(map[string]any{"includeUsers": []string{"All"}, "excludeGroups": []string{"g-bypass"}})}}, model.Pass},
		{"exclusion of a non-admin still covers", m365Fixture{policies: []map[string]any{mfaPolicy(map[string]any{"includeUsers": []string{"All"}, "excludeUsers": []string{"u3"}})}}, model.Pass},
		{"included via group", m365Fixture{groups: map[string][]string{"a2": {"g-admins"}}, policies: []map[string]any{mfaPolicy(map[string]any{"includeGroups": []string{"g-admins"}})}}, model.Pass},
		{"single-app policy is not coverage", m365Fixture{policies: []map[string]any{{"displayName": "MFA portal", "state": "enabled",
			"conditions":    map[string]any{"users": map[string]any{"includeUsers": []string{"All"}}, "applications": map[string]any{"includeApplications": []string{"797f4846-ba00-4fd7-ba43-dac1f8f63013"}}},
			"grantControls": map[string]any{"builtInControls": []string{"mfa"}}}}}, model.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := m365Server(t, tc.fx)
			c := &M365{TenantID: "tenant-1", ClientID: "cid", ClientSecret: "sec", GraphURL: srv.URL + "/v1.0", LoginURL: srv.URL, Now: fixedNow, Backoff: time.Millisecond}
			res, err := c.Collect(context.Background(), core.AccountSpec{Provider: "m365"}, graph.New())
			if err != nil || len(res.Errors) > 0 {
				t.Fatalf("err=%v errors=%v", err, res.Errors)
			}
			if got := statuses(res)["entra_admin_users_mfa_enabled|m365:user/a2"]; got != tc.want {
				t.Errorf("a2 = %q, want %q", got, tc.want)
			}
		})
	}
}
