package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// W7-VERIFY r5 #9 (bar: Vanta's resources API for private integrations, compliance-and-adjacent.md
// "Features nimbus should steal" #1): nimbus pushes one flat custom resource per evaluated cloud
// resource with a full-state PUT — every sync carries the complete set, and anything omitted is
// deleted by Vanta — so the exporter refuses to send an empty or truncated set, and the dry run
// says what the PUT would add and delete.

type vantaMock struct {
	mu       sync.Mutex
	srv      *httptest.Server
	tokens   int
	puts     []map[string]any
	auth     []string
	putCode  int
	tokenErr bool
}

func newVantaMock(t *testing.T) *vantaMock {
	m := &vantaMock{putCode: 200}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/oauth/token":
			var req map[string]string
			json.Unmarshal(body, &req)
			if m.tokenErr || req["client_id"] != "cid" || req["client_secret"] != "secret" || req["grant_type"] != "client_credentials" ||
				!strings.Contains(req["scope"], "connectors.self:write-resource") {
				w.WriteHeader(401)
				return
			}
			m.tokens++
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-1", "expires_in": 3600, "token_type": "Bearer"})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/resources/custom_resource":
			var doc map[string]any
			json.Unmarshal(body, &doc)
			m.puts = append(m.puts, doc)
			m.auth = append(m.auth, r.Header.Get("Authorization"))
			w.WriteHeader(m.putCode)
			w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(m.srv.Close)
	SetAllowPrivateSinks(true)
	t.Cleanup(func() { SetAllowPrivateSinks(false) })
	return m
}

func vantaInputs() ([]model.Finding, []model.Issue) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	f := func(id, res string, st model.Status, sev model.Severity) model.Finding {
		x := model.Finding{ID: id, Source: "native", CheckID: id, CanonicalID: strings.ToUpper(id), Status: st, Severity: sev, Provider: "aws",
			Account: "111111111111", Resource: model.Resource{ID: res, Type: "aws_s3_bucket", Name: res[strings.LastIndex(res, ":")+1:]}, LastSeen: now}
		return x
	}
	fs := []model.Finding{
		f("f1", "arn:aws:s3:::pii", model.Fail, model.Critical),
		f("f2", "arn:aws:s3:::pii", model.Pass, model.Medium),
		f("f3", "arn:aws:s3:::logs", model.Pass, model.Low),
	}
	is := []model.Issue{
		{ID: "i1", Kind: model.IssueSingle, ResourceID: "arn:aws:s3:::pii", Severity: model.Critical, State: model.StateOpen, Provider: "aws", Account: "111111111111"},
		{ID: "p1", Kind: model.IssuePath, AnchorID: "arn:aws:s3:::pii", ResourceID: "arn:aws:s3:::pii", Severity: model.Critical, State: model.StateOpen, Score: 9.4},
		{ID: "i2", Kind: model.IssueSingle, ResourceID: "arn:aws:s3:::logs", Severity: model.High, State: model.StateResolved},
	}
	return fs, is
}

func TestVantaResourcesAreFlat(t *testing.T) {
	fs, is := vantaInputs()
	rs := BuildVantaResources(fs, is, VantaBuildOptions{ExternalURLBase: "https://nimbus.example.com"})
	if len(rs) != 2 {
		t.Fatalf("resources = %+v", rs)
	}
	byID := map[string]VantaResource{}
	for _, r := range rs {
		byID[r.UniqueID] = r
		for k, v := range r.CustomProperties {
			switch v.(type) {
			case bool, int32, string:
			default:
				t.Errorf("%s.%s is %T: Vanta custom properties are flat boolean / int32 / string / timestamp", r.UniqueID, k, v)
			}
		}
	}
	pii := byID["arn:aws:s3:::pii"]
	p := pii.CustomProperties
	if p["open_issues"] != int32(2) || p["open_critical"] != int32(2) || p["on_attack_path"] != true || p["nimbus_pass"] != false ||
		p["failing_checks"] != int32(1) || p["passing_checks"] != int32(1) || p["max_path_score_x10"] != int32(94) {
		t.Errorf("pii properties = %v", p)
	}
	if pii.DisplayName != "pii" || !strings.HasPrefix(pii.ExternalURL, "https://nimbus.example.com/#node?arg=") {
		t.Errorf("pii display / url = %q %q", pii.DisplayName, pii.ExternalURL)
	}
	if lp := byID["arn:aws:s3:::logs"].CustomProperties; lp["nimbus_pass"] != true || lp["open_issues"] != int32(0) {
		t.Errorf("logs (only a resolved Issue) must pass: %v", lp)
	}
}

func TestVantaSyncFullStateDryRunAndGuards(t *testing.T) {
	m := newVantaMock(t)
	fs, is := vantaInputs()
	rs := BuildVantaResources(fs, is, VantaBuildOptions{})
	v := &Vanta{BaseURL: m.srv.URL, ClientID: "cid", ClientSecret: "secret", ResourceID: "res-type-1"}
	ctx := context.Background()

	// Dry run: no request at all; the diff against the last synced set names what Vanta would delete.
	res, err := v.Sync(ctx, rs, VantaSyncOptions{DryRun: true, Previous: []string{"arn:aws:s3:::logs", "arn:aws:s3:::gone"}})
	if err != nil {
		t.Fatal(err)
	}
	if m.tokens != 0 || len(m.puts) != 0 || !res.DryRun || len(res.Removed) != 1 || res.Removed[0] != "arn:aws:s3:::gone" || len(res.Added) != 1 || len(res.Kept) != 1 {
		t.Fatalf("dry run = %+v (tokens %d puts %d)", res, m.tokens, len(m.puts))
	}
	if !strings.Contains(res.Text(), "would delete 1") {
		t.Errorf("dry-run text = %q", res.Text())
	}

	// Real sync: one token, one PUT with the complete set.
	res, err = v.Sync(ctx, rs, VantaSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if m.tokens != 1 || len(m.puts) != 1 || m.auth[0] != "Bearer tok-1" || res.Sent != 2 {
		t.Fatalf("sync: tokens %d puts %d auth %v res %+v", m.tokens, len(m.puts), m.auth, res)
	}
	put := m.puts[0]
	if put["resourceId"] != "res-type-1" || len(put["resources"].([]any)) != 2 {
		t.Fatalf("PUT body = %v", put)
	}
	r0 := put["resources"].([]any)[0].(map[string]any)
	for _, k := range []string{"displayName", "uniqueId", "customProperties"} {
		if _, ok := r0[k]; !ok {
			t.Errorf("resource lacks %s: %v", k, r0)
		}
	}

	// Guards: an empty set would delete everything in Vanta; a set over the cap would have to be
	// truncated (= deletions). Both are refused before any request.
	if _, err := v.Sync(ctx, nil, VantaSyncOptions{}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty set: %v", err)
	}
	if _, err := v.Sync(ctx, nil, VantaSyncOptions{AllowEmpty: true, DryRun: true}); err != nil {
		t.Errorf("an explicit empty dry run is allowed: %v", err)
	}
	small := &Vanta{BaseURL: m.srv.URL, ClientID: "cid", ClientSecret: "secret", ResourceID: "r", MaxResources: 1}
	if _, err := small.Sync(ctx, rs, VantaSyncOptions{}); err == nil || !strings.Contains(err.Error(), "full-state") {
		t.Errorf("over the cap: %v", err)
	}
	dup := append(append([]VantaResource{}, rs...), rs[0])
	if _, err := v.Sync(ctx, dup, VantaSyncOptions{}); err == nil || !strings.Contains(err.Error(), "uniqueId") {
		t.Errorf("duplicate uniqueId: %v", err)
	}
	if len(m.puts) != 1 {
		t.Errorf("a refused sync sent a PUT")
	}
	// Errors: a 4xx is reported with the status; bad credentials fail at the token.
	m.putCode = 422
	if _, err := v.Sync(ctx, rs, VantaSyncOptions{}); err == nil || !strings.Contains(err.Error(), "422") {
		t.Errorf("PUT 422: %v", err)
	}
	bad := &Vanta{BaseURL: m.srv.URL, ClientID: "cid", ClientSecret: "wrong", ResourceID: "r"}
	if _, err := bad.Sync(ctx, rs, VantaSyncOptions{}); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("bad secret: %v (the secret must never appear in errors)", err)
	}
	if _, err := (&Vanta{BaseURL: m.srv.URL}).Sync(ctx, rs, VantaSyncOptions{}); err == nil || !strings.Contains(err.Error(), "VANTA_CLIENT_ID") {
		t.Errorf("missing config: %v", err)
	}
}

// The custom test recipe ships with the exporter (VantaCustomTestRecipe; `issues export --to vanta --recipe`).
func TestVantaRecipeNamesTheProperties(t *testing.T) {
	r := VantaCustomTestRecipe()
	for _, want := range []string{"nimbus_pass", "open_critical", "on_attack_path", "omitted", "deleted"} {
		if !strings.Contains(r, want) {
			t.Errorf("recipe lacks %q", want)
		}
	}
}
