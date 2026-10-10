package integrations

// Vanta export (W7-VERIFY r5 #9; bar: Vanta's resources API for private integrations, and the
// "Features nimbus should steal" #1 of docs/research/competitors/compliance-and-adjacent.md).
//
// nimbus becomes an evidence source inside the customer's GRC tool: one Vanta custom resource per
// cloud resource nimbus evaluated, with flat properties (boolean / int32 / string / timestamp —
// the only types the API accepts), and a Vanta Custom Test that fails a resource when nimbus says
// it should (VantaCustomTestRecipe).
//
// The API is FULL-STATE: "Every PUT must contain the complete set of resources … Any resource
// omitted from a sync is treated as no longer existing and will be marked as deleted"
// (developer.vanta.com/docs/concepts/resources.md). So Sync sends exactly one PUT with every
// resource, and refuses — before any request — a set that is empty (it would delete everything;
// AllowEmpty overrides), larger than MaxResources (sending only part would delete the rest), or
// that repeats a uniqueId. The dry run sends nothing and diffs the set against the previous sync
// (the caller keeps the list), naming what Vanta would delete.
//
// Auth: OAuth client credentials (POST /oauth/token, scope connectors.self:write-resource) with
// VANTA_CLIENT_ID / VANTA_CLIENT_SECRET; the resource type id of the private integration is
// VANTA_RESOURCE_ID. Secrets are never logged or echoed in errors. Requests go through the sink
// client (https only, no private / metadata addresses, no redirects off the origin).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/model"
)

const (
	DefaultVantaBaseURL      = "https://api.vanta.com"
	DefaultVantaMaxResources = 10000
	vantaScope               = "connectors.self:write-resource connectors.self:read-resource"
)

// VantaResource is one custom resource (the API's field names).
type VantaResource struct {
	DisplayName      string         `json:"displayName"`
	UniqueID         string         `json:"uniqueId"`
	ExternalURL      string         `json:"externalUrl,omitempty"`
	CustomProperties map[string]any `json:"customProperties"`
}

// VantaBuildOptions configures BuildVantaResources.
type VantaBuildOptions struct {
	// ExternalURLBase is where the nimbus dashboard is served (`cloud-posture serve`); each
	// resource deep-links to its node there. Empty: no externalUrl.
	ExternalURLBase string
}

// BuildVantaResources makes one resource per cloud resource in findings (any status: a resource
// whose checks all pass is evidence too), with its Issue counts from issues.
func BuildVantaResources(findings []model.Finding, issues []model.Issue, o VantaBuildOptions) []VantaResource {
	type acc struct {
		name, typ, provider, account string
		lastSeen                     time.Time
		fail, pass                   int32
		open, crit, high             int32
		onPath                       bool
		maxPath                      float64
	}
	by := map[string]*acc{}
	get := func(id string) *acc {
		a := by[id]
		if a == nil {
			a = &acc{}
			by[id] = a
		}
		return a
	}
	for _, f := range findings {
		id := f.Resource.ID
		if id == "" || strings.HasPrefix(id, "file:") {
			continue // code findings are not cloud resources
		}
		a := get(id)
		if a.name == "" {
			a.name, a.typ, a.provider, a.account = firstNonEmpty(f.Resource.Name, id), f.Resource.Type, f.Provider, f.Account
		}
		if f.LastSeen.After(a.lastSeen) {
			a.lastSeen = f.LastSeen
		}
		switch f.Status {
		case model.Fail:
			a.fail++
		case model.Pass:
			a.pass++
		}
	}
	for _, is := range issues {
		if !model.IsActive(is.State) && is.State != model.StatePendingVerification {
			continue
		}
		ids := []string{is.ResourceID}
		if is.Kind == model.IssuePath {
			ids = []string{is.AnchorID, is.EntryID}
		}
		for i, id := range ids {
			a, ok := by[id]
			if !ok || id == "" {
				continue
			}
			if is.Kind == model.IssuePath {
				a.onPath = true
				if is.Score > a.maxPath {
					a.maxPath = is.Score
				}
				if i > 0 {
					continue // the entry is on the path; the Issue counts once, on its anchor
				}
			}
			a.open++
			switch is.Severity {
			case model.Critical:
				a.crit++
			case model.High:
				a.high++
			}
		}
	}
	ids := make([]string, 0, len(by))
	for id := range by {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]VantaResource, 0, len(ids))
	for _, id := range ids {
		a := by[id]
		r := VantaResource{DisplayName: a.name, UniqueID: id, CustomProperties: map[string]any{
			"provider": a.provider, "account": a.account, "resource_type": a.typ,
			"open_issues": a.open, "open_critical": a.crit, "open_high": a.high,
			"failing_checks": a.fail, "passing_checks": a.pass,
			"on_attack_path": a.onPath, "max_path_score_x10": int32(a.maxPath*10 + 0.5),
			"nimbus_pass": a.crit+a.high == 0 && !a.onPath,
			"last_seen":   a.lastSeen.UTC().Format(time.RFC3339), // timestamp
		}}
		if b := strings.TrimRight(o.ExternalURLBase, "/"); b != "" {
			r.ExternalURL = b + "/#node?arg=" + url.QueryEscape(id)
		}
		out = append(out, r)
	}
	return out
}

// Vanta pushes resources to one custom resource type of a Vanta private integration.
type Vanta struct {
	BaseURL      string // default DefaultVantaBaseURL
	ClientID     string // VANTA_CLIENT_ID
	ClientSecret string // VANTA_CLIENT_SECRET
	ResourceID   string // VANTA_RESOURCE_ID: the custom resource type
	MaxResources int    // default DefaultVantaMaxResources
}

// NewVantaFromEnv reads VANTA_CLIENT_ID, VANTA_CLIENT_SECRET, VANTA_RESOURCE_ID and
// VANTA_BASE_URL (optional).
func NewVantaFromEnv() *Vanta {
	return &Vanta{BaseURL: os.Getenv("VANTA_BASE_URL"), ClientID: os.Getenv("VANTA_CLIENT_ID"),
		ClientSecret: os.Getenv("VANTA_CLIENT_SECRET"), ResourceID: os.Getenv("VANTA_RESOURCE_ID")}
}

// VantaSyncOptions configures one Sync.
type VantaSyncOptions struct {
	DryRun bool
	// Previous are the uniqueIds of the last successful sync (the caller keeps them): the dry
	// run's diff, and Removed of a real sync.
	Previous []string
	// AllowEmpty permits an empty set (which deletes every resource of the type in Vanta).
	AllowEmpty bool
}

// VantaSyncResult is what a sync sent (or would send).
type VantaSyncResult struct {
	DryRun  bool     `json:"dry_run"`
	Sent    int      `json:"sent"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"` // omitted now: Vanta marks them deleted
	Kept    []string `json:"kept"`
	Status  int      `json:"status,omitempty"`
}

// Text is the one-line summary.
func (r *VantaSyncResult) Text() string {
	verb, del := "synced", "deleted"
	if r.DryRun {
		verb, del = "dry run: would send", "would delete"
	}
	return fmt.Sprintf("Vanta %s %d resource(s) (full state): %d new, %d kept, %s %d omitted since the last sync",
		verb, r.Sent, len(r.Added), len(r.Kept), del, len(r.Removed))
}

func (v *Vanta) base() string {
	return strings.TrimRight(firstNonEmpty(v.BaseURL, DefaultVantaBaseURL), "/")
}

// Sync sends the complete set in one full-state PUT (see the package comment for the guards).
func (v *Vanta) Sync(ctx context.Context, resources []VantaResource, o VantaSyncOptions) (*VantaSyncResult, error) {
	max := v.MaxResources
	if max <= 0 {
		max = DefaultVantaMaxResources
	}
	if len(resources) == 0 && !o.AllowEmpty {
		return nil, fmt.Errorf("vanta: refusing an empty sync: the resources API is full-state, so an empty PUT deletes every resource of the type (pass AllowEmpty / --allow-empty to mean it)")
	}
	if len(resources) > max {
		return nil, fmt.Errorf("vanta: %d resources exceed the cap of %d; the API is full-state, so sending part of the set would delete the rest (raise the cap)", len(resources), max)
	}
	seen := map[string]bool{}
	res := &VantaSyncResult{DryRun: o.DryRun, Sent: len(resources), Added: []string{}, Removed: []string{}, Kept: []string{}}
	for _, r := range resources {
		if r.UniqueID == "" || seen[r.UniqueID] {
			return nil, fmt.Errorf("vanta: duplicate or empty uniqueId %q: every resource of a full-state sync needs its own", r.UniqueID)
		}
		seen[r.UniqueID] = true
	}
	prev := map[string]bool{}
	for _, id := range o.Previous {
		prev[id] = true
	}
	for _, r := range resources {
		if prev[r.UniqueID] {
			res.Kept = append(res.Kept, r.UniqueID)
		} else {
			res.Added = append(res.Added, r.UniqueID)
		}
	}
	for id := range prev {
		if !seen[id] {
			res.Removed = append(res.Removed, id)
		}
	}
	sort.Strings(res.Removed)
	if o.DryRun {
		return res, nil
	}
	if v.ClientID == "" || v.ClientSecret == "" || v.ResourceID == "" {
		return nil, fmt.Errorf("vanta: VANTA_CLIENT_ID, VANTA_CLIENT_SECRET and VANTA_RESOURCE_ID are required")
	}
	tok, err := v.token(ctx)
	if err != nil {
		return nil, err
	}
	if resources == nil {
		resources = []VantaResource{}
	}
	body, err := json.Marshal(map[string]any{"resourceId": v.ResourceID, "resources": resources})
	if err != nil {
		return nil, err
	}
	req, err := newRequest(ctx, http.MethodPut, v.base()+"/v1/resources/custom_resource", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "cloud-posture/0.1")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vanta: PUT custom_resource: %w", err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res.Status = resp.StatusCode
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vanta: PUT custom_resource: HTTP %d: %s", resp.StatusCode, oneLineBody(msg))
	}
	return res, nil
}

func (v *Vanta) token(ctx context.Context) (string, error) {
	data, code, err := postJSON(ctx, v.base()+"/oauth/token", nil, map[string]string{
		"client_id": v.ClientID, "client_secret": v.ClientSecret, "scope": vantaScope, "grant_type": "client_credentials"})
	if err != nil {
		return "", fmt.Errorf("vanta: token: %w", err)
	}
	if code/100 != 2 {
		return "", fmt.Errorf("vanta: token: HTTP %d (check VANTA_CLIENT_ID / VANTA_CLIENT_SECRET and the application's scopes)", code)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(data, &t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("vanta: token: no access_token in the reply")
	}
	return t.AccessToken, nil
}

func oneLineBody(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// VantaCustomTestRecipe is the Vanta Custom Test that turns the export into passing / failing
// tests (Vanta's custom resources have no built-in tests).
func VantaCustomTestRecipe() string {
	return `Vanta custom test for nimbus resources (Vanta: Tests → Create custom test)

1. Private integration: create an application with the scope connectors.self:write-resource and a
   custom resource type "Nimbus cloud resource". Its id is VANTA_RESOURCE_ID; the app's client id
   and secret are VANTA_CLIENT_ID / VANTA_CLIENT_SECRET (keep them in a secret store, not a file).
2. Sync: cloud-posture issues export --to vanta --dry-run   (shows what the PUT would add and
   delete), then without --dry-run after every scan. The API is full-state: every sync sends the
   complete set and any resource omitted from it is deleted in Vanta, so nimbus refuses an empty
   or truncated set.
3. Test data: resource "Nimbus cloud resource" (one data source is enough).
4. Evaluation logic: the resource FAILS when nimbus_pass is false. Stricter variants:
     open_critical > 0                      — any open Critical Issue on the resource
     on_attack_path = true                  — the resource is the entry or target of an open attack path
     max_path_score_x10 >= 70               — a path scoring 7.0 or more
   Properties: provider, account, resource_type (string); open_issues, open_critical, open_high,
   failing_checks, passing_checks, max_path_score_x10 (int32); on_attack_path, nimbus_pass
   (boolean); last_seen (timestamp).
5. Test details: map the test to the controls it evidences (e.g. SOC 2 CC6.1, CC7.1). Vanta
   re-runs it on every push; externalUrl opens the resource in the nimbus dashboard.`
}
