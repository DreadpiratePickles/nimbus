package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// GitHub collects organization 2FA enforcement, default-branch protection and
// secret scanning across every repository of spec.Org.
type GitHub struct {
	BaseURL     string
	HTTP        *http.Client
	Now         func() time.Time
	Concurrency int
	// Backoff is the base retry delay passed to core.REST (tests set it tiny).
	Backoff time.Duration
}

func NewGitHub() *GitHub { return &GitHub{BaseURL: "https://api.github.com", Concurrency: 8} }

func (c *GitHub) Name() string     { return "github" }
func (c *GitHub) Provider() string { return model.ProviderGitHub }

type ghOrg struct {
	Login                       string `json:"login"`
	Name                        string `json:"name"`
	HTMLURL                     string `json:"html_url"`
	CreatedAt                   string `json:"created_at"`
	TwoFactorRequirementEnabled *bool  `json:"two_factor_requirement_enabled"`
}

type ghSecurity struct {
	SecretScanning *struct {
		Status string `json:"status"`
	} `json:"secret_scanning"`
	SecretScanningPushProtection *struct {
		Status string `json:"status"`
	} `json:"secret_scanning_push_protection"`
}

type ghRepo struct {
	Name                string      `json:"name"`
	FullName            string      `json:"full_name"`
	Private             bool        `json:"private"`
	Visibility          string      `json:"visibility"`
	DefaultBranch       string      `json:"default_branch"`
	Archived            bool        `json:"archived"`
	Fork                bool        `json:"fork"`
	HTMLURL             string      `json:"html_url"`
	CreatedAt           string      `json:"created_at"`
	PushedAt            string      `json:"pushed_at"`
	Topics              []string    `json:"topics"`
	SecurityAndAnalysis *ghSecurity `json:"security_and_analysis"`
}

func (c *GitHub) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	if spec.Org == "" {
		return core.Result{}, errors.New("github: spec.Org is required")
	}
	token := core.Token(spec, "GITHUB_TOKEN")
	if token == "" {
		return core.Result{}, errors.New("github: GITHUB_TOKEN not set")
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	rc := &core.REST{BaseURL: base, Client: c.HTTP, Backoff: c.Backoff, Headers: map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}}
	now := nowFn(c.Now)
	org := spec.Org
	acc := &core.Acc{}
	acctID := core.EnsureAccount(g, model.ProviderGitHub, org, spec.Name)

	var o ghOrg
	if _, err := rc.Get(ctx, "/orgs/"+url.PathEscape(org), &o); err != nil {
		return acc.Result(), fmt.Errorf("github: get org %s: %w", org, err)
	}
	orgID := "github:org/" + org
	orgRes := model.Resource{ID: orgID, Type: "github_organization", Name: org, Attributes: map[string]any{"html_url": o.HTMLURL, "display_name": o.Name}}
	if o.TwoFactorRequirementEnabled != nil {
		orgRes.Attributes["two_factor_requirement_enabled"] = *o.TwoFactorRequirementEnabled
	}
	core.AddResource(g, core.Res{Provider: model.ProviderGitHub, Account: org, Resource: orgRes, Created: parseTime(o.CreatedAt)})
	g.AddEdge(acctID, orgID, graph.EdgeContains, nil)
	if o.TwoFactorRequirementEnabled == nil {
		acc.Warn("github: org %s: two_factor_requirement_enabled not visible (token needs admin:org); 2FA check skipped", org)
	} else {
		detail := "Organization requires two-factor authentication for all members."
		if !*o.TwoFactorRequirementEnabled {
			detail = "Organization does not require two-factor authentication for members."
		}
		emit(acc, g, now, core.Check{CheckID: "organization_members_mfa_required", Provider: model.ProviderGitHub, Account: org, AccountLabel: spec.Name,
			Resource: orgRes, Pass: *o.TwoFactorRequirementEnabled, Detail: detail})
	}

	var repos []ghRepo
	err := rc.GetAll(ctx, "/orgs/"+url.PathEscape(org)+"/repos?per_page=100&type=all", func(item json.RawMessage) error {
		var r ghRepo
		if err := json.Unmarshal(item, &r); err != nil {
			return err
		}
		repos = append(repos, r)
		return nil
	})
	if err != nil {
		acc.Error("github: list repos", err)
	}

	tasks := make([]core.Task, 0, len(repos))
	for _, r := range repos {
		tasks = append(tasks, core.Task{Name: "github: repo " + r.FullName, Fn: func(ctx context.Context) error {
			return c.repo(ctx, rc, spec, org, orgID, r, g, acc, now)
		}})
	}
	core.RunTasks(ctx, c.Concurrency, acc, tasks)
	return acc.Result(), nil
}

func (c *GitHub) repo(ctx context.Context, rc *core.REST, spec core.AccountSpec, org, orgID string, r ghRepo, g *graph.Graph, acc *core.Acc, now time.Time) error {
	visibility := r.Visibility
	if visibility == "" {
		visibility = map[bool]string{true: "private", false: "public"}[r.Private]
	}
	id := "github:repo/" + org + "/" + r.Name
	tags := map[string]string{}
	for _, t := range r.Topics {
		tags[t] = "true"
	}
	res := model.Resource{ID: id, Type: "github_repository", Name: r.Name, Attributes: map[string]any{
		"visibility": visibility, "private": r.Private, "default_branch": r.DefaultBranch, "archived": r.Archived, "fork": r.Fork, "html_url": r.HTMLURL,
		"full_name": r.FullName, "pushed_at": r.PushedAt,
	}}
	core.AddResource(g, core.Res{Provider: model.ProviderGitHub, Account: org, Resource: res, Tags: tags, Created: parseTime(r.CreatedAt)})
	g.AddEdge(orgID, id, graph.EdgeContains, nil)
	if visibility == "public" {
		core.Expose(g, id, map[string]any{"via": "public_repository"}, nil, spec.TrustedCIDRs)
	}
	if len(tags) > 0 {
		res.Attributes["tags"] = core.TagsAny(tags)
	}
	check := func(id string, pass bool, detail string) {
		emit(acc, g, now, core.Check{CheckID: id, Provider: model.ProviderGitHub, Account: org, AccountLabel: spec.Name, Resource: res, Pass: pass, Detail: detail})
	}

	// Branch protection on the default branch.
	if r.DefaultBranch != "" && !r.Archived {
		path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection", url.PathEscape(org), url.PathEscape(r.Name), url.PathEscape(r.DefaultBranch))
		_, err := rc.Get(ctx, path, nil)
		if core.IsRateLimited(err) {
			// Surface throttling as a rate_limited collection error (coverage), never a skip.
			return fmt.Errorf("branch protection: %w", err)
		}
		switch core.StatusOf(err) {
		case 0:
			if err != nil {
				return fmt.Errorf("branch protection: %w", err)
			}
			check("repository_default_branch_protection_enabled", true, fmt.Sprintf("Default branch %q is protected.", r.DefaultBranch))
		case http.StatusNotFound:
			check("repository_default_branch_protection_enabled", false, fmt.Sprintf("Default branch %q is not protected.", r.DefaultBranch))
		case http.StatusForbidden:
			acc.Warn("github: %s: branch protection not readable (403; plan or token scope); check skipped", r.FullName)
		default:
			return fmt.Errorf("branch protection: %w", err)
		}
	}

	// Secret scanning.
	sa := r.SecurityAndAnalysis
	if sa == nil {
		var full ghRepo
		if _, err := rc.Get(ctx, fmt.Sprintf("/repos/%s/%s", url.PathEscape(org), url.PathEscape(r.Name)), &full); err != nil {
			if core.IsRateLimited(err) {
				return fmt.Errorf("get repo: %w", err)
			}
			if s := core.StatusOf(err); s == http.StatusForbidden || s == http.StatusNotFound {
				acc.Warn("github: %s: repository details not readable (%d); secret scanning check skipped", r.FullName, s)
				return nil
			}
			return fmt.Errorf("get repo: %w", err)
		}
		sa = full.SecurityAndAnalysis
	}
	if sa == nil || sa.SecretScanning == nil {
		acc.Warn("github: %s: security_and_analysis not visible (token needs admin access); secret scanning check skipped", r.FullName)
		return nil
	}
	res.Attributes["secret_scanning"] = sa.SecretScanning.Status
	enabled := sa.SecretScanning.Status == "enabled"
	detail := "Secret scanning is enabled."
	if !enabled {
		detail = "Secret scanning is " + sa.SecretScanning.Status + "."
	}
	check("repository_secret_scanning_enabled", enabled, detail)
	return nil
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// ---------------------------------------------------------------- GitHub OIDC trust subjects
//
// A cloud role that trusts GitHub's OIDC provider (token.actions.githubusercontent.com) is
// assumable by every workflow run whose token `sub` claim matches the trust's condition. The
// subject decides who that is (P1-PLANDIFF CI-entry floor, planning decision on P12):
//
//	wildcard  no sub condition, "*", or a wildcard in the owner/repository part: any repository
//	          (on GitHub, or in the organisation) can assume the role
//	unpinned  one repository, but any ref / pull request / environment ("repo:o/r:*",
//	          "ref:refs/heads/*", "pull_request", any * or ?): whoever can run a workflow in the
//	          repository can assume it, unreviewed branches included
//	pinned    one repository and one concrete ref, tag or environment
//
// These helpers only read policy documents and attribute text; they never call GitHub.

// GitHubOIDCHost is the issuer host of GitHub Actions OIDC tokens.
const GitHubOIDCHost = "token.actions.githubusercontent.com"

// OIDC subject classes, worst first.
const (
	OIDCSubjectWildcard = "wildcard"
	OIDCSubjectUnpinned = "unpinned"
	OIDCSubjectPinned   = "pinned"
)

var oidcClassRank = map[string]int{OIDCSubjectWildcard: 0, OIDCSubjectUnpinned: 1, OIDCSubjectPinned: 2}

// OIDCTrust is what one role trust policy grants GitHub Actions.
type OIDCTrust struct {
	// Subjects are the sub-claim patterns of every Allow statement that trusts the GitHub
	// provider (sorted, de-duplicated). NoSubject is set when one such statement has no sub
	// condition at all; its subject is then "" (any repository).
	Subjects  []string `json:"subjects,omitempty"`
	NoSubject bool     `json:"no_subject,omitempty"`
}

// Class is the worst class over the trust's subjects.
func (t OIDCTrust) Class() string {
	if t.NoSubject {
		return OIDCSubjectWildcard
	}
	return WorstOIDCClass(t.Subjects)
}

// WorstOIDCClass is the worst class over subjects ("" when there are none).
func WorstOIDCClass(subs []string) string {
	worst := ""
	for _, s := range subs {
		c, _ := ClassifyOIDCSubject(s)
		if worst == "" || oidcClassRank[c] < oidcClassRank[worst] {
			worst = c
		}
	}
	return worst
}

// ClassifyOIDCSubject classifies one sub-claim pattern and says why.
func ClassifyOIDCSubject(sub string) (class, why string) {
	s := strings.TrimSpace(sub)
	if s == "" {
		return OIDCSubjectWildcard, "no sub condition: any GitHub repository can assume the role"
	}
	if s == "*" || strings.EqualFold(s, "repo:*") {
		return OIDCSubjectWildcard, fmt.Sprintf("sub %q matches every GitHub repository", s)
	}
	rest, ok := cutPrefixFold(s, "repo:")
	if !ok {
		if strings.ContainsAny(s, "*?") {
			return OIDCSubjectWildcard, fmt.Sprintf("sub %q is a wildcard pattern", s)
		}
		return OIDCSubjectPinned, fmt.Sprintf("sub %q is a custom claim with no wildcard", s)
	}
	repo, ctx, _ := strings.Cut(rest, ":")
	if strings.ContainsAny(repo, "*?") || !strings.Contains(repo, "/") {
		return OIDCSubjectWildcard, fmt.Sprintf("sub %q matches more than one repository", s)
	}
	switch {
	case ctx == "" || strings.ContainsAny(ctx, "*?"):
		return OIDCSubjectUnpinned, fmt.Sprintf("sub %q accepts any ref, pull request or environment of %s", s, repo)
	case strings.EqualFold(ctx, "pull_request"):
		return OIDCSubjectUnpinned, fmt.Sprintf("sub %q accepts any pull-request run of %s", s, repo)
	}
	return OIDCSubjectPinned, fmt.Sprintf("sub %q is pinned to one ref or environment of %s", s, repo)
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// GitHubOIDCTrust reads a role trust policy (JSON text or decoded map) and returns the GitHub
// Actions subjects it accepts; ok is false when no Allow statement trusts the GitHub provider.
func GitHubOIDCTrust(policy any) (OIDCTrust, bool) {
	doc := policy
	switch x := policy.(type) {
	case string:
		var m any
		if json.Unmarshal([]byte(x), &m) != nil {
			return OIDCTrust{}, false
		}
		doc = m
	case []byte:
		var m any
		if json.Unmarshal(x, &m) != nil {
			return OIDCTrust{}, false
		}
		doc = m
	}
	m, _ := doc.(map[string]any)
	if m == nil {
		return OIDCTrust{}, false
	}
	var stmts []any
	switch st := m["Statement"].(type) {
	case []any:
		stmts = st
	case map[string]any:
		stmts = []any{st}
	}
	var tr OIDCTrust
	found := false
	seen := map[string]bool{}
	for _, raw := range stmts {
		st, _ := raw.(map[string]any)
		if st == nil || !strings.EqualFold(fmt.Sprint(st["Effect"]), "Allow") {
			continue
		}
		pr, _ := st["Principal"].(map[string]any)
		fed := false
		for _, f := range anyStrings(pr["Federated"]) {
			if strings.Contains(strings.ToLower(f), GitHubOIDCHost) {
				fed = true
			}
		}
		if !fed {
			continue
		}
		found = true
		subs := conditionValues(st["Condition"], GitHubOIDCHost+":sub")
		if len(subs) == 0 {
			tr.NoSubject = true
			continue
		}
		for _, s := range subs {
			if !seen[s] {
				seen[s] = true
				tr.Subjects = append(tr.Subjects, s)
			}
		}
	}
	sort.Strings(tr.Subjects)
	return tr, found
}

// conditionValues collects the values every condition operator gives key (case-insensitive).
func conditionValues(cond any, key string) []string {
	c, _ := cond.(map[string]any)
	ops := make([]string, 0, len(c))
	for op := range c {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var out []string
	for _, op := range ops {
		kv, _ := c[op].(map[string]any)
		for k, v := range kv {
			if strings.EqualFold(k, key) {
				out = append(out, anyStrings(v)...)
			}
		}
	}
	return out
}

func anyStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

var (
	oidcSubText   = regexp.MustCompile(`(?i)\bsub\s*[=:]?\s*"?(repo:[^\s",;)]+|\*)`)
	oidcNoSubText = regexp.MustCompile(`(?i)no\s+sub(ject)?\s+condition`)
)

// OIDCSubjectsFromText extracts subjects from free text a collector or the lab wrote on an
// edge or role ("GitHub OIDC sub repo:o/r:*", "sub=repo:o/r:ref:refs/heads/main"). "(no sub
// condition)" yields the empty subject (wildcard); no subject at all yields nil.
func OIDCSubjectsFromText(s string) []string {
	if oidcNoSubText.MatchString(s) {
		return []string{""}
	}
	var out []string
	for _, m := range oidcSubText.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// OIDCSubjectMatchesRepo reports whether subject sub can be satisfied by a workflow in repo
// (github.com/o/r, github:repo/o/r or o/r). The empty subject matches every repository.
func OIDCSubjectMatchesRepo(sub, repo string) bool {
	if strings.TrimSpace(sub) == "" || sub == "*" {
		return true
	}
	rest, ok := cutPrefixFold(sub, "repo:")
	if !ok {
		return false
	}
	pat, _, _ := strings.Cut(rest, ":")
	name := RepoFullName(repo)
	if name == "" {
		return false
	}
	re := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(strings.ToLower(pat)), `\*`, ".*"), `\?`, ".") + "$"
	ok, _ = regexp.MatchString(re, strings.ToLower(name))
	return ok
}

// RepoFullName normalises a repository node id or name to owner/repo ("" when it is not one).
func RepoFullName(id string) string {
	s := strings.TrimSpace(id)
	for _, p := range []string{"https://github.com/", "http://github.com/", "github.com/", "github:repo/"} {
		if r, ok := cutPrefixFold(s, p); ok {
			s = r
			break
		}
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	if strings.Count(s, "/") != 1 || strings.ContainsAny(s, " :") {
		return ""
	}
	return s
}
