package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
		g.AddEdge(graph.InternetNodeID, id, graph.EdgeExposes, map[string]any{"via": "public_repository"})
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
