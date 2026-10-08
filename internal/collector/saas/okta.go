package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// Okta collects administrator MFA enrollment and sign-on policy MFA requirements.
type Okta struct {
	// OrgURL / Token override OKTA_ORG_URL / OKTA_API_TOKEN.
	OrgURL, Token string
	HTTP          *http.Client
	Now           func() time.Time
	Concurrency   int
	Backoff       time.Duration
}

func NewOkta() *Okta { return &Okta{Concurrency: 8} }

func (c *Okta) Name() string     { return "okta" }
func (c *Okta) Provider() string { return model.ProviderOkta }

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Created string `json:"created"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type oktaRole struct {
	Type   string `json:"type"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

type oktaFactor struct {
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
}

type oktaPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Priority int    `json:"priority"`
	System   bool   `json:"system"`
	Created  string `json:"created"`
}

type oktaRule struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Actions struct {
		Signon struct {
			Access        string `json:"access"`
			RequireFactor bool   `json:"requireFactor"`
		} `json:"signon"`
	} `json:"actions"`
}

func (c *Okta) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	orgURL := c.OrgURL
	if spec.Domain != "" {
		orgURL = spec.Domain
		if !strings.HasPrefix(orgURL, "http") {
			orgURL = "https://" + orgURL
		}
	}
	if orgURL == "" {
		orgURL = os.Getenv("OKTA_ORG_URL")
	}
	token := c.Token
	if token == "" {
		token = core.Token(spec, "OKTA_API_TOKEN")
	}
	if orgURL == "" {
		return core.Result{}, errors.New("okta: OKTA_ORG_URL not set")
	}
	if token == "" {
		return core.Result{}, errors.New("okta: OKTA_API_TOKEN not set")
	}
	account := orgURL
	if u, err := url.Parse(orgURL); err == nil && u.Host != "" {
		account = u.Host
	}
	rc := &core.REST{BaseURL: orgURL, Client: c.HTTP, Backoff: c.Backoff, Headers: map[string]string{"Authorization": "SSWS " + token}}
	now := nowFn(c.Now)
	acc := &core.Acc{}
	core.EnsureAccount(g, model.ProviderOkta, account, spec.Name)

	var users []oktaUser
	if err := rc.GetAll(ctx, "/api/v1/users?limit=200", func(item json.RawMessage) error {
		var u oktaUser
		if err := json.Unmarshal(item, &u); err != nil {
			return err
		}
		users = append(users, u)
		return nil
	}); err != nil {
		acc.Error("okta: list users", err)
	}

	type userInfo struct {
		roles []string
		mfa   []string
		known bool
	}
	var mu sync.Mutex
	info := map[string]*userInfo{}
	tasks := make([]core.Task, 0, len(users))
	for _, u := range users {
		tasks = append(tasks, core.Task{Name: "okta: user " + u.Profile.Login, Fn: func(ctx context.Context) error {
			var roles []oktaRole
			if _, err := rc.Get(ctx, "/api/v1/users/"+url.PathEscape(u.ID)+"/roles", &roles); err != nil {
				return fmt.Errorf("roles: %w", err)
			}
			ui := &userInfo{}
			for _, r := range roles {
				if r.Status == "" || strings.EqualFold(r.Status, "ACTIVE") {
					ui.roles = append(ui.roles, r.Type)
				}
			}
			if len(ui.roles) > 0 {
				var factors []oktaFactor
				if _, err := rc.Get(ctx, "/api/v1/users/"+url.PathEscape(u.ID)+"/factors", &factors); err != nil {
					mu.Lock()
					info[u.ID] = ui
					mu.Unlock()
					return fmt.Errorf("factors: %w", err)
				}
				ui.known = true
				for _, f := range factors {
					if strings.EqualFold(f.Status, "ACTIVE") {
						ui.mfa = append(ui.mfa, f.FactorType)
					}
				}
			}
			mu.Lock()
			info[u.ID] = ui
			mu.Unlock()
			return nil
		}})
	}
	core.RunTasks(ctx, c.Concurrency, acc, tasks)

	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	for _, u := range users {
		res := model.Resource{ID: "okta:user/" + u.ID, Type: "okta_user", Name: u.Profile.Login, Attributes: map[string]any{
			"status": u.Status, "email": u.Profile.Email,
		}}
		ui := info[u.ID]
		admin := ui != nil && len(ui.roles) > 0
		if admin {
			res.Attributes["admin"] = true
			res.Attributes["roles"] = ui.roles
			res.Attributes["mfa_factors"] = ui.mfa
		}
		core.AddResource(g, core.Res{Provider: model.ProviderOkta, Account: account, Resource: res, Created: parseTime(u.Created)})
		if !admin || !ui.known {
			continue
		}
		pass := len(ui.mfa) > 0
		detail := fmt.Sprintf("Administrator %s (%s) has active MFA factors: %s.", u.Profile.Login, strings.Join(ui.roles, ", "), strings.Join(ui.mfa, ", "))
		if !pass {
			detail = fmt.Sprintf("Administrator %s (%s) has no active MFA factor enrolled.", u.Profile.Login, strings.Join(ui.roles, ", "))
		}
		emit(acc, g, now, core.Check{CheckID: "okta_admin_user_mfa_enrolled", AliasSource: "steampipe", Provider: model.ProviderOkta, Account: account,
			AccountLabel: spec.Name, Resource: res, Pass: pass, Detail: detail})
	}

	var policies []oktaPolicy
	if err := rc.GetAll(ctx, "/api/v1/policies?type=OKTA_SIGN_ON", func(item json.RawMessage) error {
		var p oktaPolicy
		if err := json.Unmarshal(item, &p); err != nil {
			return err
		}
		policies = append(policies, p)
		return nil
	}); err != nil {
		acc.Error("okta: list sign-on policies", err)
	}
	for _, p := range policies {
		res := model.Resource{ID: "okta:policy/" + p.ID, Type: "okta_policy", Name: p.Name, Attributes: map[string]any{
			"status": p.Status, "priority": p.Priority, "system": p.System, "policy_type": "OKTA_SIGN_ON",
		}}
		core.AddResource(g, core.Res{Provider: model.ProviderOkta, Account: account, Resource: res, Created: parseTime(p.Created)})
		if !strings.EqualFold(p.Status, "ACTIVE") {
			continue
		}
		var rules []oktaRule
		if err := rc.GetAll(ctx, "/api/v1/policies/"+url.PathEscape(p.ID)+"/rules", func(item json.RawMessage) error {
			var r oktaRule
			if err := json.Unmarshal(item, &r); err != nil {
				return err
			}
			rules = append(rules, r)
			return nil
		}); err != nil {
			acc.Error("okta: policy rules "+p.Name, err)
			continue
		}
		pass := signOnRequiresMFA(rules)
		detail := fmt.Sprintf("Sign-on policy %q has an active rule requiring MFA.", p.Name)
		if !pass {
			detail = fmt.Sprintf("Sign-on policy %q has no active allow rule that requires MFA.", p.Name)
		}
		emit(acc, g, now, core.Check{CheckID: "okta_sign_on_policy_require_mfa", AliasSource: "steampipe", Provider: model.ProviderOkta, Account: account,
			AccountLabel: spec.Name, Resource: res, Pass: pass, Detail: detail})
	}
	return acc.Result(), nil
}

// signOnRequiresMFA reports whether any ACTIVE rule allows sign-on only with a factor.
func signOnRequiresMFA(rules []oktaRule) bool {
	for _, r := range rules {
		if strings.EqualFold(r.Status, "ACTIVE") && strings.EqualFold(r.Actions.Signon.Access, "ALLOW") && r.Actions.Signon.RequireFactor {
			return true
		}
	}
	return false
}
