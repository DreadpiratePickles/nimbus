package saas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DreadpiratePickles/nimbus/internal/collector/core"
	"github.com/DreadpiratePickles/nimbus/internal/graph"
	"github.com/DreadpiratePickles/nimbus/internal/model"
)

// M365 collects Entra ID admin MFA coverage and legacy-authentication blocking
// through Microsoft Graph using an app registration (client credentials).
type M365 struct {
	TenantID, ClientID, ClientSecret string
	GraphURL, LoginURL               string
	HTTP                             *http.Client
	Now                              func() time.Time
	Backoff                          time.Duration
}

func NewM365() *M365 {
	return &M365{GraphURL: "https://graph.microsoft.com/v1.0", LoginURL: "https://login.microsoftonline.com"}
}

func (c *M365) Name() string     { return "m365" }
func (c *M365) Provider() string { return model.ProviderM365 }

type m365User struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
	AccountEnabled    *bool  `json:"accountEnabled"`
	CreatedDateTime   string `json:"createdDateTime"`
}

type m365Role struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		ID string `json:"id"`
	} `json:"members"`
}

type m365Registration struct {
	ID              string `json:"id"`
	IsMfaRegistered bool   `json:"isMfaRegistered"`
}

type caPolicy struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		ClientAppTypes []string `json:"clientAppTypes"`
		Users          struct {
			IncludeUsers []string `json:"includeUsers"`
			IncludeRoles []string `json:"includeRoles"`
		} `json:"users"`
	} `json:"conditions"`
	GrantControls *struct {
		BuiltInControls []string `json:"builtInControls"`
	} `json:"grantControls"`
}

func (p caPolicy) enabled() bool { return strings.EqualFold(p.State, "enabled") }

func (p caPolicy) grants(control string) bool {
	if p.GrantControls == nil {
		return false
	}
	for _, c := range p.GrantControls.BuiltInControls {
		if strings.EqualFold(c, control) {
			return true
		}
	}
	return false
}

// requiresAdminMFA: enabled policy granting "mfa" that targets all users or admin roles.
func (p caPolicy) requiresAdminMFA() bool {
	if !p.enabled() || !p.grants("mfa") {
		return false
	}
	if len(p.Conditions.Users.IncludeRoles) > 0 {
		return true
	}
	for _, u := range p.Conditions.Users.IncludeUsers {
		if strings.EqualFold(u, "All") {
			return true
		}
	}
	return false
}

// blocksLegacyAuth: enabled policy blocking Exchange ActiveSync / other legacy clients.
func (p caPolicy) blocksLegacyAuth() bool {
	if !p.enabled() || !p.grants("block") {
		return false
	}
	for _, t := range p.Conditions.ClientAppTypes {
		if strings.EqualFold(t, "exchangeActiveSync") || strings.EqualFold(t, "other") {
			return true
		}
	}
	return false
}

func (c *M365) token(ctx context.Context, tenant, clientID, secret string) (string, error) {
	login := c.LoginURL
	if login == "" {
		login = "https://login.microsoftonline.com"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(login, "/")+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errors.New("token endpoint returned no access_token")
	}
	return tok.AccessToken, nil
}

func firstSet(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (c *M365) Collect(ctx context.Context, spec core.AccountSpec, g *graph.Graph) (core.Result, error) {
	tenant := firstSet(spec.TenantID, c.TenantID, os.Getenv("M365_TENANT_ID"))
	clientID := firstSet(c.ClientID, os.Getenv("M365_CLIENT_ID"))
	secret := c.ClientSecret
	if secret == "" {
		secret = core.Token(spec, "M365_CLIENT_SECRET")
	}
	switch {
	case tenant == "":
		return core.Result{}, errors.New("m365: M365_TENANT_ID not set")
	case clientID == "":
		return core.Result{}, errors.New("m365: M365_CLIENT_ID not set")
	case secret == "":
		return core.Result{}, errors.New("m365: M365_CLIENT_SECRET not set")
	}
	tok, err := c.token(ctx, tenant, clientID, secret)
	if err != nil {
		return core.Result{}, fmt.Errorf("m365: acquire token: %w", err)
	}
	base := firstSet(c.GraphURL, "https://graph.microsoft.com/v1.0")
	rc := &core.REST{BaseURL: base, Client: c.HTTP, Backoff: c.Backoff, Headers: map[string]string{"Authorization": "Bearer " + tok}}
	now := nowFn(c.Now)
	acc := &core.Acc{}
	core.EnsureAccount(g, model.ProviderM365, tenant, spec.Name)

	tenantRes := model.Resource{ID: "m365:tenant/" + tenant, Type: "m365_tenant", Name: firstSet(spec.Name, tenant), Attributes: map[string]any{"tenant_id": tenant}}
	core.AddResource(g, core.Res{Provider: model.ProviderM365, Account: tenant, Resource: tenantRes})

	users := map[string]m365User{}
	if err := rc.GetAll(ctx, "/users?$select=id,userPrincipalName,displayName,accountEnabled,createdDateTime&$top=999", func(item json.RawMessage) error {
		var u m365User
		if err := json.Unmarshal(item, &u); err != nil {
			return err
		}
		users[u.ID] = u
		return nil
	}); err != nil {
		acc.Error("m365: list users", err)
	}

	adminRoles := map[string][]string{} // user id -> role names
	if err := rc.GetAll(ctx, "/directoryRoles?$expand=members", func(item json.RawMessage) error {
		var r m365Role
		if err := json.Unmarshal(item, &r); err != nil {
			return err
		}
		if !strings.Contains(strings.ToLower(r.DisplayName), "administrator") {
			return nil
		}
		for _, m := range r.Members {
			adminRoles[m.ID] = append(adminRoles[m.ID], r.DisplayName)
		}
		return nil
	}); err != nil {
		acc.Error("m365: list directory roles", err)
	}

	mfa := map[string]bool{}
	mfaKnown := true
	if err := rc.GetAll(ctx, "/reports/authenticationMethods/userRegistrationDetails", func(item json.RawMessage) error {
		var r m365Registration
		if err := json.Unmarshal(item, &r); err != nil {
			return err
		}
		mfa[r.ID] = r.IsMfaRegistered
		return nil
	}); err != nil {
		mfaKnown = false
		if s := core.StatusOf(err); s == http.StatusForbidden || s == http.StatusUnauthorized {
			acc.Warn("m365: userRegistrationDetails not permitted (%d; needs AuditLog.Read.All + Entra P1); MFA registration unknown", s)
		} else {
			acc.Error("m365: user registration details", err)
		}
	}

	var policies []caPolicy
	caKnown := true
	if err := rc.GetAll(ctx, "/identity/conditionalAccess/policies", func(item json.RawMessage) error {
		var p caPolicy
		if err := json.Unmarshal(item, &p); err != nil {
			return err
		}
		policies = append(policies, p)
		return nil
	}); err != nil {
		caKnown = false
		if s := core.StatusOf(err); s == http.StatusForbidden || s == http.StatusUnauthorized {
			acc.Warn("m365: conditional access policies not permitted (%d; needs Policy.Read.All)", s)
		} else {
			acc.Error("m365: conditional access policies", err)
		}
	}
	var caMFA, caLegacy []string
	for _, p := range policies {
		if p.requiresAdminMFA() {
			caMFA = append(caMFA, p.DisplayName)
		}
		if p.blocksLegacyAuth() {
			caLegacy = append(caLegacy, p.DisplayName)
		}
	}

	ids := core.SortedKeys(users)
	for id := range adminRoles {
		if _, ok := users[id]; !ok {
			ids = append(ids, id) // admin principal outside the user listing (paging failure)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := users[id]
		res := model.Resource{ID: "m365:user/" + id, Type: "m365_user", Name: firstSet(u.UserPrincipalName, u.DisplayName, id), Attributes: map[string]any{
			"display_name": u.DisplayName,
		}}
		if u.AccountEnabled != nil {
			res.Attributes["account_enabled"] = *u.AccountEnabled
		}
		roles, admin := adminRoles[id]
		if admin {
			res.Attributes["admin"] = true
			res.Attributes["roles"] = roles
		}
		if reg, ok := mfa[id]; ok {
			res.Attributes["mfa_registered"] = reg
		}
		core.AddResource(g, core.Res{Provider: model.ProviderM365, Account: tenant, Resource: res, Created: parseTime(u.CreatedDateTime)})
		if !admin {
			continue
		}
		registered, regKnown := mfa[id]
		var pass bool
		var detail string
		switch {
		case regKnown && registered:
			pass, detail = true, "Administrator has MFA registered."
		case len(caMFA) > 0:
			pass, detail = true, "Administrator is covered by conditional access requiring MFA: "+strings.Join(caMFA, ", ")+"."
		case !mfaKnown || !regKnown:
			if !caKnown {
				continue // nothing to evaluate against
			}
			pass, detail = false, "MFA registration unknown and no enabled conditional access policy requires MFA for administrators."
		default:
			pass, detail = false, "Administrator has no MFA registered and no enabled conditional access policy requires MFA."
		}
		emit(acc, g, now, core.Check{CheckID: "entra_admin_users_mfa_enabled", Provider: model.ProviderM365, Account: tenant, AccountLabel: spec.Name,
			Resource: res, Pass: pass, Detail: detail + " Roles: " + strings.Join(roles, ", ")})
	}

	if caKnown {
		detail := "No enabled conditional access policy blocks legacy authentication clients."
		if len(caLegacy) > 0 {
			detail = "Legacy authentication blocked by: " + strings.Join(caLegacy, ", ") + "."
		}
		emit(acc, g, now, core.Check{CheckID: "entra_legacy_authentication_blocked", Provider: model.ProviderM365, Account: tenant, AccountLabel: spec.Name,
			Resource: tenantRes, Pass: len(caLegacy) > 0, Detail: detail})
	}
	return acc.Result(), nil
}
