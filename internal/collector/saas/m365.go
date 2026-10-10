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
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	RoleTemplateID string `json:"roleTemplateId"`
	Members        []struct {
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
			IncludeUsers  []string `json:"includeUsers"`
			IncludeRoles  []string `json:"includeRoles"`
			IncludeGroups []string `json:"includeGroups"`
			ExcludeUsers  []string `json:"excludeUsers"`
			ExcludeRoles  []string `json:"excludeRoles"`
			ExcludeGroups []string `json:"excludeGroups"`
			// ExcludeGuestsOrExternalUsers is an object when set; any value narrows the policy.
			ExcludeGuestsOrExternalUsers json.RawMessage `json:"excludeGuestsOrExternalUsers"`
		} `json:"users"`
		Applications *struct {
			IncludeApplications []string `json:"includeApplications"`
			ExcludeApplications []string `json:"excludeApplications"`
		} `json:"applications"`
		Locations *struct {
			IncludeLocations []string `json:"includeLocations"`
			ExcludeLocations []string `json:"excludeLocations"`
		} `json:"locations"`
		Platforms *struct {
			IncludePlatforms []string `json:"includePlatforms"`
			ExcludePlatforms []string `json:"excludePlatforms"`
		} `json:"platforms"`
		Devices *struct {
			DeviceFilter *struct {
				Rule string `json:"rule"`
			} `json:"deviceFilter"`
		} `json:"devices"`
		SignInRiskLevels           []string `json:"signInRiskLevels"`
		UserRiskLevels             []string `json:"userRiskLevels"`
		ServicePrincipalRiskLevels []string `json:"servicePrincipalRiskLevels"`
		InsiderRiskLevels          *string  `json:"insiderRiskLevels"`
	} `json:"conditions"`
	GrantControls *struct {
		Operator               string          `json:"operator"`
		BuiltInControls        []string        `json:"builtInControls"`
		CustomAuthFactors      []string        `json:"customAuthenticationFactors"`
		TermsOfUse             []string        `json:"termsOfUse"`
		AuthenticationStrength json.RawMessage `json:"authenticationStrength"`
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

// requiresMFA reports whether satisfying the grant controls always takes MFA: the
// "mfa" built-in control or an authentication strength, and no other control that
// can satisfy an OR instead (e.g. "mfa OR compliantDevice" lets a compliant device
// sign in without MFA).
func (p caPolicy) requiresMFA() bool {
	gc := p.GrantControls
	if gc == nil {
		return false
	}
	strength := len(gc.AuthenticationStrength) > 0 && string(gc.AuthenticationStrength) != "null"
	mfa := p.grants("mfa") || strength
	if !mfa {
		return false
	}
	controls := len(gc.BuiltInControls) + len(gc.CustomAuthFactors) + len(gc.TermsOfUse)
	if strength {
		controls++
	}
	return controls <= 1 || !strings.EqualFold(gc.Operator, "OR")
}

// allSignIns reports whether the policy's conditions match every sign-in to every
// cloud app (no application, location, platform, device, client-app or risk
// narrowing); returns the narrowing condition otherwise.
func (p caPolicy) allSignIns() (bool, string) {
	c := p.Conditions
	if a := c.Applications; a == nil || !anyIn(a.IncludeApplications, "All") {
		return false, "does not include all cloud apps"
	} else if len(a.ExcludeApplications) > 0 {
		return false, "excludes applications"
	}
	if l := c.Locations; l != nil && ((len(l.IncludeLocations) > 0 && !anyIn(l.IncludeLocations, "All")) || len(l.ExcludeLocations) > 0) {
		return false, "is limited by location"
	}
	if pl := c.Platforms; pl != nil && ((len(pl.IncludePlatforms) > 0 && !anyIn(pl.IncludePlatforms, "all")) || len(pl.ExcludePlatforms) > 0) {
		return false, "is limited to some device platforms"
	}
	if d := c.Devices; d != nil && d.DeviceFilter != nil && strings.TrimSpace(d.DeviceFilter.Rule) != "" {
		return false, "is limited by a device filter"
	}
	if len(c.ClientAppTypes) > 0 && !anyIn(c.ClientAppTypes, "all") {
		return false, "is limited to some client apps"
	}
	if len(c.SignInRiskLevels) > 0 || len(c.UserRiskLevels) > 0 || len(c.ServicePrincipalRiskLevels) > 0 ||
		(c.InsiderRiskLevels != nil && *c.InsiderRiskLevels != "") {
		return false, "only applies at some risk levels"
	}
	return true, ""
}

// caSubject is one administrator as conditional access sees them.
type caSubject struct {
	ID      string
	Roles   []string // role template IDs
	Groups  []string // transitive group IDs
	GroupsK bool     // group membership known
}

func anyIn(list []string, vals ...string) bool {
	for _, l := range list {
		for _, v := range vals {
			if v != "" && strings.EqualFold(l, v) {
				return true
			}
		}
	}
	return false
}

// coversWithMFA reports whether this policy enforces MFA for the subject on all
// cloud apps: enabled, grants "mfa", includes the subject (All users, the user, one
// of their admin role templates, or one of their groups) and excludes none of them.
// An exclude-group whose membership is unknown is treated as excluding (fail closed).
func (p caPolicy) coversWithMFA(s caSubject) (bool, string) {
	if !p.enabled() || !p.requiresMFA() {
		return false, ""
	}
	if ok, why := p.allSignIns(); !ok {
		return false, fmt.Sprintf("policy %q %s", p.DisplayName, why)
	}
	u := p.Conditions.Users
	included := anyIn(u.IncludeUsers, "All", s.ID) || anyIn(u.IncludeRoles, s.Roles...) || anyIn(u.IncludeGroups, s.Groups...)
	if !included {
		return false, ""
	}
	switch {
	case anyIn(u.ExcludeUsers, s.ID):
		return false, fmt.Sprintf("policy %q excludes this user", p.DisplayName)
	case anyIn(u.ExcludeRoles, s.Roles...):
		return false, fmt.Sprintf("policy %q excludes this administrator's role", p.DisplayName)
	case len(u.ExcludeGroups) > 0 && !s.GroupsK:
		return false, fmt.Sprintf("policy %q excludes groups whose membership could not be read", p.DisplayName)
	case anyIn(u.ExcludeGroups, s.Groups...):
		return false, fmt.Sprintf("policy %q excludes a group this user belongs to", p.DisplayName)
	}
	return true, ""
}

// needsGroups reports whether evaluating the policy needs group membership.
func (p caPolicy) needsGroups() bool {
	return p.enabled() && p.requiresMFA() && (len(p.Conditions.Users.IncludeGroups) > 0 || len(p.Conditions.Users.ExcludeGroups) > 0)
}

// maxLegacyBlockUserExclusions is how many individually excluded users a tenant-wide
// legacy-auth block may have: Microsoft's guidance is two emergency-access accounts.
const maxLegacyBlockUserExclusions = 2

// blocksLegacyAuth: enabled policy that blocks both legacy client-app types (Exchange
// ActiveSync and "other" clients) for all users on all cloud apps, with no location,
// platform, device or risk narrowing and no app, group, role or guest exclusion. At
// most maxLegacyBlockUserExclusions individual users (break-glass accounts) may be
// excluded; anything narrower is not a tenant-wide block.
func (p caPolicy) blocksLegacyAuth() bool {
	if !p.enabled() || !p.grants("block") {
		return false
	}
	u := p.Conditions.Users
	if !anyIn(u.IncludeUsers, "All") || len(u.ExcludeGroups) > 0 || len(u.ExcludeRoles) > 0 ||
		len(u.ExcludeUsers) > maxLegacyBlockUserExclusions || anyIn(u.ExcludeUsers, "GuestsOrExternalUsers") ||
		(len(u.ExcludeGuestsOrExternalUsers) > 0 && string(u.ExcludeGuestsOrExternalUsers) != "null") {
		return false
	}
	types := p.Conditions.ClientAppTypes
	if !anyIn(types, "all") && !(anyIn(types, "exchangeActiveSync") && anyIn(types, "other")) {
		return false
	}
	// Every other condition must match all sign-ins (allSignIns checks apps, app
	// exclusions, locations, platforms, device filter and risk levels); client-app
	// types were checked above.
	q := p
	q.Conditions.ClientAppTypes = nil
	ok, _ := q.allSignIns()
	return ok
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
	resp, err := tokenRedirectSafe(client).Do(req)
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

// ErrTokenRedirect is returned when the token endpoint redirects to another origin: the
// request body carries the client secret (net/http resends it on 307/308), so it is never
// followed.
var ErrTokenRedirect = errors.New("m365: token request redirected to another origin; refused (the request carries the client secret)")

// tokenRedirectSafe applies core/rest.go's redirect rule to the token request client (a
// shallow copy; the caller's CheckRedirect still runs afterwards): an https → non-https hop is
// refused with core.ErrInsecureRedirect, and — stricter than REST, because the credential is
// in the body, not a header that can be stripped — any hop to another scheme/host/port is
// refused with ErrTokenRedirect. Same-origin hops drop nothing and are followed.
func tokenRedirectSafe(client *http.Client) *http.Client {
	cp := *client
	inner := client.CheckRedirect
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		for _, prev := range via {
			if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("%w: %s → %s", core.ErrInsecureRedirect, prev.URL.Redacted(), req.URL.Redacted())
			}
		}
		orig := via[0].URL
		if !strings.EqualFold(orig.Scheme, req.URL.Scheme) || !strings.EqualFold(orig.Host, req.URL.Host) {
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.Header.Del("Proxy-Authorization")
			return fmt.Errorf("%w: %s → %s", ErrTokenRedirect, orig.Redacted(), req.URL.Redacted())
		}
		if inner != nil {
			return inner(req, via)
		}
		return nil
	}
	return &cp
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

	adminRoles := map[string][]string{}     // user id -> role names
	adminTemplates := map[string][]string{} // user id -> role template ids
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
			adminTemplates[m.ID] = append(adminTemplates[m.ID], r.RoleTemplateID, r.ID)
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
	var caLegacy []string
	needGroups := false
	for _, p := range policies {
		if p.blocksLegacyAuth() {
			caLegacy = append(caLegacy, p.DisplayName)
		}
		if p.needsGroups() {
			needGroups = true
		}
	}
	// caCoverage evaluates every policy for one administrator.
	caCoverage := func(id string) (covering []string, why []string) {
		s := caSubject{ID: id, Roles: adminTemplates[id]}
		if needGroups {
			err := rc.GetAll(ctx, "/users/"+url.PathEscape(id)+"/transitiveMemberOf?$select=id", func(item json.RawMessage) error {
				var g struct {
					ID string `json:"id"`
				}
				if err := json.Unmarshal(item, &g); err != nil {
					return err
				}
				s.Groups = append(s.Groups, g.ID)
				return nil
			})
			if err != nil {
				acc.Warn("m365: group membership of %s not readable (%v); exclude-group policies treated as excluding", id, err)
			} else {
				s.GroupsK = true
			}
		}
		for _, p := range policies {
			ok, reason := p.coversWithMFA(s)
			if ok {
				covering = append(covering, p.DisplayName)
			} else if reason != "" {
				why = append(why, reason)
			}
		}
		return covering, why
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
		var caMFA, excluded []string
		if !(regKnown && registered) && caKnown {
			caMFA, excluded = caCoverage(id)
		}
		exclNote := ""
		if len(excluded) > 0 {
			exclNote = " Excluded: " + strings.Join(excluded, "; ") + "."
		}
		switch {
		case regKnown && registered:
			pass, detail = true, "Administrator has MFA registered."
		case len(caMFA) > 0:
			pass, detail = true, "Administrator is covered by conditional access requiring MFA: "+strings.Join(caMFA, ", ")+"."
		case !mfaKnown || !regKnown:
			if !caKnown {
				continue // nothing to evaluate against
			}
			pass, detail = false, "MFA registration unknown and no enabled conditional access policy requires MFA for this administrator."+exclNote
		default:
			pass, detail = false, "Administrator has no MFA registered and no enabled conditional access policy requires MFA for them."+exclNote
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
