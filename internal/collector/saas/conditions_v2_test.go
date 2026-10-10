package saas

// V2 defect 8 (M365 / Okta false PASS). Adapted from the verifier probe zz_verify_idp_test.go.

import (
	"encoding/json"
	"fmt"
	"testing"
)

const gaRoleTemplate = "62e90394-69f5-4237-9190-012177145e10"

func caPol(t *testing.T, js string) caPolicy {
	var p caPolicy
	if err := json.Unmarshal([]byte(js), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestM365CoverageConditions(t *testing.T) {
	admin := caSubject{ID: "a1", Roles: []string{gaRoleTemplate}, GroupsK: true}
	base := `"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}%s}`
	cases := []struct {
		name string
		js   string
		want bool
	}{
		{"report-only", `{"displayName":"p","state":"enabledForReportingButNotEnforced",` + sprintf(base, "") + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"disabled", `{"displayName":"p","state":"disabled",` + sprintf(base, "") + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"compliantDevice only", `{"displayName":"p","state":"enabled",` + sprintf(base, "") + `,"grantControls":{"builtInControls":["compliantDevice"]}}`, false},
		{"OR mfa|compliantDevice (MFA bypassable)", `{"displayName":"p","state":"enabled",` + sprintf(base, "") + `,"grantControls":{"operator":"OR","builtInControls":["mfa","compliantDevice"]}}`, false},
		{"AND mfa+compliantDevice", `{"displayName":"p","state":"enabled",` + sprintf(base, "") + `,"grantControls":{"operator":"AND","builtInControls":["mfa","compliantDevice"]}}`, true},
		{"All users, excludeRoles GA", `{"displayName":"p","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeRoles":["` + gaRoleTemplate + `"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"GuestsOrExternalUsers only", `{"displayName":"p","state":"enabled","conditions":{"users":{"includeUsers":["GuestsOrExternalUsers"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"All apps but excludes Azure Management", `{"displayName":"p","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"],"excludeApplications":["797f4846-ba00-4fd7-ba43-dac1f8f63013"]}},"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"only from untrusted locations (excludes AllTrusted)", `{"displayName":"p","state":"enabled",` + sprintf(base, `,"locations":{"includeLocations":["All"],"excludeLocations":["AllTrusted"]}`) + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"only on high sign-in risk", `{"displayName":"p","state":"enabled",` + sprintf(base, `,"signInRiskLevels":["high"]`) + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"only exchangeActiveSync client", `{"displayName":"p","state":"enabled",` + sprintf(base, `,"clientAppTypes":["exchangeActiveSync"]`) + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"only android platform", `{"displayName":"p","state":"enabled",` + sprintf(base, `,"platforms":{"includePlatforms":["android"]}`) + `,"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"applications omitted (null)", `{"displayName":"p","state":"enabled","conditions":{"users":{"includeUsers":["All"]}},"grantControls":{"builtInControls":["mfa"]}}`, false},
		{"authenticationStrength MFA (no builtIn mfa)", `{"displayName":"p","state":"enabled",` + sprintf(base, "") + `,"grantControls":{"builtInControls":[],"authenticationStrength":{"id":"00000000-0000-0000-0000-000000000002"}}}`, true},
	}
	for _, c := range cases {
		got, why := caPol(t, c.js).coversWithMFA(admin)
		if got != c.want {
			t.Errorf("MISMATCH %s: covers=%v (%s) want %v", c.name, got, why, c.want)
		}
	}
	// legacy-auth blocking scoped to a single test user counts as tenant-wide?
	p := caPol(t, `{"displayName":"block legacy for one user","state":"enabled","conditions":{"clientAppTypes":["exchangeActiveSync","other"],"users":{"includeUsers":["u-test"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}`)
	if p.blocksLegacyAuth() {
		t.Errorf("MISMATCH legacy-auth block scoped to one user counts as tenant-wide block")
	}
}

func TestOktaScopedRulesAreNotCatchAll(t *testing.T) {
	parse := func(js string) []oktaRule {
		var rs []oktaRule
		if err := json.Unmarshal([]byte(js), &rs); err != nil {
			t.Fatal(err)
		}
		return rs
	}
	defNo := `{"name":"Default Rule","status":"ACTIVE","priority":99,"system":true,"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}`
	defMFA := `{"name":"Default Rule","status":"ACTIVE","priority":99,"system":true,"actions":{"signon":{"access":"ALLOW","requireFactor":true}}}`
	cases := []struct {
		name, rules string
		want        bool
	}{
		{"zone-only MFA rule then no-MFA default", `[{"name":"off-net","status":"ACTIVE","priority":1,"conditions":{"network":{"connection":"ZONE","exclude":["corp"]}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},` + defNo + `]`, false},
		{"higher-prio allow-no-MFA scoped rule precedes MFA catch-all", `[{"name":"mfa","status":"ACTIVE","priority":2,"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},{"name":"contractors","status":"ACTIVE","priority":1,"conditions":{"people":{"groups":{"include":["g"]}}},"actions":{"signon":{"access":"ALLOW","requireFactor":false}}}]`, false},
		{"inactive no-MFA rule ignored", `[{"name":"x","status":"INACTIVE","priority":1,"actions":{"signon":{"access":"ALLOW","requireFactor":false}}},` + defMFA + `]`, true},
		{"people exclude MFA rule then no-MFA default", `[{"name":"mfa-except","status":"ACTIVE","priority":1,"conditions":{"people":{"users":{"exclude":["u1"]}}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},` + defNo + `]`, false},
		{"risk-scoped MFA rule then no-MFA default", `[{"name":"risky","status":"ACTIVE","priority":1,"conditions":{"riskScore":{"level":"HIGH"}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},` + defNo + `]`, false},
		{"IdP-scoped MFA rule then no-MFA default", `[{"name":"idp","status":"ACTIVE","priority":1,"conditions":{"identityProvider":{"provider":"SPECIFIC_IDP","idpIds":["x"]}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},` + defNo + `]`, false},
		{"network ANYWHERE with exclude zones", `[{"name":"n","status":"ACTIVE","priority":1,"conditions":{"network":{"connection":"ANYWHERE","exclude":["corp"]}},"actions":{"signon":{"access":"ALLOW","requireFactor":true}}},` + defNo + `]`, true},
	}
	for _, c := range cases {
		got, why := signOnRequiresMFA(parse(c.rules))
		if got != c.want {
			t.Errorf("MISMATCH %s: %v (%s) want %v", c.name, got, why, c.want)
		}
	}
}

func sprintf(f, a string) string { return fmt.Sprintf(f, a) }
