package saas

import "testing"

// Verify-3 defect 5: a legacy-auth block is tenant-wide only when it is enabled,
// covers all users and all cloud apps, blocks both legacy client-app types and is
// not narrowed by location, platform, device, risk, or app/group/role exclusions.
// Up to two excluded users (emergency-access accounts) are tolerated.
func TestM365LegacyBlockMustBeTenantWide(t *testing.T) {
	const pre = `{"displayName":"L","state":"enabled","conditions":{`
	const post = `},"grantControls":{"builtInControls":["block"]}}`
	const legacy = `"clientAppTypes":["exchangeActiveSync","other"]`
	const allUsers = `"users":{"includeUsers":["All"]}`
	const allApps = `"applications":{"includeApplications":["All"]}`
	cases := []struct {
		name, js string
		want     bool
	}{
		{"tenant-wide", pre + legacy + `,` + allUsers + `,` + allApps + post, true},
		{"break-glass user excluded", pre + legacy + `,"users":{"includeUsers":["All"],"excludeUsers":["bg1","bg2"]},` + allApps + post, true},
		{"three users excluded", pre + legacy + `,"users":{"includeUsers":["All"],"excludeUsers":["u1","u2","u3"]},` + allApps + post, false},
		{"one user", pre + legacy + `,"users":{"includeUsers":["u1"]},` + allApps + post, false},
		{"report-only", `{"displayName":"L","state":"enabledForReportingButNotEnforced","conditions":{` + legacy + `,` + allUsers + `,` + allApps + post, false},
		{"one location", pre + legacy + `,` + allUsers + `,` + allApps + `,"locations":{"includeLocations":["loc-untrusted-1"]}` + post, false},
		{"excludes trusted locations", pre + legacy + `,` + allUsers + `,` + allApps + `,"locations":{"includeLocations":["All"],"excludeLocations":["AllTrusted"]}` + post, false},
		{"android only", pre + legacy + `,` + allUsers + `,` + allApps + `,"platforms":{"includePlatforms":["android"]}` + post, false},
		{"high sign-in risk only", pre + legacy + `,` + allUsers + `,` + allApps + `,"signInRiskLevels":["high"]` + post, false},
		{"user risk only", pre + legacy + `,` + allUsers + `,` + allApps + `,"userRiskLevels":["high"]` + post, false},
		{"device filter", pre + legacy + `,` + allUsers + `,` + allApps + `,"devices":{"deviceFilter":{"mode":"include","rule":"device.isCompliant -eq False"}}` + post, false},
		{"excludes Exchange Online", pre + legacy + `,` + allUsers + `,"applications":{"includeApplications":["All"],"excludeApplications":["00000002-0000-0ff1-ce00-000000000000"]}` + post, false},
		{"excludes a group", pre + legacy + `,"users":{"includeUsers":["All"],"excludeGroups":["all-staff"]},` + allApps + post, false},
		{"excludes a role", pre + legacy + `,"users":{"includeUsers":["All"],"excludeRoles":["r1"]},` + allApps + post, false},
		{"excludes guests", pre + legacy + `,"users":{"includeUsers":["All"],"excludeGuestsOrExternalUsers":{"guestOrExternalUserTypes":"b2bCollaborationGuest"}},` + allApps + post, false},
		{"only exchangeActiveSync", pre + `"clientAppTypes":["exchangeActiveSync"],` + allUsers + `,` + allApps + post, false},
		{"one app only", pre + legacy + `,` + allUsers + `,"applications":{"includeApplications":["00000002-0000-0ff1-ce00-000000000000"]}` + post, false},
		{"mfa not block", `{"displayName":"L","state":"enabled","conditions":{` + legacy + `,` + allUsers + `,` + allApps + `},"grantControls":{"builtInControls":["mfa"]}}`, false},
	}
	for _, c := range cases {
		if got := caPol(t, c.js).blocksLegacyAuth(); got != c.want {
			t.Errorf("%s: blocksLegacyAuth=%v want %v", c.name, got, c.want)
		}
	}
}
