# Every human identity with console/password access must have MFA.
# Input: {"users": [{"name": "...", "password_enabled": true, "mfa_active": false, "admin": false}]}
# (shape of the AWS IAM credential report / Okta / Entra exports normalised by cloud-posture).
package nimbus.identity.no_mfa

import rego.v1

deny contains msg if {
	u := input.users[_]
	u.password_enabled == true
	not u.mfa_active == true
	msg := sprintf("user %q can sign in with a password but has no MFA (IAM_USER_NO_MFA)", [u.name])
}

deny contains msg if {
	u := input.users[_]
	u.admin == true
	not u.mfa_active == true
	msg := sprintf("administrator %q has no MFA (OKTA_ADMIN_NO_MFA / M365_NO_MFA_ADMIN)", [u.name])
}
