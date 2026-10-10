# Least-change fix for Okta user {{ .Name }}: the sign-on rule that lets the user in without MFA
# requires it. Find the policy and rule that matched (System Log: policy.evaluate_sign_on, or Admin
# Console > Security > Authentication policies) and pass their ids; the rule's other settings are
# imported and kept.

variable "{{ .Slug }}_policy_id" {
  description = "Id of the Okta sign-on policy whose rule exempts {{ .Name }} from MFA. REQUIRED."
  type        = string
}

variable "{{ .Slug }}_rule_id" {
  description = "Id of the MFA-exempt rule in that policy. REQUIRED."
  type        = string
}

variable "{{ .Slug }}_rule_name" {
  description = "Name of that rule (as shown in the Admin Console)."
  type        = string
}

import {
  to = okta_policy_rule_signon.{{ .Slug }}
  id = "${var.{{ .Slug }}_policy_id}/${var.{{ .Slug }}_rule_id}"
}

resource "okta_policy_rule_signon" "{{ .Slug }}" {
  policy_id          = var.{{ .Slug }}_policy_id
  name               = var.{{ .Slug }}_rule_name
  mfa_required       = true
  mfa_prompt         = "SESSION"
  mfa_remember_device = false
  lifecycle {
    ignore_changes = [network_connection, network_includes, network_excludes, users_excluded, groups_included, session_idle, session_lifetime, session_persistent, priority, status, access, authtype, identity_provider, behaviors, risc_level]
  }
}
