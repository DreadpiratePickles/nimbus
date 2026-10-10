{{- $accts := or .Attr.trusted_accounts (accountids .Attr.trust_principals) -}}
{{- $needCond := eq (printf "%v" .Attr.external_id_required) "false" -}}
# Least-change fix for role {{ .Name }}: the trust policy names the accounts that already use the
# role instead of a wildcard/unexpected principal, and can require sts:ExternalId (third-party
# access: the confused-deputy guard) or aws:PrincipalOrgID (callers inside your AWS Organization).
# No MFA condition is added (it would lock out automation).
{{- if $needCond }}
# The finding is a trust without ExternalId: the plan stops until external_id or principal_org_id is set.
{{- end }}
# BEFORE applying, compare with the live trust policy and carry over anything still needed:
# CLI: aws iam get-role --role-name={{ sh .Raw.Name }} --query Role.AssumeRolePolicyDocument
# Federated (SAML/OIDC) statements are NOT reproduced here; the plan would drop them.

variable "{{ .Slug }}_trusted_account_ids" {
  description = "12-digit AWS account IDs allowed to assume {{ .Name }}.{{ if not $accts }} REQUIRED: nimbus saw no explicit external account (the role trusts a wildcard).{{ end }}"
  type        = list(string)
  {{- with $accts }}
  default     = {{ hcllist . }} # accounts nimbus observed in the current trust policy
  {{- end }}
  validation {
    condition     = length(var.{{ .Slug }}_trusted_account_ids) > 0 && alltrue([for id in var.{{ .Slug }}_trusted_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "List 12-digit account IDs; a wildcard principal is what this fix removes."
  }
}

variable "{{ .Slug }}_trusted_services" {
  description = "AWS service principals that must keep trusting the role (e.g. ec2.amazonaws.com)."
  type        = list(string)
  default     = {{ with .Attr.trusted_services }}{{ hcllist . }}{{ else }}[]{{ end }}
}

variable "{{ .Slug }}_external_id" {
  description = "sts:ExternalId the trusted accounts must send (third-party access; agree the value with the vendor).{{ if $needCond }} Set this or principal_org_id.{{ else }} null keeps today's behaviour.{{ end }}"
  type        = string
  default     = null
  validation {
    condition     = var.{{ .Slug }}_external_id == null || can(regex("^[A-Za-z0-9+=,.@:/-]{2,1224}$", var.{{ .Slug }}_external_id))
    error_message = "An external ID is 2-1224 characters of A-Z a-z 0-9 + = , . @ : / -."
  }
}

variable "{{ .Slug }}_principal_org_id" {
  description = "AWS Organization ID (o-...) the calling principals must belong to (aws:PrincipalOrgID), for trust inside your organization.{{ if $needCond }} Set this or external_id.{{ else }} null adds no condition.{{ end }}"
  type        = string
  default     = null
  validation {
    condition     = var.{{ .Slug }}_principal_org_id == null || can(regex("^o-[a-z0-9]{10,32}$", var.{{ .Slug }}_principal_org_id))
    error_message = "An organization ID looks like o-a1b2c3d4e5."
  }
}

data "aws_iam_policy_document" "{{ .Slug }}_trust" {
  statement {
    sid     = "TrustedAccounts"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [for id in var.{{ .Slug }}_trusted_account_ids : "arn:aws:iam::${id}:root"]
    }
    dynamic "condition" {
      for_each = var.{{ .Slug }}_external_id == null ? [] : [var.{{ .Slug }}_external_id]
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
    dynamic "condition" {
      for_each = var.{{ .Slug }}_principal_org_id == null ? [] : [var.{{ .Slug }}_principal_org_id]
      content {
        test     = "StringEquals"
        variable = "aws:PrincipalOrgID"
        values   = [condition.value]
      }
    }
  }
  dynamic "statement" {
    for_each = length(var.{{ .Slug }}_trusted_services) > 0 ? [1] : []
    content {
      sid     = "TrustedServices"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "Service"
        identifiers = var.{{ .Slug }}_trusted_services
      }
    }
  }
}

import {
  to = aws_iam_role.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_iam_role" "{{ .Slug }}" {
  name               = "{{ .Name }}"
  assume_role_policy = data.aws_iam_policy_document.{{ .Slug }}_trust.json
  lifecycle {
    ignore_changes = [name, path, description, max_session_duration, permissions_boundary, tags, managed_policy_arns, inline_policy]
{{- if $needCond }}
    precondition {
      condition     = var.{{ .Slug }}_external_id != null || var.{{ .Slug }}_principal_org_id != null
      error_message = "This role is trusted without an ExternalId: set external_id (third party) or principal_org_id (inside your organization)."
    }
{{- end }}
  }
}
