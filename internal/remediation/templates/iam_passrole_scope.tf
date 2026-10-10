# Least-change fix for a privilege escalation ({{ .Attr.technique }}): {{ .Name }} may pass
# {{ .Attr.escalation_role }} to {{ .Attr.passed_to_service }} and so act as that role.
# Keep every other permission; scope iam:PassRole to the roles {{ .Name }} really passes (never an
# admin role) and only to {{ .Attr.passed_to_service }}. Granting statement: {{ .Attr.statement }}
{{- if .Attr.policy_diff }}
# Policy diff (the PassRole grant only; everything else unchanged):
{{- range .Attr.policy_diff }}
#   {{ . }}
{{- end }}
{{- end }}
# 1. Put the roles {{ .Name }} must still pass in {{ .Slug }}_passable_roles (empty = none).
# 2. Replace the granting statement with data.aws_iam_policy_document.{{ .Slug }}_passrole
#    (inline policy: merge into the principal's aws_iam_user_policy / aws_iam_role_policy;
#    managed policy: new default version via source_policy_documents).
# 3. terraform plan: only that policy may change.
# Rollback: restore the saved policy document (aws iam get-user-policy / get-role-policy /
# get-policy-version before applying).

variable "{{ .Slug }}_passable_roles" {
  description = "Role ARNs {{ .Name }} may still pass to {{ .Attr.passed_to_service }}. Must not include {{ .Attr.escalation_role }} or a wildcard."
  type        = list(string)
  default     = {{ hcllist .Attr.allowed_roles }}
  validation {
    condition     = alltrue([for r in var.{{ .Slug }}_passable_roles : r != "{{ .Attr.escalation_role }}" && !strcontains(r, "*")])
    error_message = "The escalation role and wildcards keep the privilege escalation open."
  }
}

data "aws_iam_policy_document" "{{ .Slug }}_passrole" {
  dynamic "statement" {
    for_each = length(var.{{ .Slug }}_passable_roles) > 0 ? [1] : []
    content {
      sid       = "ScopedPassRole"
      effect    = "Allow"
      actions   = ["iam:PassRole"]
      resources = var.{{ .Slug }}_passable_roles
      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["{{ .Attr.passed_to_service }}"]
      }
    }
  }
  statement {
    sid       = "DenyEscalationPassRole"
    effect    = "Deny"
    actions   = ["iam:PassRole"]
    resources = ["{{ .Attr.escalation_role }}"]
  }
}

output "{{ .Slug }}_passrole_policy" {
  description = "The scoped PassRole statements for {{ .Name }}: merge them in place of the granting statement."
  value       = data.aws_iam_policy_document.{{ .Slug }}_passrole.json
}
