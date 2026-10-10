# Least-change fix for {{ .Name }}: protect the default branch with pull-request review and no
# force pushes or deletion. Status checks are not required (the contexts are repo-specific).
# Needs the integrations/github provider configured for the repository's owner.
# Admins are not bound (enforce_admins = false) so a break-glass push stays possible.
# Compare with the current rule first (Settings → Branches, or GET /repos/OWNER/REPO/branches/BRANCH/protection;
# 404 means none): a rule this file replaces loses any setting not listed here.

variable "{{ .Slug }}_required_approvals" {
  description = "Approving reviews a pull request into {{ default "main" .Attr.default_branch }} of {{ .Name }} needs."
  type        = number
  default     = 1
  validation {
    condition     = var.{{ .Slug }}_required_approvals >= 1 && var.{{ .Slug }}_required_approvals <= 6
    error_message = "Between 1 and 6 approving reviews."
  }
}

data "github_repository" "{{ .Slug }}" {
  full_name = "{{ .Name }}"
}

resource "github_branch_protection" "{{ .Slug }}" {
  repository_id           = data.github_repository.{{ .Slug }}.node_id
  pattern                 = "{{ default "main" .Attr.default_branch }}"
  enforce_admins          = false
  allows_force_pushes     = false
  allows_deletions        = false
  required_linear_history = false
  required_pull_request_reviews {
    required_approving_review_count = var.{{ .Slug }}_required_approvals
    dismiss_stale_reviews           = true
  }
}
