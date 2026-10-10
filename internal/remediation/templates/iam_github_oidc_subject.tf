# Least-change fix for role {{ .Name }}: its GitHub Actions OIDC trust names the repositories (and
# branches or environments) that may assume it, instead of every workflow on GitHub.
# BEFORE applying, compare with the live trust policy and carry over anything still needed:
# CLI: aws iam get-role --role-name={{ sh .Raw.Name }} --query Role.AssumeRolePolicyDocument
# Other (non-GitHub) statements are NOT reproduced here; the plan would drop them.

variable "{{ .Slug }}_allowed_subjects" {
  description = "GitHub OIDC subjects allowed to assume {{ .Name }}, e.g. repo:my-org/infra-live:ref:refs/heads/main or repo:my-org/infra-live:environment:production. REQUIRED."
  type        = list(string)
  validation {
    condition     = length(var.{{ .Slug }}_allowed_subjects) > 0 && alltrue([for s in var.{{ .Slug }}_allowed_subjects : can(regex("^repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.*-]+:.+$", s))])
    error_message = "Each subject is repo:<org>/<repo>:<ref|environment|pull_request ...>; a bare * is what this fix removes."
  }
}

data "aws_caller_identity" "{{ .Slug }}" {}

data "aws_iam_policy_document" "{{ .Slug }}_trust" {
  statement {
    sid     = "GitHubActionsOIDC"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.{{ .Slug }}.account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.{{ .Slug }}_allowed_subjects
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
    ignore_changes = [description, max_session_duration, managed_policy_arns, inline_policy, permissions_boundary, tags, tags_all, path]
  }
}
