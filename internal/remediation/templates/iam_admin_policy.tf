# Least-change fix for IAM policy {{ .Name }}: it stays attached to the same principals; only
# Action "*" is replaced by the actions those principals actually use. Nothing is detached.
# 1. TODO: build the action list from real usage (nimbus cannot observe it yet):
#      IAM Access Analyzer "generate policy" from CloudTrail, or
# CLI: aws iam generate-service-last-accessed-details --arn={{ sh .Raw.ID }}
# 2. Put it in {{ .Slug }}_allowed_actions (tfvars). Narrow {{ .Slug }}_allowed_resources later.
# 3. terraform plan: only aws_iam_policy.{{ .Slug }} may change (it gets a new default version).
# Rollback (set PREVIOUS_VERSION):
# CLI: aws iam set-default-policy-version --policy-arn={{ sh .Raw.ID }} --version-id="$PREVIOUS_VERSION"

variable "{{ .Slug }}_allowed_actions" {
  description = "REQUIRED (TODO): IAM actions the principals of {{ .Name }} use, e.g. [\"s3:GetObject\", \"ec2:Describe*\"]."
  type        = list(string)
  {{- with .Attr.observed_actions }}
  default     = {{ hcllist . }}
  {{- end }}
  validation {
    condition     = length(var.{{ .Slug }}_allowed_actions) > 0 && alltrue([for a in var.{{ .Slug }}_allowed_actions : can(regex("^[a-z0-9-]+:[A-Za-z0-9*]+$", a))])
    error_message = "List service:Action entries; a bare * would keep the policy administrative."
  }
}

variable "{{ .Slug }}_allowed_resources" {
  description = "Resource ARNs the actions apply to. Defaults to all resources, as today; narrow once the action list is right."
  type        = list(string)
  default     = ["*"]
}

data "aws_iam_policy_document" "{{ .Slug }}_scoped" {
  statement {
    sid       = "ScopedFromAdmin"
    effect    = "Allow"
    actions   = var.{{ .Slug }}_allowed_actions
    resources = var.{{ .Slug }}_allowed_resources
  }
}

import {
  to = aws_iam_policy.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "aws_iam_policy" "{{ .Slug }}" {
  name   = "{{ .Name }}"
  policy = data.aws_iam_policy_document.{{ .Slug }}_scoped.json
  lifecycle {
    # Changing name/path/description forces replacement (detach + delete); never touch them here.
    ignore_changes = [name, name_prefix, path, description, tags]
  }
}
