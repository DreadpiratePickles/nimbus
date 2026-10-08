variable "{{ .Slug }}_trusted_account_ids" {
  description = "Explicit AWS account IDs allowed to assume {{ .Name }}"
  type        = list(string)
  default     = []
}

data "aws_iam_policy_document" "{{ .Slug }}_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [for id in var.{{ .Slug }}_trusted_account_ids : "arn:aws:iam::${id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["TODO-external-id"]
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
    ignore_changes = [description, tags, managed_policy_arns, inline_policy]
  }
}
