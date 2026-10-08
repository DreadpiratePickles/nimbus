# Replace the wildcard policy with a scoped one. Fill in the actions actually used
# (CloudTrail / IAM Access Analyzer "generate policy" is a good source).
data "aws_iam_policy_document" "{{ .Slug }}_scoped" {
  statement {
    sid       = "ScopedInsteadOfAdmin"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"] # TODO: least-privilege action list
    resources = ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
  }
}

import {
  to = aws_iam_policy.{{ .Slug }}
  id = "{{ .ID }}"
}

resource "aws_iam_policy" "{{ .Slug }}" {
  name   = "{{ .Name }}"
  policy = data.aws_iam_policy_document.{{ .Slug }}_scoped.json
}
