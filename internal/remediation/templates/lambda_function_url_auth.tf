# Least-change fix for Lambda function {{ .Name }}: its function URL stops accepting anonymous
# calls (AuthType NONE). With AWS_IAM, callers sign requests with SigV4 and need
# lambda:InvokeFunctionUrl, either in their own IAM policy or through invoker_arns below.
# Only the URL's authorization type is managed; CORS and invoke mode are left as they are.
# Browser or webhook callers that cannot sign requests need a front door first (CloudFront with
# origin access control, or API Gateway with an authorizer).
# Current URL config, and any public (Principal "*") statement in the resource policy:
# CLI: aws lambda get-function-url-config --function-name={{ sh .Raw.Name }}
# CLI: aws lambda get-policy --function-name={{ sh .Raw.Name }}
# A public statement there is a second way in; remove it by its Sid once callers are listed:
# CLI: aws lambda remove-permission --function-name={{ sh .Raw.Name }} --statement-id="$PUBLIC_STATEMENT_ID"

variable "{{ .Slug }}_invoker_arns" {
  description = "IAM role/user ARNs that must keep invoking the URL of {{ .Name }} once it requires AWS_IAM. Empty: only principals whose own IAM policy allows lambda:InvokeFunctionUrl."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for a in var.{{ .Slug }}_invoker_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:(role|user)/", a))])
    error_message = "List IAM role or user ARNs; a wildcard principal would re-open the URL."
  }
}

import {
  to = aws_lambda_function_url.{{ .Slug }}
  id = "{{ .Name }}"
}

resource "aws_lambda_function_url" "{{ .Slug }}" {
  function_name      = "{{ .Name }}"
  authorization_type = "AWS_IAM"
  lifecycle {
    ignore_changes = [cors, invoke_mode]
  }
}

resource "aws_lambda_permission" "{{ .Slug }}_invoke_url" {
  for_each               = toset(var.{{ .Slug }}_invoker_arns)
  statement_id           = "nimbus-invoke-url-${substr(sha1(each.value), 0, 12)}"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = "{{ .Name }}"
  principal              = each.value
  function_url_auth_type = "AWS_IAM"
}
# CLI: aws lambda update-function-url-config --function-name={{ sh .Raw.Name }} --auth-type=AWS_IAM
