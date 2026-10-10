# Least-change fix for Bedrock agent {{ .Name }}: the public chat endpoint in front of it stops
# accepting unauthenticated calls. Bedrock agents are invoked through an API you own (API Gateway
# HTTP API -> Lambda -> bedrock:InvokeAgent); this file makes that route require SigV4 (AWS_IAM).
# Find the front door that calls the agent (the Lambda's resource policy / the API's integrations):
# CLI: aws bedrock-agent get-agent --agent-id={{ sh .Raw.ShortID }} --query agent.agentResourceRoleArn
# Browser users need a front door that authenticates them first (Cognito authorizer, or
# CloudFront + Lambda@Edge signing); set authorization_type accordingly if so.

variable "{{ .Slug }}_api_id" {
  description = "API Gateway HTTP API id of the public chat endpoint that invokes {{ .Name }}. REQUIRED."
  type        = string
}

variable "{{ .Slug }}_route_id" {
  description = "Route id of the chat route that invokes {{ .Name }} (listed by get-routes on the API). REQUIRED."
  type        = string
}

variable "{{ .Slug }}_route_key" {
  description = "Route key of that route, e.g. POST /chat."
  type        = string
  default     = "POST /chat"
}

import {
  to = aws_apigatewayv2_route.{{ .Slug }}_chat
  id = "${var.{{ .Slug }}_api_id}/${var.{{ .Slug }}_route_id}"
}

resource "aws_apigatewayv2_route" "{{ .Slug }}_chat" {
  api_id             = var.{{ .Slug }}_api_id
  route_key          = var.{{ .Slug }}_route_key
  authorization_type = "AWS_IAM"
  lifecycle {
    ignore_changes = [target, request_models, request_parameter, operation_name, model_selection_expression, route_response_selection_expression]
  }
}
