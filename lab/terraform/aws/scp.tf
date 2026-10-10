# S14: path behind an SCP deny. Needs a second (member) account in an AWS Organization and
# credentials for the management account, so it is a sketch until those exist:
#
#   provider "aws" { alias = "org_mgmt" }                       # management account
#   provider "aws" { alias = "workloads" }                      # member account 222222222222 stand-in
#   resource "aws_organizations_policy" "quarantine" {
#     provider = aws.org_mgmt
#     name     = "nimbus-lab-quarantine"
#     type     = "SERVICE_CONTROL_POLICY"
#     content  = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Action = "*", Resource = "*",
#       Condition = { ArnLike = { "aws:PrincipalArn" = "arn:aws:iam::<member>:role/nimbus-lab-batch-role" } } }] })
#   }
#   resource "aws_organizations_policy_attachment" "quarantine" { provider = aws.org_mgmt, policy_id = ..., target_id = "<member account id>" }
#   + in the member account: nimbus-lab-batch-01 (IMDSv1, 0.0.0.0/0) with nimbus-lab-batch-role (AdministratorAccess)
#
# Ground truth S01 (lab/ground_truth.yaml) is status pending-feature: the path must disappear
# once nimbus evaluates SCP denies.
