output "lab_id_map" {
  description = "Real resource id -> estate resource id, consumed by the e2e harness (tests/e2e, NIMBUS_E2E=1)."
  value = merge(
    { (aws_s3_bucket.pii.arn) = "arn:aws:s3:::nimbus-lab-customer-pii" },
    { (aws_instance.web.arn) = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60001" },
    { (aws_security_group.web_open.arn) = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60001" },
    { (aws_iam_role.web.arn) = "arn:aws:iam::111111111111:role/nimbus-lab-web-instance-role" },
    { (aws_iam_role.vendor.arn) = "arn:aws:iam::111111111111:role/nimbus-lab-vendor-access" },
    { (aws_iam_user.ops.arn) = "arn:aws:iam::111111111111:user/nimbus-lab-ops-jane" },
    { (aws_lambda_function.export.arn) = "arn:aws:lambda:us-east-1:111111111111:function:nimbus-lab-export" },
    { (aws_iam_role.export.arn) = "arn:aws:iam::111111111111:role/nimbus-lab-export-lambda-role" },
    { (aws_iam_role.gha_deploy.arn) = "arn:aws:iam::111111111111:role/nimbus-lab-gha-deploy" },
    { (aws_instance.corp.arn) = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60002" },
    { (aws_security_group.corp_ssh.arn) = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60002" },
    { (aws_iam_role.corp.arn) = "arn:aws:iam::111111111111:role/nimbus-lab-corp-tools-role" },
    var.enable_rds ? { (aws_db_instance.orders[0].arn) = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-orders" } : {},
    var.enable_eks ? { (aws_eks_cluster.lab[0].arn) = "arn:aws:eks:us-east-1:111111111111:cluster/nimbus-lab-eks" } : {},
  )
}
