# Scenario ids (S01..S14) and nimbus_lab_id tags match lab/local/estate.yaml.
data "aws_caller_identity" "current" {}
data "aws_vpc" "default" { default = true }
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

locals {
  admin_policy = "arn:aws:iam::aws:policy/AdministratorAccess"
  ec2_assume = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# ---------------------------------------------------------------- S01 public PII bucket
resource "aws_s3_bucket" "pii" {
  bucket        = "nimbus-lab-customer-pii-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = { nimbus_lab_id = "arn:aws:s3:::nimbus-lab-customer-pii", data_classification = "pii", environment = "production" }
}

resource "aws_s3_bucket_public_access_block" "pii" {
  bucket                  = aws_s3_bucket.pii.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "pii_public_read" {
  bucket     = aws_s3_bucket.pii.id
  depends_on = [aws_s3_bucket_public_access_block.pii]
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "${aws_s3_bucket.pii.arn}/*" }]
  })
}

resource "aws_s3_object" "pii_canary" {
  bucket  = aws_s3_bucket.pii.id
  key     = "customers/canary.csv"
  content = "id,email\n0,canary@example.invalid\n" # synthetic; never real PII
}

# ---------------------------------------------------------------- S02 IMDSv1 EC2 behind 0.0.0.0/0 with admin profile
resource "aws_security_group" "web_open" {
  name   = "nimbus-lab-web-open"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { nimbus_lab_id = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60001" }
}

resource "aws_iam_role" "web" {
  name               = "nimbus-lab-web-instance-role"
  assume_role_policy = local.ec2_assume
  tags               = { nimbus_lab_id = "arn:aws:iam::111111111111:role/nimbus-lab-web-instance-role" }
}

resource "aws_iam_role_policy_attachment" "web_admin" {
  role       = aws_iam_role.web.name
  policy_arn = local.admin_policy
}

resource "aws_iam_instance_profile" "web" {
  name = "nimbus-lab-web-profile"
  role = aws_iam_role.web.name
}

resource "aws_instance" "web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web_open.id]
  iam_instance_profile        = aws_iam_instance_profile.web.name
  metadata_options {
    http_tokens   = "optional" # IMDSv1 allowed (the seeded weakness)
    http_endpoint = "enabled"
  }
  tags = { Name = "nimbus-lab-web-01", nimbus_lab_id = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60001", environment = "production" }
}

# ---------------------------------------------------------------- S03 public RDS
resource "aws_security_group" "rds_open" {
  count  = var.enable_rds ? 1 : 0
  name   = "nimbus-lab-rds-open"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  count                       = var.enable_rds ? 1 : 0
  identifier                  = "nimbus-lab-orders"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "labadmin"
  manage_master_user_password = true # password lives in Secrets Manager, never in state outputs
  publicly_accessible         = true
  skip_final_snapshot         = true
  vpc_security_group_ids      = [aws_security_group.rds_open[0].id]
  tags                        = { nimbus_lab_id = "arn:aws:rds:us-east-1:111111111111:db:nimbus-lab-orders", data_classification = "confidential", environment = "production" }
}

# ---------------------------------------------------------------- S04 cross-account trust to an admin role
resource "aws_iam_role" "vendor" {
  name = "nimbus-lab-vendor-access"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.external_account_id}:root" }, Action = "sts:AssumeRole" }] # no ExternalId
  })
  tags = { nimbus_lab_id = "arn:aws:iam::111111111111:role/nimbus-lab-vendor-access" }
}

resource "aws_iam_role_policy_attachment" "vendor_admin" {
  role       = aws_iam_role.vendor.name
  policy_arn = local.admin_policy
}

# ---------------------------------------------------------------- S05 IAM user without MFA, AdministratorAccess
# The 400-day-old access key cannot be seeded in a fresh account, and creating any key would put
# a secret in Terraform state. S05's STALE_CREDENTIALS weakness (W10) is local-lab only; the
# cloud lab checks NO_MFA + admin.
resource "aws_iam_user" "ops" {
  name = "nimbus-lab-ops-jane"
  tags = { nimbus_lab_id = "arn:aws:iam::111111111111:user/nimbus-lab-ops-jane" }
}

resource "aws_iam_user_policy_attachment" "ops_admin" {
  user       = aws_iam_user.ops.name
  policy_arn = local.admin_policy
}

# ---------------------------------------------------------------- S06 public Lambda function URL -> role -> PII bucket
data "archive_file" "export" {
  type        = "zip"
  output_path = "${path.module}/.build/export.zip"
  source {
    filename = "index.py"
    content  = "def handler(event, context):\n    return {'statusCode': 200, 'body': 'nimbus lab'}\n"
  }
}

resource "aws_iam_role" "export" {
  name = "nimbus-lab-export-lambda-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = { nimbus_lab_id = "arn:aws:iam::111111111111:role/nimbus-lab-export-lambda-role" }
}

resource "aws_iam_role_policy" "export_read_pii" {
  role = aws_iam_role.export.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.pii.arn}/*" }]
  })
}

resource "aws_lambda_function" "export" {
  function_name    = "nimbus-lab-export"
  role             = aws_iam_role.export.arn
  runtime          = "python3.12"
  handler          = "index.handler"
  filename         = data.archive_file.export.output_path
  source_code_hash = data.archive_file.export.output_base64sha256
  tags             = { nimbus_lab_id = "arn:aws:lambda:us-east-1:111111111111:function:nimbus-lab-export" }
}

resource "aws_lambda_function_url" "export" {
  function_name      = aws_lambda_function.export.function_name
  authorization_type = "NONE"
}

# ---------------------------------------------------------------- S12 GitHub OIDC deploy role with AdministratorAccess
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "gha_deploy" {
  name = "nimbus-lab-gha-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*" } } # any branch: the weakness
    }]
  })
  tags = { nimbus_lab_id = "arn:aws:iam::111111111111:role/nimbus-lab-gha-deploy" }
}

resource "aws_iam_role_policy_attachment" "gha_admin" {
  role       = aws_iam_role.gha_deploy.name
  policy_arn = local.admin_policy
}

# ---------------------------------------------------------------- S13 seeded false positive: SSH only from the corporate CIDR
resource "aws_security_group" "corp_ssh" {
  name   = "nimbus-lab-corp-ssh"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.corp_cidr]
    description = "corporate egress range (trusted_cidrs)"
  }
  tags = { nimbus_lab_id = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0a1b2c3d4e5f60002" }
}

resource "aws_iam_role" "corp" {
  name               = "nimbus-lab-corp-tools-role"
  assume_role_policy = local.ec2_assume
  tags               = { nimbus_lab_id = "arn:aws:iam::111111111111:role/nimbus-lab-corp-tools-role" }
}

resource "aws_iam_role_policy_attachment" "corp_poweruser" {
  role       = aws_iam_role.corp.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_instance_profile" "corp" {
  name = "nimbus-lab-corp-tools-profile"
  role = aws_iam_role.corp.name
}

resource "aws_instance" "corp" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.corp_ssh.id]
  iam_instance_profile        = aws_iam_instance_profile.corp.name
  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }
  tags = { Name = "nimbus-lab-corp-tools-01", nimbus_lab_id = "arn:aws:ec2:us-east-1:111111111111:instance/i-0a1b2c3d4e5f60002", environment = "production" }
}
