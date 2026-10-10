# Defect 17 fixture: unary operators, ternaries, for expressions, nulls and
# references that are not statically known. The native scanner must never panic.
variable "public" {
  type    = bool
  default = false
}

variable "port" {
  type    = number
  default = 22
}

locals {
  ports   = [for p in [22, 443] : p]
  by_name = { for n in ["a", "b"] : n => upper(n) }
}

resource "aws_eks_cluster" "negated" {
  name     = "c1"
  role_arn = "arn:aws:iam::111111111111:role/eks"
  vpc_config {
    subnet_ids              = ["subnet-1"]
    endpoint_public_access  = !var.public
    endpoint_private_access = var.public ? false : true
  }
}

resource "aws_eks_cluster" "literal_negation" {
  name     = "c2"
  role_arn = "arn:aws:iam::111111111111:role/eks"
  vpc_config {
    subnet_ids             = ["subnet-1"]
    endpoint_public_access = !false
  }
}

resource "google_sql_database_instance" "negated" {
  name = "db1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = !var.public
    }
  }
}

resource "aws_security_group" "exprs" {
  name = "exprs"
  ingress {
    from_port   = -var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = [for c in ["10.0.0.0/8"] : c]
  }
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = var.public ? ["0.0.0.0/0"] : ["10.0.0.0/8"]
  }
}

resource "aws_security_group_rule" "nulls" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-1"
  cidr_blocks       = ["10.0.0.0/8", null]
}

resource "google_compute_firewall" "nulls" {
  name          = "fw"
  network       = "default"
  source_ranges = [null, "10.0.0.0/8"]
  allow {
    protocol = "tcp"
    ports    = [for p in local.ports : tostring(p)]
  }
}

resource "google_storage_bucket_iam_binding" "nulls" {
  bucket  = "b"
  role    = "roles/storage.objectViewer"
  members = [null, "user:a@example.com"]
}

resource "google_storage_bucket_iam_member" "null_member" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = null
}

resource "aws_s3_bucket_public_access_block" "unknowns" {
  bucket                  = "b"
  block_public_acls       = !var.public
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "ternary" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = var.public ? true : false
  metadata_options {
    http_tokens = var.public ? "optional" : "required"
  }
}

resource "aws_ebs_volume" "negated" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = !var.public
}

resource "aws_iam_policy" "jsonencoded" {
  name   = "p"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}

resource "azurerm_storage_account" "unknowns" {
  name                            = "sa"
  resource_group_name             = "rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = !var.public
  https_traffic_only_enabled      = -1 > 0
}

resource "azurerm_network_security_rule" "ternary" {
  name                        = "r"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.public ? "*" : "10.0.0.0/8"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "aws_cloudtrail" "neg" {
  name                       = "t"
  s3_bucket_name             = "b"
  enable_log_file_validation = !var.public
  is_multi_region_trail      = !!true
}

resource "aws_kms_key" "neg" {
  enable_key_rotation = !var.public
}

resource "aws_db_instance" "neg" {
  identifier          = "db"
  instance_class      = "db.t3.micro"
  publicly_accessible = !var.public
  storage_encrypted   = var.public == false
}
