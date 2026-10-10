# One failing block per canonical ID the native patcher handles. Used by the
# "every generated patch parses and references only declared symbols" test.
resource "aws_s3_bucket" "acl" {
  bucket = "acl-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket            = "acl-bucket"
  block_public_acls = false
}

resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0", "10.20.0.0/16"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_security_group_rule" "rule" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  security_group_id = "sg-1"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_ingress_rule" "v4" {
  security_group_id = "sg-1"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_instance" "imds" {
  ami                         = "ami-1"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 10
}

resource "aws_db_instance" "db" {
  identifier          = "db"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_cloudtrail" "trail" {
  name           = "trail"
  s3_bucket_name = "logs"
}

resource "aws_kms_key" "key" {
  description = "k"
}

resource "aws_eks_cluster" "eks" {
  name     = "eks"
  role_arn = "arn:aws:iam::111111111111:role/eks"
  vpc_config {
    subnet_ids = ["subnet-1"]
  }
}

resource "azurerm_storage_account" "sa" {
  name                            = "sa"
  resource_group_name             = "rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
}

resource "azurerm_network_security_rule" "nsg" {
  name                        = "ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "google_storage_bucket_iam_member" "member" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_iam_binding" "binding" {
  bucket  = "b"
  role    = "roles/storage.objectViewer"
  members = ["allUsers", "user:ops@example.com"]
}

resource "google_compute_firewall" "fw" {
  name          = "fw"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_sql_database_instance" "sql" {
  name = "sql"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
    }
  }
}
