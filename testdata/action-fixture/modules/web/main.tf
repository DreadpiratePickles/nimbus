variable "ssh_cidr" {
  type = string
}

resource "aws_security_group" "ssh" {
  name        = "fixture-ssh"
  description = "SSH for the fixture host"
  vpc_id      = "vpc-0fixture00000001"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }
}

resource "aws_iam_role" "host" {
  name = "fixture-host-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "host" {
  name = "fixture-host-profile"
  role = aws_iam_role.host.name
}

resource "aws_instance" "host" {
  ami                    = "ami-0fixture000000001"
  instance_type          = "t3.micro"
  subnet_id              = "subnet-0fixture000001"
  vpc_security_group_ids = [aws_security_group.ssh.id]
  iam_instance_profile   = aws_iam_instance_profile.host.name

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "fixture-host"
  }
}
