# Defect 7 fixture: the old suffix match wrote an EC2 fix into aws_kms_key.logs.
resource "aws_kms_key" "logs" {
  description         = "log encryption key"
  enable_key_rotation = true
}

resource "aws_instance" "web" {
  ami           = "ami-0web"
  instance_type = "t3.micro"
  tags = {
    Name      = "web"
    yor_trace = "trace-web"
  }
}

resource "aws_instance" "worker" {
  ami           = "ami-0worker"
  instance_type = "t3.micro"
  tags = {
    Name      = "worker"
    yor_trace = "trace-worker"
  }
}

resource "aws_instance" "batch_a" {
  ami           = "ami-0batch"
  instance_type = "t3.micro"
  tags          = { yor_trace = "trace-dup" }
}

resource "aws_instance" "batch_b" {
  ami           = "ami-0batch"
  instance_type = "t3.micro"
  tags          = { yor_trace = "trace-dup" }
}
