# =====================================
# CloudSentinel AWS Vulnerable Infrastructure
# Stable + Free Tier Friendly
# =====================================

provider "aws" {
  region = "us-east-1"
}

# RANDOM SUFFIX
resource "random_id" "suffix" {
  byte_length = 4
}

# SECURITY GROUPS

# Basic vulnerable SG (SSH + HTTP open)
resource "aws_security_group" "sg_basic" {
  name        = "cloudsentinel-sg-basic"
  description = "Basic vulnerable SG"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SSH open
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HTTP open
  }
}

# Extra vulnerable ports (RDP + MySQL)
resource "aws_security_group" "sg_extra" {
  name        = "cloudsentinel-sg-extra"
  description = "Extra vulnerable ports"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # RDP open
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # MySQL open
  }
}

# CRITICAL: Allow ALL traffic
resource "aws_security_group" "sg_all_open" {
  name        = "cloudsentinel-sg-all-open"
  description = "All ports open (critical vulnerability)"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # EVERYTHING open
  }
}

# EC2 INSTANCE
resource "aws_instance" "vuln_ec2" {
  ami           = "ami-0c02fb55956c7d316" # Debian 11
  instance_type = "t3.micro"              # Free Tier eligible

  vpc_security_group_ids = [
    aws_security_group.sg_basic.id,
    aws_security_group.sg_extra.id,
    aws_security_group.sg_all_open.id
  ]

  tags = {
    Name    = "cloudsentinel-vm"
    Project = "CloudSentinel"
  }
}

# S3 BUCKETS (VULNERABLE)

# No encryption, no versioning
resource "aws_s3_bucket" "vuln_bucket" {
  bucket = "cloudsentinel-vuln-${random_id.suffix.hex}"
}

# Second bucket (also vulnerable)
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "cloudsentinel-unencrypted-${random_id.suffix.hex}"
}

# IAM (OVERLY PERMISSIVE)

resource "aws_iam_role" "over_permissive_role" {
  name = "cloudsentinel-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "over_permissive_policy" {
  name = "cloudsentinel-policy"
  role = aws_iam_role.over_permissive_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action   = "*",
      Effect   = "Allow",
      Resource = "*"
    }]
  })
}

# EBS VOLUME (UNENCRYPTED + UNATTACHED)
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 8
  type              = "gp2"
  encrypted         = false

  tags = {
    Name = "cloudsentinel-unencrypted-ebs"
  }
}

# RDS INSTANCE (PUBLIC + UNENCRYPTED)
resource "aws_db_instance" "vuln_rds" {
  identifier           = "cloudsentineldb"
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"

  username             = "admin"
  password             = "Password123!"

  publicly_accessible  = true     # vulnerable
  storage_encrypted    = false    # vulnerable
  skip_final_snapshot  = true
}
