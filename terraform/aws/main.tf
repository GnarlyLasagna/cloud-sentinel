
provider "aws" {
  region = "us-east-1"
}

# Security Group (Vulnerable)
resource "aws_security_group" "vuln_sg" {
  name        = "cloudsentinel-vuln-sg"
  description = "Intentional vulnerabilities for CloudSentinel demo"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULNERABLE
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULNERABLE
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM Role (Over-Permissive)
resource "aws_iam_role" "cloudsentinel_role" {
  name = "cloudsentinel-overpermissive-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.cloudsentinel_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "cloudsentinel_profile" {
  name = "cloudsentinel-instance-profile"
  role = aws_iam_role.cloudsentinel_role.name
}

# Vulnerable EC2 Instance
resource "aws_instance" "vuln_vm" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.vuln_sg.id]

  iam_instance_profile = aws_iam_instance_profile.cloudsentinel_profile.name

  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "CloudSentinel-Vulnerable-VM"
  }
}

# Public S3 Bucket
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "cloudsentinel_public" {
  bucket = "cloudsentinel-public-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "allow_public" {
  bucket = aws_s3_bucket.cloudsentinel_public.id

  block_public_acls       = false
  # block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# resource "aws_s3_bucket_policy" "public_policy" {
#   bucket = aws_s3_bucket.cloudsentinel_public.id
#
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#        Principal = "*"
#        Action = [
#          "s3:GetObject"
#        ]
#        Resource = "${aws_s3_bucket.cloudsentinel_public.arn}/*"
#      }
#    ]
#  })
#}
