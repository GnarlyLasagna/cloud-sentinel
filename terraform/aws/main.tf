
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "vuln_sg" {
  name        = "cloudsentinel-vuln-sg"
  description = "Allow SSH from anywhere (intentional vulnerability)"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VULNERABLE
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "vuln_vm" {
  ami           = "ami-0c02fb55956c7d316" # Amazon Linux 2 (update if needed)
  instance_type = "t3.micro"

  vpc_security_group_ids = [aws_security_group.vuln_sg.id]

  tags = {
    Name = "CloudSentinel-Vulnerable-VM"
  }
}
