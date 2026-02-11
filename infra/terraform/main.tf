data "aws_availability_zones" "available" {}

# ----------------------------
# VPC
# ----------------------------
resource "aws_vpc" "hp" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "hp" {
  vpc_id = aws_vpc.hp.id
  tags   = { Name = "${var.project_name}-igw" }
}

# ----------------------------
# Public Subnets (2 AZs)
# ----------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.hp.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.project_name}-public-1" }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.hp.id
  cidr_block              = "10.50.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.project_name}-public-2" }
}

# ----------------------------
# Routing
# ----------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.hp.id
  tags   = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.hp.id
}

resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_2_assoc" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# ----------------------------
# CloudWatch Log Group
# ----------------------------
resource "aws_cloudwatch_log_group" "honeypot" {
  name              = local.honeypot_log_group_name
  retention_in_days = var.honeypot_log_group_retention_days
}

# ----------------------------
# IAM Role + Instance Profile
# ----------------------------
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.project_name}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Name = "${var.project_name}-instance-role" }
}

resource "aws_iam_role_policy" "cw_logs" {
  name = "${var.project_name}-cw-logs"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteHoneypotLogGroup"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:PutRetentionPolicy"
        ]
        Resource = [
          aws_cloudwatch_log_group.honeypot.arn,
          "${aws_cloudwatch_log_group.honeypot.arn}:*"
        ]
      },
      {
        Sid      = "DescribeLogGroups"
        Effect   = "Allow"
        Action   = ["logs:DescribeLogGroups"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "instance_cwagent" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.instance.name
}

# ----------------------------
# Security Group (honeypot EC2)
# ----------------------------
resource "aws_security_group" "honeypot" {
  name        = "${var.project_name}-honeypot-sg"
  description = "Honeypot security group"
  vpc_id      = aws_vpc.hp.id

  ingress {
    description = "Honeypot exposure (can tighten later)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-honeypot-sg" }
}

# ----------------------------
# AMI (Amazon Linux 2023)
# ----------------------------
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# ----------------------------
# User Data (SSM + CloudWatch Agent proof logging)
# ----------------------------
locals {
  honeypot_log_group_name = "/${var.project_name}/honeypot"

  user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail

    # log bootstrap output to a file we will ship to CloudWatch
    exec > >(tee /var/log/cloud-init-output.log) 2>&1

    dnf update -y

    # Ensure SSM is enabled/running
    systemctl enable amazon-ssm-agent || true
    systemctl restart amazon-ssm-agent || true
    systemctl status amazon-ssm-agent --no-pager || true

    # Ensure auth logs are written to files we can ship to CloudWatch.
    dnf install -y rsyslog amazon-cloudwatch-agent || yum install -y rsyslog amazon-cloudwatch-agent
    systemctl enable rsyslog || true
    systemctl restart rsyslog || true

    # Write CW Agent config (ship bootstrap log first — guaranteed file)
    mkdir -p /opt/aws/amazon-cloudwatch-agent/etc

    cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<CFG
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/cloud-init-output.log",
                "log_group_name": "${local.honeypot_log_group_name}",
                "log_stream_name": "{instance_id}-bootstrap",
                "timezone": "UTC"
              },
              {
                "file_path": "/var/log/secure",
                "log_group_name": "${local.honeypot_log_group_name}",
                "log_stream_name": "{instance_id}-secure",
                "timezone": "UTC"
              }
            ]
          }
        }
      }
    }
    CFG

    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 \
      -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status || true
    systemctl status amazon-cloudwatch-agent --no-pager || true
  EOF
}

# ----------------------------
# EC2 Honeypot Instance
# ----------------------------
resource "aws_instance" "honeypot" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.honeypot.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = true
  user_data                   = local.user_data

  # IMPORTANT: ensure IAM + endpoints exist before instance boot
  depends_on = [
    aws_iam_role_policy.cw_logs,
    aws_iam_role_policy_attachment.instance_cwagent,
    aws_iam_role_policy_attachment.instance_ssm,
    aws_vpc_endpoint.ssm,
    aws_vpc_endpoint.ssmmessages,
    aws_vpc_endpoint.ec2messages,
    aws_vpc_endpoint.logs
  ]

  tags = { Name = "${var.project_name}-honeypot" }
}
