# ----------------------------
# VPC Interface Endpoints for SSM + CloudWatch Logs
# ----------------------------

data "aws_region" "current" {}

resource "aws_security_group" "vpce" {
  name        = "${var.project_name}-vpce-sg"
  description = "Security group for VPC interface endpoints"
  vpc_id      = aws_vpc.hp.id

  ingress {
    description = "HTTPS from inside VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.hp.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-vpce-sg" }
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.hp.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = [aws_subnet.public.id, aws_subnet.public_2.id]
  security_group_ids = [aws_security_group.vpce.id]

  tags = { Name = "${var.project_name}-vpce-ssm" }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.hp.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = [aws_subnet.public.id, aws_subnet.public_2.id]
  security_group_ids = [aws_security_group.vpce.id]

  tags = { Name = "${var.project_name}-vpce-ssmmessages" }
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.hp.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2messages"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = [aws_subnet.public.id, aws_subnet.public_2.id]
  security_group_ids = [aws_security_group.vpce.id]

  tags = { Name = "${var.project_name}-vpce-ec2messages" }
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.hp.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.logs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids         = [aws_subnet.public.id, aws_subnet.public_2.id]
  security_group_ids = [aws_security_group.vpce.id]

  tags = { Name = "${var.project_name}-vpce-logs" }
}