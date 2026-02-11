# ----------------------------
# Phase 4: WAF-protected ALB demo endpoint
# Requires: aws_wafv2_web_acl.honeypot_acl (from phase3_waf.tf)
# ----------------------------

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "ALB security group"
  vpc_id      = aws_vpc.hp.id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-alb-sg" }
}

resource "aws_security_group" "demo_web" {
  name        = "${var.project_name}-demo-web-sg"
  description = "Demo web instance SG (only ALB can reach it)"
  vpc_id      = aws_vpc.hp.id

  ingress {
    description     = "HTTP from ALB only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-demo-web-sg" }
}

locals {
  demo_user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail
    dnf update -y
    dnf install -y nginx
    cat > /usr/share/nginx/html/index.html <<'HTML'
    <html>
      <head><title>WAF Demo</title></head>
      <body>
        <h1>WAF-protected endpoint is live</h1>
        <p>If your IP is in the WAF blocklist, you should get blocked.</p>
      </body>
    </html>
    HTML
    systemctl enable --now nginx
  EOF
}

resource "aws_instance" "demo_web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.demo_web.id]
  associate_public_ip_address = true

  key_name  = var.key_name != "" ? var.key_name : null
  user_data = local.demo_user_data

  tags = { Name = "${var.project_name}-demo-web" }
}

resource "aws_lb_target_group" "demo_tg" {
  name        = substr("${var.project_name}-demo-tg", 0, 32)
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.hp.id
  target_type = "instance"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 15
    matcher             = "200-399"
  }
}

resource "aws_lb_target_group_attachment" "demo_attach" {
  target_group_arn = aws_lb_target_group.demo_tg.arn
  target_id        = aws_instance.demo_web.id
  port             = 80
}

resource "aws_lb" "demo_alb" {
  name               = substr("${var.project_name}-demo-alb", 0, 32)
  load_balancer_type = "application"

  # ALB requires 2 subnets in 2 different AZs
  subnets         = [aws_subnet.public.id, aws_subnet.public_2.id]
  security_groups = [aws_security_group.alb.id]

  tags = { Name = "${var.project_name}-demo-alb" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.demo_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo_tg.arn
  }
}

resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.demo_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.honeypot_acl.arn
}

output "alb_dns_name" {
  value       = aws_lb.demo_alb.dns_name
  description = "WAF-protected ALB DNS name"
}