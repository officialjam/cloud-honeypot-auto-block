# ----------------------------
# Phase 3: WAFv2 IPSet (blocklist)
# ----------------------------

variable "waf_scope" {
  type        = string
  description = "WAF scope: REGIONAL (ALB/APIGW) or CLOUDFRONT (global)."
  default     = "REGIONAL"
}

variable "block_threshold" {
  type        = number
  description = "Score at/above which an IP gets added to the WAF IPSet."
  default     = 7
}

variable "allowlist_ips" {
  type        = list(string)
  description = "IPs/CIDRs that should never be blocked (e.g., your home/office IP)."
  default     = []
}

resource "aws_wafv2_ip_set" "blocklist" {
  name               = "${var.project_name}-blocklist"
  description        = "Auto-managed blocklist from honeypot detections"
  scope              = var.waf_scope
  ip_address_version = "IPV4"

  # Start empty. Lambda will add entries.
  addresses = []

  # Decision engine Lambda is the source of truth for live block entries.
  lifecycle {
    ignore_changes = [addresses]
  }

  tags = {
    Name = "${var.project_name}-blocklist"
  }
}

# Optional (recommended): WebACL that references the blocklist.
# You will attach this WebACL to an ALB or API Gateway later.
resource "aws_wafv2_web_acl" "honeypot_acl" {
  name        = "${var.project_name}-web-acl"
  description = "WebACL with blocklist rule - auto managed by honeypot"
  scope       = var.waf_scope

  default_action {
    allow {}
  }

  rule {
    name     = "BlocklistRule"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocklist.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-blocklist"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-webacl"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${var.project_name}-web-acl"
  }
}

output "waf_ipset_arn" {
  value       = aws_wafv2_ip_set.blocklist.arn
  description = "ARN of the WAF IPSet used for blocking"
}

output "waf_web_acl_arn" {
  value       = aws_wafv2_web_acl.honeypot_acl.arn
  description = "ARN of the WebACL (attach to ALB/APIGW/CloudFront depending on scope)"
}
