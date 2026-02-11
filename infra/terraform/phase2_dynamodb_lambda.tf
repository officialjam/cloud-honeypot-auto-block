# ----------------------------
# Phase 2 + SOC automation: Detection + Blocking pipeline
# CloudWatch Logs -> Subscription Filter -> Lambda -> DynamoDB (+ WAF IPSet)
# ----------------------------

resource "aws_dynamodb_table" "ip_reputation" {
  name         = "${var.project_name}-ip-reputation"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip"

  attribute {
    name = "ip"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-ip-reputation"
  }
}

# ----------------------------
# IAM role for decision engine Lambda
# ----------------------------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "decision_lambda" {
  name               = "${var.project_name}-decision-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "decision_lambda_basic" {
  role       = aws_iam_role.decision_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# DynamoDB + WAF permissions
data "aws_iam_policy_document" "decision_lambda_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:PutItem",
      "dynamodb:GetItem"
    ]
    resources = [aws_dynamodb_table.ip_reputation.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
    ]
    resources = [aws_wafv2_ip_set.blocklist.arn]
  }
}

resource "aws_iam_role_policy" "decision_lambda_permissions" {
  name   = "${var.project_name}-decision-permissions"
  role   = aws_iam_role.decision_lambda.id
  policy = data.aws_iam_policy_document.decision_lambda_permissions.json
}

# ----------------------------
# Package Lambda code as zip
# ----------------------------
data "archive_file" "decision_zip" {
  type        = "zip"
  source_dir  = "${path.module}/src/decision_engine"
  output_path = "${path.module}/.build/decision_engine.zip"
}

# ----------------------------
# Decision Engine Lambda
# ----------------------------
resource "aws_lambda_function" "decision_engine" {
  function_name = "${var.project_name}-decision-engine"
  role          = aws_iam_role.decision_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.decision_zip.output_path
  source_code_hash = data.archive_file.decision_zip.output_base64sha256

  environment {
    variables = {
      # Core scoring
      IP_TABLE_NAME   = aws_dynamodb_table.ip_reputation.name
      TTL_SECONDS     = "86400"
      SCORE_INCREMENT = "1"

      # WAF enforcement
      WAF_IPSET_ARN   = aws_wafv2_ip_set.blocklist.arn
      BLOCK_THRESHOLD = tostring(var.block_threshold)

      # SOC guardrails
      ALLOWLIST_IPS      = jsonencode(var.allowlist_ips)
      AUTO_BLOCK_ENABLED = tostring(var.auto_block_enabled)
      MAX_IPSET_SIZE     = tostring(var.max_ipset_size)
      MAX_WAF_RETRIES    = tostring(var.waf_update_max_retries)
    }
  }

  depends_on = [
    aws_iam_role_policy.decision_lambda_permissions
  ]
}

# ----------------------------
# Allow CloudWatch Logs to invoke the Lambda
# ----------------------------
resource "aws_lambda_permission" "allow_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.decision_engine.arn
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.honeypot.arn}:*"
}

# ----------------------------
# Subscription Filter: forward honeypot logs to decision engine
# ----------------------------
resource "aws_cloudwatch_log_subscription_filter" "honeypot_to_lambda" {
  name            = "${var.project_name}-honeypot-to-decision"
  log_group_name  = aws_cloudwatch_log_group.honeypot.name
  filter_pattern  = "" # forward everything; refine later
  destination_arn = aws_lambda_function.decision_engine.arn

  depends_on = [
    aws_lambda_permission.allow_logs
  ]
}
