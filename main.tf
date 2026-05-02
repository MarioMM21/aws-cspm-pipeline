# ============================================
# CSPM PIPELINE - AWS Security Automation
# Author: Mario Myles | github.com/MarioMM21
# ============================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================
# S3 BUCKET - CloudTrail Log Storage
# ============================================

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = var.s3_bucket_name
  force_destroy = true

  tags = {
    Name        = "CSPM CloudTrail Logs"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.s3_bucket_name}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.s3_bucket_name}/AWSLogs/${var.aws_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
# ============================================
# SNS TOPIC - Security Alert Notifications
# ============================================

resource "aws_sns_topic" "security_alerts" {
  name = "cspm-security-alerts"

  tags = {
    Name        = "CSPM Security Alerts"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.email_address
}

# ============================================
# CLOUDTRAIL - Audit Logging
# ============================================

resource "aws_cloudtrail" "main" {
  name                          = "cspm-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = {
    Name        = "CSPM CloudTrail"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# ============================================
# IAM ROLE - AWS Config
# ============================================

resource "aws_iam_role" "config_role" {
  name = "cspm-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "CSPM Config Role"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3_policy" {
  name = "cspm-config-s3-policy"
  role = aws_iam_role.config_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl"
        ]
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_name}",
          "arn:aws:s3:::${var.s3_bucket_name}/*"
        ]
      }
    ]
  })
}
# ============================================
# AWS CONFIG - Configuration Recorder
# ============================================

resource "aws_config_configuration_recorder" "main" {
  name     = "cspm-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "cspm-config-delivery"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ============================================
# AWS CONFIG RULES - CIS Benchmark Controls
# ============================================

resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name        = "s3-bucket-public-read-prohibited"
  description = "CIS 2.1.1 - Checks S3 buckets do not allow public read access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Environment = var.environment
    Project     = "cspm-pipeline"
    CIS_Control = "2.1.1"
  }
}

resource "aws_config_config_rule" "s3_public_write_prohibited" {
  name        = "s3-bucket-public-write-prohibited"
  description = "CIS 2.1.2 - Checks S3 buckets do not allow public write access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Environment = var.environment
    Project     = "cspm-pipeline"
    CIS_Control = "2.1.2"
  }
}

resource "aws_config_config_rule" "iam_root_access_key" {
  name        = "iam-root-access-key-check"
  description = "CIS 1.4 - Checks root account does not have active access keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Environment = var.environment
    Project     = "cspm-pipeline"
    CIS_Control = "1.4"
  }
}

resource "aws_config_config_rule" "mfa_enabled_for_iam_console" {
  name        = "mfa-enabled-for-iam-console-access"
  description = "CIS 1.10 - Checks MFA is enabled for all IAM users with console access"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Environment = var.environment
    Project     = "cspm-pipeline"
    CIS_Control = "1.10"
  }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "cloudtrail-enabled"
  description = "CIS 3.1 - Checks CloudTrail is enabled in all regions"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]

  tags = {
    Environment = var.environment
    Project     = "cspm-pipeline"
    CIS_Control = "3.1"
  }
}

# ============================================
# AWS SECURITY HUB
# ============================================

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
    delete = "10m"
  }
}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
    delete = "10m"
  }
}
# ============================================
# CLOUDWATCH - Security Event Alerting
# ============================================

resource "aws_cloudwatch_log_group" "security_events" {
  name              = "/cspm/security-events"
  retention_in_days = 90

  tags = {
    Name        = "CSPM Security Events"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_cloudwatch_metric_alarm" "config_compliance" {
  alarm_name          = "cspm-config-non-compliant"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "NonCompliantRules"
  namespace           = "AWS/Config"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Triggers when AWS Config detects non-compliant resources"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  ok_actions          = [aws_sns_topic.security_alerts.arn]

  tags = {
    Name        = "CSPM Config Compliance Alarm"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

# ============================================
# IAM ROLE - Lambda Auto-Remediation
# ============================================

resource "aws_iam_role" "lambda_role" {
  name = "cspm-lambda-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "CSPM Lambda Role"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "cspm-lambda-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceDetailsByResource",
          "config:DescribeConfigRules"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:UpdateFindings"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListMFADevices"
        ]
        Resource = "*"
      }
    ]
  })
}
# ============================================
# LAMBDA - Auto-Remediation Functions
# ============================================

data "archive_file" "remediate_s3" {
  type        = "zip"
  source_file = "${path.module}/lambda/remediate_s3.py"
  output_path = "${path.module}/lambda/remediate_s3.zip"
}

data "archive_file" "compliance_report" {
  type        = "zip"
  source_file = "${path.module}/lambda/compliance_report.py"
  output_path = "${path.module}/lambda/compliance_report.zip"
}

resource "aws_lambda_function" "remediate_s3" {
  filename         = data.archive_file.remediate_s3.output_path
  function_name    = "cspm-remediate-s3-public-access"
  role             = aws_iam_role.lambda_role.arn
  handler          = "remediate_s3.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.remediate_s3.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      ENVIRONMENT   = var.environment
    }
  }

  tags = {
    Name        = "CSPM S3 Auto-Remediation"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_lambda_function" "compliance_report" {
  filename         = data.archive_file.compliance_report.output_path
  function_name    = "cspm-compliance-report"
  role             = aws_iam_role.lambda_role.arn
  handler          = "compliance_report.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.compliance_report.output_base64sha256
  timeout          = 120

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      ENVIRONMENT   = var.environment
    }
  }

  tags = {
    Name        = "CSPM Compliance Report"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_lambda_permission" "allow_config_s3" {
  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3.function_name
  principal     = "config.amazonaws.com"
}

resource "aws_cloudwatch_event_rule" "daily_compliance" {
  name                = "cspm-daily-compliance-report"
  description         = "Triggers daily compliance report generation"
  schedule_expression = "cron(0 8 * * ? *)"

  tags = {
    Name        = "CSPM Daily Report Trigger"
    Environment = var.environment
    Project     = "cspm-pipeline"
  }
}

resource "aws_cloudwatch_event_target" "daily_compliance" {
  rule      = aws_cloudwatch_event_rule.daily_compliance.name
  target_id = "cspm-compliance-report"
  arn       = aws_lambda_function.compliance_report.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_report.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_compliance.arn
}