# ============================================
# OUTPUTS - Important Resource Information
# ============================================

output "s3_bucket_name" {
  description = "Name of the CloudTrail logs S3 bucket"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "s3_bucket_arn" {
  description = "ARN of the CloudTrail logs S3 bucket"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS security alerts topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "lambda_remediation_arn" {
  description = "ARN of the S3 auto-remediation Lambda function"
  value       = aws_lambda_function.remediate_s3.arn
}

output "lambda_report_arn" {
  description = "ARN of the compliance report Lambda function"
  value       = aws_lambda_function.compliance_report.arn
}

output "security_hub_id" {
  description = "Security Hub account ID"
  value       = aws_securityhub_account.main.id
}