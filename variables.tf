variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "Your AWS Account ID"
  type        = string
}

variable "email_address" {
  description = "Email address for security alerts"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "cspm-lab"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  type        = string
  default     = "cspm-cloudtrail-logs"
}