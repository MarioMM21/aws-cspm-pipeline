# AWS Cloud Security Posture Management (CSPM) Pipeline

![AWS](https://img.shields.io/badge/AWS-Cloud%20Security-orange?style=for-the-badge&logo=amazon-aws)
![Terraform](https://img.shields.io/badge/Terraform-IaC-purple?style=for-the-badge&logo=terraform)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/CIS-Benchmark%20v1.4.0-red?style=for-the-badge)

## Overview

A production-grade, automated Cloud Security Posture Management pipeline built entirely on AWS using Infrastructure as Code. This project continuously monitors an AWS environment for security misconfigurations mapped to CIS AWS Foundations Benchmark controls, automatically remediates critical findings, and delivers daily compliance reports to security stakeholders.

This is not a lab exercise — it is a fully deployed, operational security pipeline running in a live AWS environment.

---

## Architecture
---

## What This Pipeline Does

### 🔍 Continuous Detection
- Deploys 5 AWS Config rules mapped directly to CIS AWS Foundations Benchmark v1.4.0 controls
- Integrates with AWS Security Hub to aggregate findings across CIS and AWS Foundational Security Best Practices standards
- Detected **18 real security findings** upon initial deployment including IAM privilege misconfigurations

### ⚡ Automated Remediation
- Lambda function automatically detects S3 buckets with public access enabled
- Applies Block Public Access configuration without human intervention
- Sends real-time SNS notification documenting every remediation action taken

### 📊 Daily Compliance Reporting
- EventBridge triggers compliance report Lambda every day at 8AM UTC
- Report calculates overall CIS Benchmark compliance score across all monitored controls
- Classifies findings by severity (Critical, High, Medium, Low)
- Delivers formatted report via SNS email to security stakeholders

### 🔒 Audit Logging
- CloudTrail captures every API call across all regions
- Logs stored in AES-256 encrypted S3 bucket with versioning enabled
- Full audit trail maintained for compliance and forensic purposes

---

## CIS Benchmark Controls Implemented

| Control | Rule | Severity |
|---|---|---|
| CIS 1.4 | Root account should not have active access keys | CRITICAL |
| CIS 1.10 | MFA should be enabled for all IAM users | HIGH |
| CIS 2.1.1 | S3 buckets should not allow public read access | HIGH |
| CIS 2.1.2 | S3 buckets should not allow public write access | HIGH |
| CIS 3.1 | CloudTrail should be enabled in all regions | CRITICAL |

---

## Tech Stack

| Category | Technology |
|---|---|
| Cloud Platform | AWS (us-east-1) |
| Infrastructure as Code | Terraform v5.x |
| Scripting / Automation | Python 3.11 (boto3) |
| Threat Detection | AWS GuardDuty, AWS Config |
| Security Aggregation | AWS Security Hub |
| Audit Logging | AWS CloudTrail |
| Auto-Remediation | AWS Lambda |
| Alerting | AWS SNS |
| Scheduling | Amazon EventBridge |
| Monitoring | Amazon CloudWatch |
| Log Storage | Amazon S3 (AES-256 encrypted) |
| Access Control | AWS IAM (least privilege) |

---

## Project Structure
---

## Deployment

### Prerequisites
- AWS account with appropriate IAM permissions
- Terraform installed (v1.0+)
- Python 3.11+
- AWS CLI configured (`aws configure`)

### Deploy

```bash
# Clone the repository
git clone https://github.com/MarioMM21/aws-cspm-pipeline.git
cd aws-cspm-pipeline

# Create your tfvars file
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# Initialize Terraform
terraform init

# Preview infrastructure
terraform plan

# Deploy
terraform apply
```

### Destroy

```bash
terraform destroy
```

---

## Live Results

Upon deployment this pipeline immediately detected real security findings in the AWS environment:

- **43 non-compliant Config rules** identified across the account
- **18 Security Hub findings** detected including IAM privilege misconfigurations
- **S3 auto-remediation** triggered and confirmed compliant
- **CloudTrail** actively logging all API calls to encrypted S3 bucket
- **Security Hub** running CIS Benchmark v1.4.0 and AWS Foundational Security Best Practices standards simultaneously

---

## Screenshots

| Screenshot | Description |
|---|---|
| AWS Config Dashboard | 43 non-compliant rules detected on first scan |
| Config Rules | All 5 CIS Benchmark rules deployed and evaluating |
| Security Hub Findings | 18 real findings detected including IAM misconfigurations |
| Lambda Functions | Both auto-remediation and reporting functions deployed |
| CloudTrail | Multi-region audit logging active |
| S3 Bucket | Encrypted log storage with public access blocked |
| Terraform Apply | Full deployment output showing 32 resources created |

---

## Key Skills Demonstrated

- **Cloud Security Architecture** — Designed and deployed a multi-service AWS security pipeline from scratch
- **Infrastructure as Code** — Entire environment provisioned via Terraform — repeatable, version-controlled, production-ready
- **Python Automation** — Built Lambda functions using boto3 for auto-remediation and compliance reporting
- **CIS Benchmark Implementation** — Mapped detection rules directly to CIS AWS Foundations Benchmark v1.4.0
- **CSPM** — Implemented continuous cloud security posture management without commercial tooling
- **IAM Least Privilege** — All roles and policies scoped to minimum required permissions
- **Incident Response Automation** — Detection to remediation to notification in seconds with zero human intervention

---

## Author

**Mario Myles**
Cybersecurity Engineer | Cloud Security | AWS | Terraform | Python

- GitHub: [github.com/MarioMM21](https://github.com/MarioMM21)
- LinkedIn: [linkedin.com/in/mario-myles](https://linkedin.com/in/mario-myles)

---

*Built and deployed May 2026*