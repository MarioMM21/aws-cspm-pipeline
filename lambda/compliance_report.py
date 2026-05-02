import boto3
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

config_client = boto3.client('config')
securityhub_client = boto3.client('securityhub')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']

CIS_RULES = {
    's3-bucket-public-read-prohibited': {
        'control': 'CIS 2.1.1',
        'description': 'S3 buckets should not allow public read access',
        'severity': 'HIGH'
    },
    's3-bucket-public-write-prohibited': {
        'control': 'CIS 2.1.2',
        'description': 'S3 buckets should not allow public write access',
        'severity': 'HIGH'
    },
    'iam-root-access-key-check': {
        'control': 'CIS 1.4',
        'description': 'Root account should not have active access keys',
        'severity': 'CRITICAL'
    },
    'mfa-enabled-for-iam-console-access': {
        'control': 'CIS 1.10',
        'description': 'MFA should be enabled for all IAM users',
        'severity': 'HIGH'
    },
    'cloudtrail-enabled': {
        'control': 'CIS 3.1',
        'description': 'CloudTrail should be enabled in all regions',
        'severity': 'CRITICAL'
    }
}


def get_config_compliance():
    """Get compliance status for all CSPM Config rules"""
    compliance_results = []

    for rule_name, rule_info in CIS_RULES.items():
        try:
            response = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT']
            )

            results = response.get('EvaluationResults', [])
            compliant = sum(1 for r in results
                          if r['ComplianceType'] == 'COMPLIANT')
            non_compliant = sum(1 for r in results
                              if r['ComplianceType'] == 'NON_COMPLIANT')

            compliance_results.append({
                'rule_name': rule_name,
                'control': rule_info['control'],
                'description': rule_info['description'],
                'severity': rule_info['severity'],
                'compliant_count': compliant,
                'non_compliant_count': non_compliant,
                'total_resources': compliant + non_compliant,
                'compliance_percentage': round(
                    (compliant / (compliant + non_compliant) * 100)
                    if (compliant + non_compliant) > 0 else 100, 2
                )
            })

        except Exception as e:
            logger.error(f"Error getting compliance for {rule_name}: {str(e)}")
            compliance_results.append({
                'rule_name': rule_name,
                'control': rule_info['control'],
                'description': rule_info['description'],
                'severity': rule_info['severity'],
                'error': str(e)
            })

    return compliance_results


def calculate_overall_score(compliance_results):
    """Calculate overall compliance score"""
    valid_results = [r for r in compliance_results if 'error' not in r]

    if not valid_results:
        return 0

    total_score = sum(r['compliance_percentage'] for r in valid_results)
    return round(total_score / len(valid_results), 2)


def format_report(compliance_results, overall_score):
    """Format compliance report for SNS notification"""
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    critical_failures = [
        r for r in compliance_results
        if r.get('non_compliant_count', 0) > 0
        and r.get('severity') == 'CRITICAL'
    ]

    high_failures = [
        r for r in compliance_results
        if r.get('non_compliant_count', 0) > 0
        and r.get('severity') == 'HIGH'
    ]

    report = f"""
╔══════════════════════════════════════════════════════════════╗
          CSPM COMPLIANCE REPORT - {ENVIRONMENT.upper()}
          Generated: {timestamp}
╚══════════════════════════════════════════════════════════════╝

OVERALL COMPLIANCE SCORE: {overall_score}%
{'✅ PASSING' if overall_score >= 80 else '⚠️  NEEDS ATTENTION' if overall_score >= 60 else '🚨 CRITICAL'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CIS BENCHMARK CONTROL RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

    for result in compliance_results:
        if 'error' in result:
            report += f"""
[{result['control']}] {result['description']}
  Status: ERROR - {result['error']}
  Severity: {result['severity']}
"""
        else:
            status = '✅ COMPLIANT' if result['non_compliant_count'] == 0 \
                else '🚨 NON-COMPLIANT'
            report += f"""
[{result['control']}] {result['description']}
  Status: {status}
  Severity: {result['severity']}
  Compliant Resources: {result['compliant_count']}
  Non-Compliant Resources: {result['non_compliant_count']}
  Compliance Rate: {result['compliance_percentage']}%
"""

    if critical_failures or high_failures:
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACTION REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Critical Issues: {len(critical_failures)}
High Issues: {len(high_failures)}

Immediate remediation required for critical findings.
Auto-remediation has been triggered where applicable.
"""

    report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generated by CSPM Pipeline | github.com/MarioMM21/aws-cspm-pipeline
Framework: CIS AWS Foundations Benchmark v1.4.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return report


def lambda_handler(event, context):
    """
    Generates and sends a CIS Benchmark compliance report
    Triggered daily by EventBridge at 8AM UTC
    """
    logger.info("Starting CSPM compliance report generation...")

    try:
        compliance_results = get_config_compliance()
        overall_score = calculate_overall_score(compliance_results)
        report = format_report(compliance_results, overall_score)

        logger.info(f"Compliance report generated. Overall score: {overall_score}%")

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[CSPM] Daily Compliance Report - Score: {overall_score}% - {ENVIRONMENT.upper()}',
            Message=report
        )

        logger.info("Compliance report sent via SNS")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'overall_score': overall_score,
                'rules_evaluated': len(compliance_results),
                'report_sent': True
            })
        }

    except Exception as e:
        logger.error(f"Failed to generate compliance report: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }