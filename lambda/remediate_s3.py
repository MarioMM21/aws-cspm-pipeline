import boto3
import json
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
ENVIRONMENT = os.environ['ENVIRONMENT']


def lambda_handler(event, context):
    """
    Auto-remediates S3 buckets with public access enabled.
    Triggered by AWS Config rule: s3-bucket-public-read-prohibited
    """
    logger.info(f"Event received: {json.dumps(event)}")
    
    remediated_buckets = []
    failed_buckets = []
    
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        
        logger.info(f"Scanning {len(buckets)} S3 buckets for public access...")
        
        for bucket in buckets:
            bucket_name = bucket['Name']
            
            try:
                try:
                    public_access = s3_client.get_public_access_block(
                        Bucket=bucket_name
                    )
                    config = public_access['PublicAccessBlockConfiguration']
                    
                    is_public = not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])
                    
                except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    is_public = True
                
                if is_public:
                    logger.info(f"Remediating public access on bucket: {bucket_name}")
                    
                    s3_client.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    
                    remediated_buckets.append(bucket_name)
                    logger.info(f"Successfully remediated: {bucket_name}")
                    
            except Exception as e:
                logger.error(f"Failed to remediate {bucket_name}: {str(e)}")
                failed_buckets.append({
                    'bucket': bucket_name,
                    'error': str(e)
                })
        
        summary = {
            'environment': ENVIRONMENT,
            'total_buckets_scanned': len(buckets),
            'buckets_remediated': len(remediated_buckets),
            'remediated_buckets': remediated_buckets,
            'failed_buckets': failed_buckets
        }
        
        logger.info(f"Remediation summary: {json.dumps(summary)}")
        
        if remediated_buckets:
            message = f"""
CSPM Auto-Remediation Alert - {ENVIRONMENT.upper()}

Action: S3 Public Access Block Applied
Buckets Remediated: {len(remediated_buckets)}

Remediated Buckets:
{chr(10).join(f'  - {b}' for b in remediated_buckets)}

CIS Control: 2.1.1 - S3 Bucket Public Read Prohibited
Severity: HIGH
Status: REMEDIATED

This was an automated remediation by the CSPM Pipeline.
"""
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f'[CSPM] S3 Public Access Auto-Remediated - {len(remediated_buckets)} bucket(s)',
                Message=message
            )
            
        return {
            'statusCode': 200,
            'body': json.dumps(summary)
        }
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }