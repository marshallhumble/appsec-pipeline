# AWS Security Patterns

Load when the question involves AWS infrastructure, services, IAM, secrets, or deployment.
Load alongside `references/lang/<lang>.md` for SDK usage in a specific language.

---

## IAM — Least Privilege

**Core rules:**
- Every service, Lambda, ECS task, and EC2 instance gets its own IAM role
- No wildcard `*` on actions or resources in production policies
- No `AdministratorAccess` attached to application roles
- No long-lived access keys in code, config files, environment variables, or container images
  — use instance profiles, ECS task roles, Lambda execution roles, or IRSA (EKS)
- Separate roles per environment; never share prod credentials with dev/staging

```json
// NEVER — overly broad policy
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}

// ALWAYS — specific actions on specific resources
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue"
  ],
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/*"
}
```

### Auditing IAM
```bash
# Find roles with admin or wildcard policies
aws iam list-roles --query 'Roles[*].RoleName' --output text \
    | xargs -I{} aws iam list-attached-role-policies --role-name {}

# IAM Access Analyzer — finds overly permissive policies and external access
aws accessanalyzer list-findings --analyzer-arn <arn>
```

---

## Secrets Manager

```bash
# Store a secret
aws secretsmanager create-secret \
    --name "prod/db/password" \
    --secret-string '{"password":"...","username":"app_user"}'

# Retrieve in scripts
SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "prod/db/password" \
    --query SecretString --output text)

# Rotate automatically — attach a Lambda rotation function
aws secretsmanager rotate-secret \
    --secret-id "prod/db/password" \
    --rotation-lambda-arn arn:aws:lambda:...
```

**SSM Parameter Store** for non-secret config and feature flags:
```bash
# Store (SecureString uses KMS encryption)
aws ssm put-parameter \
    --name "/prod/app/db-host" \
    --value "db.prod.internal" \
    --type SecureString

# Retrieve
DB_HOST=$(aws ssm get-parameter \
    --name "/prod/app/db-host" \
    --with-decryption \
    --query Parameter.Value --output text)
```

---

## S3 Security

```bash
# ALWAYS — block all public access at the account level
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# ALWAYS — enable server-side encryption by default
aws s3api put-bucket-encryption \
    --bucket my-bucket \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'

# ALWAYS — enable versioning for buckets with important data
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled

# ALWAYS — enforce TLS via bucket policy
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
  "Condition": {"Bool": {"aws:SecureTransport": "false"}}
}
```

---

## Lambda Security

```bash
# ALWAYS — grant only required permissions in the execution role
# NEVER attach AWSLambdaFullAccess or AdministratorAccess to a Lambda role

# Environment variables for non-secret config only
# Secrets: use Secrets Manager and fetch at cold start, cache in memory

# ALWAYS — set a timeout (never leave at default 3s without review)
aws lambda update-function-configuration \
    --function-name my-function \
    --timeout 30 \
    --memory-size 256

# ALWAYS — enable X-Ray tracing for observability
aws lambda update-function-configuration \
    --function-name my-function \
    --tracing-config Mode=Active

# Reserve concurrency to prevent noisy-neighbor DoS
aws lambda put-function-concurrency \
    --function-name my-function \
    --reserved-concurrent-executions 100
```

**Deployment from CI:**
```bash
# NEVER include AWS credentials in the deployment artifact or image
# ALWAYS use OIDC-based role assumption from GitHub Actions / CodeBuild

# GitHub Actions: use aws-actions/configure-aws-credentials with role-to-assume
# CodeBuild: IAM service role attached to the project provides credentials automatically
```

---

## VPC / Network Security

- **Security groups:** default-deny; open only required ports to specific CIDRs or
  security group IDs — never `0.0.0.0/0` for management ports (SSH, RDP, DB ports)
- **NACLs:** use as a secondary layer for subnet-level controls
- **Private subnets:** databases, internal services, and Lambda functions that don't
  need internet access should be in private subnets
- **VPC endpoints:** use Gateway endpoints for S3/DynamoDB and Interface endpoints
  for other services to keep traffic off the public internet
- **Flow logs:** enable VPC flow logs to CloudWatch or S3 for incident investigation

---

## CloudTrail & Monitoring

```bash
# ALWAYS — enable CloudTrail in all regions (multi-region trail)
aws cloudtrail create-trail \
    --name org-trail \
    --s3-bucket-name audit-logs \
    --is-multi-region-trail \
    --enable-log-file-validation

# ALWAYS — alert on root account usage
# CloudWatch Events rule: eventSource=signin.amazonaws.com, userType=Root

# Key events to alert on:
# - ConsoleLogin with MFA=No
# - CreateUser, AttachUserPolicy, CreateAccessKey
# - DeleteTrail, StopLogging, PutBucketPolicy (public)
# - Unauthorized API calls (errorCode: AccessDenied)
```

---

## ECS / Container Security

```bash
# ALWAYS — use task roles, not instance profiles, for container permissions
# ALWAYS — run containers as non-root user (set user in Dockerfile)
# ALWAYS — use read-only root filesystem where possible
# ALWAYS — set CPU and memory limits to prevent resource exhaustion

# Secrets in ECS: inject via Secrets Manager reference in task definition
{
  "secrets": [
    {
      "name": "DB_PASSWORD",
      "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password"
    }
  ]
}
# Value is injected as environment variable; never stored in image or task definition plaintext
```

---

## KMS — Encryption Key Management

```bash
# Create a CMK with key rotation enabled
aws kms create-key --description "prod-data-encryption"
aws kms enable-key-rotation --key-id <key-id>

# ALWAYS enable automatic annual rotation on CMKs
# ALWAYS use separate CMKs per service/environment
# NEVER use AWS-managed keys (aws/s3, aws/rds) for data you need to control access to
```

---

## AWS Security Checklist

- [ ] No root account used for day-to-day operations; MFA enabled on root
- [ ] IAM roles used everywhere; no long-lived access keys in code or CI
- [ ] All production policies follow least privilege; no `*:*`
- [ ] CloudTrail enabled multi-region; logs integrity validation on
- [ ] S3 buckets: public access blocked, encryption enabled, versioning on important data
- [ ] RDS: not publicly accessible; encrypted at rest; in private subnet
- [ ] Security groups: no 0.0.0.0/0 on management or database ports
- [ ] Secrets in Secrets Manager; never in environment variables for production secrets
- [ ] GuardDuty enabled for threat detection
- [ ] AWS Config enabled for compliance drift detection
