# AWS Pentest MCP Server - Usage Guide

**Version:** 1.0.0 | **Total Tools:** 27

## Quick Start

Get comprehensive help with all 27 tools:
```bash
#mcp_aws-pentest_help
```

For TRA (Threat & Risk Assessment) reporting:
```bash
#mcp_aws-pentest_generate_tra_report region: us-east-1
```

## Installation

```powershell
# Clone or download the repository
cd aws-pentest

# Install dependencies
npm install

# Build the server
npm run build
```

## MCP Configuration

Add to your MCP settings file:

**Windows:** `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

```json
{
  "mcpServers": {
    "aws-pentest": {
      "command": "node",
      "args": ["C:\\path\\to\\aws-pentest\\dist\\index.js"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

**After configuration:** Restart VS Code

## Authentication

```powershell
# Authenticate with AWS CLI (most common method)
aws configure

# Verify authentication
aws sts get-caller-identity
```

**AWS Authentication Methods:**
1. **AWS CLI credentials** (`~/.aws/credentials`)
2. **Environment variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. **IAM instance profile** (when running on EC2)
4. **IAM roles** (for AWS services)

**Required AWS Permissions:**
- **ReadOnlyAccess** policy (minimum)
- **SecurityAudit** policy (recommended)
- Individual service `Describe*` and `List*` permissions

**After Installation:** Restart VS Code to load the MCP server

## Professional Pentesting Workflow

### Phase 1: Reconnaissance
```bash
#mcp_aws-pentest_whoami
#mcp_aws-pentest_enumerate_public_resources region: us-east-1
#mcp_aws-pentest_enumerate_ec2_instances region: us-east-1
```

### Phase 2: Enumeration
```bash
#mcp_aws-pentest_enumerate_s3_buckets
#mcp_aws-pentest_enumerate_iam_users
#mcp_aws-pentest_enumerate_iam_roles
#mcp_aws-pentest_enumerate_rds_databases region: us-east-1
```

### Phase 3: Security Scanning
```bash
#mcp_aws-pentest_analyze_security_groups region: us-east-1
#mcp_aws-pentest_check_iam_policies
#mcp_aws-pentest_scan_s3_bucket_security bucketName: my-bucket
#mcp_aws-pentest_scan_secrets_manager region: us-east-1
#mcp_aws-pentest_scan_dynamodb_security region: us-east-1
#mcp_aws-pentest_scan_api_gateway_security region: us-east-1
#mcp_aws-pentest_scan_cloudfront_security
#mcp_aws-pentest_scan_elasticache_security region: us-east-1
#mcp_aws-pentest_get_guardduty_findings region: us-east-1
#mcp_aws-pentest_scan_sns_security region: us-east-1
#mcp_aws-pentest_scan_sqs_security region: us-east-1
#mcp_aws-pentest_scan_cognito_security region: us-east-1
```

### Phase 4: Attack Path Analysis
```bash
#mcp_aws-pentest_analyze_attack_paths region: us-east-1
```

### Phase 5: Generate Report
```bash
# Standard security report
#mcp_aws-pentest_generate_security_report region: us-east-1 format: pdf outputFile: C:\reports\aws-security.pdf

# TRA report (NEW - recommended for compliance audits)
#mcp_aws-pentest_generate_tra_report region: us-east-1 format: pdf outputFile: C:\reports\TRA-Report.pdf
```

## TRA (Threat & Risk Assessment) Workflow ⭐ NEW

### Quick TRA Report
```bash
#mcp_aws-pentest_generate_tra_report region: us-east-1
```

### Compliance-Specific Reports
```bash
# CIS AWS Foundations Benchmark
#mcp_aws-pentest_generate_tra_report region: us-east-1 framework: cis format: pdf outputFile: C:\reports\CIS-Audit.pdf

# NIST 800-53
#mcp_aws-pentest_generate_tra_report region: us-east-1 framework: nist format: pdf outputFile: C:\reports\NIST-Audit.pdf

# PCI-DSS
#mcp_aws-pentest_generate_tra_report region: us-east-1 framework: pci format: pdf outputFile: C:\reports\PCI-Audit.pdf

# All frameworks
#mcp_aws-pentest_generate_tra_report region: us-east-1 framework: all format: html outputFile: C:\reports\TRA-Full.html
```

**What TRA Report Includes:**
- Risk scoring (0-10 scale)
- Compliance framework mapping (CIS/NIST/PCI/HIPAA)
- MITRE ATT&CK Cloud Matrix
- Top 10 critical findings
- 4-phase remediation roadmap
- Executive summary

**See [TRA_TOOL.md](TRA_TOOL.md) for complete guide**

## Common Security Findings

### EC2 Instances
- Public IP addresses exposed to Internet
- IAM instance profiles with excessive permissions
- Security Groups allowing 0.0.0.0/0 access

### Security Groups
- Open management ports (SSH 22, RDP 3389)
- Database ports exposed (MySQL 3306, PostgreSQL 5432, MongoDB 27017)
- Wildcard rules allowing all traffic

### S3 Buckets
- Public access not blocked
- Server-side encryption not enabled
- Missing bucket policies

### IAM
- Wildcard permissions (`Action: "*"`, `Resource: "*"`)
- IAM users with old access keys (90+ days)
- Privilege escalation paths (IAM modify permissions)

### RDS Databases
- Publicly accessible databases
- Encryption at rest not enabled
- Insufficient backup retention

### Lambda Functions
- Deprecated runtimes (python2, node10, node12)
- Secrets in environment variables
- Overly permissive IAM roles

### DynamoDB
- Encryption at rest not enabled
- Point-in-time recovery disabled
- No continuous backups

### API Gateway
- Access logging not enabled (no audit trail)
- Throttling not configured (DDoS risk)
- Client certificates not configured

### CloudFront
- Weak TLS versions (SSLv3, TLSv1.0/1.1)
- HTTPS not enforced (allows HTTP)
- No Origin Access Identity for S3
- WAF not enabled

### ElastiCache
- Encryption in transit not enabled
- Encryption at rest not enabled
- Auth tokens not enabled (Redis)

### GuardDuty
- Active threat findings (backdoors, unauthorized access)
- Cryptocurrency mining detected
- Port scanning detected

### SNS Topics
- Server-side encryption not enabled (messages in plaintext)
- Topic policy allows public access (Principal: *)
- Wildcard actions in topic policy
- HTTP subscriptions (should use HTTPS)
- Cross-account access configured

### SQS Queues
- Server-side encryption not enabled (messages in plaintext)
- Queue policy allows public access (Principal: *)
- Dead letter queue not configured (message loss risk)
- Long message retention periods

### Cognito
- Identity pools allow unauthenticated access (anonymous IAM role assumption)
- User pools have MFA disabled or optional
- Weak password policies (min length < 8, no complexity)
- Classic flow enabled (deprecated)
- Email verification not enabled

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Authentication failed** | Run `aws configure` and verify with `aws sts get-caller-identity` |
| **Access denied** | Check IAM permissions - need at least `ReadOnlyAccess` |
| **Region not found** | Use valid AWS region codes (us-east-1, eu-west-1, etc.) |
| **Tool not recognized** | Restart VS Code to reload MCP server |
| **Empty results** | Verify AWS credentials have access to the account/region |

## AWS Regions

Common AWS regions:
- **us-east-1** - US East (N. Virginia)
- **us-west-2** - US West (Oregon)
- **eu-west-1** - Europe (Ireland)
- **ap-southeast-1** - Asia Pacific (Singapore)
- **ap-northeast-1** - Asia Pacific (Tokyo)

Use `aws ec2 describe-regions` to list all available regions

## Tool Categories (26 Total)

**Enumeration (10 tools):** whoami, enumerate_ec2_instances, enumerate_s3_buckets, enumerate_iam_users, enumerate_iam_roles, enumerate_rds_databases, enumerate_vpcs, enumerate_lambda_functions, enumerate_eks_clusters, enumerate_public_resources

**Security Scanning (13 tools):** scan_s3_bucket_security, analyze_security_groups, check_iam_policies, check_kms_keys, scan_secrets_manager, scan_dynamodb_security, scan_api_gateway_security, scan_cloudfront_security, scan_elasticache_security, get_guardduty_findings, scan_sns_security, scan_sqs_security, scan_cognito_security

**Attack Analysis (2 tools):** analyze_attack_paths, generate_security_report

**Reporting (1 tool):** generate_security_report (supports markdown, PDF, HTML, CSV)

## New Services

**Phase 3:**  
**DynamoDB:** Encryption, point-in-time recovery, backups  
**API Gateway:** Authorization, throttling, logging, SSL  
**CloudFront:** TLS versions, HTTPS enforcement, WAF, origin access  
**ElastiCache:** Encryption (transit/rest), auth tokens, Redis/Memcached  
**GuardDuty:** AWS threat detection findings with severity ratings  

**Phase 4 (Messaging & Identity):**  
**SNS:** Topic encryption (KMS), access policies, subscriptions, cross-account  
**SQS:** Queue encryption (KMS), access policies, dead letter queues, retention  
**Cognito:** Identity pools (unauthenticated access), user pools (MFA, password policies)  

📚 **Complete documentation:** [README.md](README.md)  
🔍 **New services:** [NEW_SERVICES.md](NEW_SERVICES.md)  
🔍 **Report examples:** See generate_security_report output

---
**Version:** 1.0.0 | **Total Tools:** 26 | **Last Updated:** December 2025
