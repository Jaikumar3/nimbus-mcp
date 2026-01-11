# Changelog

All notable changes to the AWS Penetration Testing MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-01-11

### Added

#### Multi-Region Scanning (2 new tools)
- **scan_all_regions** - Scan ALL AWS regions for resources in parallel
  - Supports: EC2, Lambda, RDS, EKS, Secrets Manager, GuardDuty, ElastiCache, VPC
  - Two modes: 'common' (11 popular regions) or 'all' (30+ regions)
  - Configurable parallelism (1-10 concurrent scans)
  - Aggregated findings with critical issues highlighted
  - Security analysis per region with risk ratings

- **list_active_regions** - Quick discovery of regions with resources
  - Fast parallel scan to identify active regions
  - Shows EC2, Lambda, RDS counts per region
  - Helps prioritize which regions to deep-scan

#### Infrastructure
- Added AWS_REGIONS constant with all 30+ AWS regions
- Added COMMON_REGIONS for faster scanning (covers 90%+ of deployments)
- Parallel execution helper with configurable concurrency
- Region-specific scanner functions for each resource type

### Changed
- Total tools: **43** (up from 41)
- Improved attack surface discovery across global deployments
- Better visibility into multi-region security posture

---

## [1.2.0] - 2026-01-09

### Added

#### New Automated MCP Tools (2 new)
- **scan_eks_service_accounts** - Automated EKS service account security analysis
  - Checks IRSA/OIDC provider configuration
  - Validates secrets encryption (etcd)
  - Analyzes API server endpoint exposure
  - Verifies control plane logging
  - Provides kubectl commands for deeper SA analysis
  - Risk scoring and MITRE ATT&CK mappings

- **hunt_eks_secrets** - Comprehensive EKS secret hunting guide
  - K8s secrets enumeration commands
  - AWS Secrets Manager/SSM Parameter Store hunting
  - IMDS credential theft techniques
  - ConfigMap secret discovery
  - Mounted secret file extraction
  - Service account token theft
  - ECR pull secret extraction

### Changed
- Total tools: **41** (up from 39)
- All Kubernetes security tools now automated via MCP
- Added exploitation payloads for offensive testing

---

## [1.1.0] - 2026-01-08

### Added

#### New Security Tools (7 tools)
- **`analyze_cloudwatch_security`** - Analyze CloudWatch configuration for security monitoring gaps: missing alarms, log groups without encryption, insufficient retention, missing metric filters for security events
- **`analyze_iam_privilege_escalation`** - Deep analysis of IAM privilege escalation paths: iam:PassRole abuse, sts:AssumeRole chains, policy attachment permissions, service-linked role exploitation
- **`scan_ssm_security`** - Analyze AWS Systems Manager security: SSM documents with embedded credentials, parameter store secrets, Session Manager logging, patch compliance
- **`analyze_ec2_metadata_exposure`** - Check EC2 instances for IMDSv1 exposure (SSRF risk), analyze instance profiles, and identify potential credential theft vectors
- **`scan_resource_policies`** - Comprehensive scan of resource-based policies: S3, SQS, SNS, Lambda, KMS, Secrets Manager for overly permissive access patterns
- **`analyze_network_exposure`** - Deep network security analysis: internet-facing resources, VPC peering risks, Transit Gateway exposure, NAT Gateway egress points
- **`detect_data_exfiltration_paths`** - Identify potential data exfiltration vectors: S3 replication rules, Lambda external connections, EC2 egress routes, cross-account data sharing

#### Infrastructure Improvements
- **Caching System** - Added TTL-based caching for repeated API calls to improve performance
- **Rate Limiting** - Per-service rate limiters (EC2, IAM, S3, Lambda, RDS) to prevent API throttling
- **Retry Logic** - Exponential backoff with configurable retries for transient failures
- **Error Handling** - Improved error handling with `safeApiCall` and `safeExecute` wrappers
- **Batch Processing** - `batchProcess` utility for processing large datasets efficiently

#### Testing
- **Unit Tests** - Added Jest unit tests for utility functions (Cache, RateLimiter, withRetry, etc.)
- **Test Scripts** - Added `npm test`, `npm test:watch`, and `npm test:coverage` commands

### Changed
- Updated `package.json` with Jest configuration and test scripts
- Tool count increased from 32 to 39

### Technical Details
- New file: `src/utils.ts` - Shared utility functions
- New file: `tests/utils.test.ts` - Jest unit tests
- Jest configured for ES modules with `ts-jest`

---

## [1.0.0] - 2025-12-15

### Added

#### Core Enumeration Tools (10 tools)
- `whoami` - Identify current AWS identity
- `enumerate_ec2_instances` - List EC2 instances with security details
- `enumerate_s3_buckets` - List all S3 buckets
- `enumerate_iam_users` - List IAM users with access key info
- `enumerate_iam_roles` - List IAM roles with trust policies
- `enumerate_rds_databases` - List RDS instances/clusters
- `enumerate_vpcs` - List VPCs with network details
- `enumerate_lambda_functions` - List Lambda functions
- `enumerate_eks_clusters` - List EKS clusters
- `enumerate_public_resources` - Map public attack surface

#### Security Scanning Tools (13 tools)
- `scan_s3_bucket_security` - Deep S3 bucket analysis (7 checks)
- `analyze_security_groups` - Security group rule analysis
- `check_iam_policies` - IAM policy permission analysis
- `check_kms_keys` - KMS key configuration analysis
- `scan_secrets_manager` - Secrets Manager security checks
- `scan_dynamodb_security` - DynamoDB encryption and backup checks
- `scan_api_gateway_security` - API Gateway security analysis
- `scan_cloudfront_security` - CloudFront distribution security
- `scan_elasticache_security` - ElastiCache security configuration
- `get_guardduty_findings` - Retrieve GuardDuty threat findings
- `scan_sns_security` - SNS topic security analysis
- `scan_sqs_security` - SQS queue security analysis
- `scan_cognito_security` - Cognito pool security checks

#### Advanced Analysis Tools (9 tools)
- `analyze_attack_paths` - Identify privilege escalation chains
- `generate_security_report` - Multi-format report generation (PDF/HTML/CSV/Markdown)
- `analyze_encryption_security` - KMS and DynamoDB encryption analysis
- `analyze_api_distribution_security` - API Gateway and CloudFront combined analysis
- `analyze_messaging_security` - SNS, SQS, Cognito combined analysis
- `analyze_infrastructure_automation` - CloudFormation and EventBridge security
- `scan_for_backdoors` - Detect persistence mechanisms
- `analyze_cross_account_movement` - Cross-account lateral movement analysis
- `detect_mfa_bypass_vectors` - Identify MFA bypass vulnerabilities

### Features
- Multi-format report generation (PDF, HTML, CSV, Markdown)
- TRA (Threat & Risk Assessment) integration
- CIS, NIST, PCI-DSS, HIPAA compliance mapping
- MITRE ATT&CK cloud matrix alignment
- Risk scoring (0-10 scale)
- Remediation roadmaps

### Technical
- Built with TypeScript
- AWS SDK v3
- Model Context Protocol (MCP) integration
- 100% read-only operations
