# Changelog

All notable changes to **Nimbus** (AWS Security Assessment MCP Server) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-01-13

### Added

#### Attack Chain Builder & Advanced Privilege Escalation (3 new tools)
- **build_attack_chains** - Build multi-step attack paths from IAM findings
  - Identifies complete attack chains: initial access → privilege escalation → lateral movement → data exfiltration
  - MITRE ATT&CK technique mapping for all chains
  - Blast radius scoring (0-100) based on compromised resources
  - Chain categories: PassRole abuse, Policy manipulation, Credential access
  - Mermaid diagram output for visualization
  - 6 pre-built attack chain templates

- **analyze_eks_attack_surface** - Comprehensive EKS security analysis
  - IRSA (IAM Roles for Service Accounts) abuse detection
  - Node role credential theft via IMDS analysis
  - Cluster config manipulation vectors
  - Pod security risks assessment
  - Kubernetes RBAC to AWS IAM privilege escalation paths
  - Fargate profile security analysis
  - Node group role auditing

- **detect_privesc_patterns** - 50+ IAM privilege escalation pattern detection
  - Based on Rhino Security Labs & Heimdall research
  - Categories: PassRole abuse, Policy manipulation, Credential access, EKS abuse, Lambda abuse, SSM abuse, S3 abuse, Defense evasion
  - MITRE ATT&CK mapping for all patterns
  - Detailed exploitation commands
  - Remediation recommendations

### Changed
- **Tool Consolidation** - Reduced tool count from 46 to 40 by merging overlapping functionality:
  - Merged `scan_privilege_escalation_paths` into `detect_privesc_patterns`
  - Merged `analyze_iam_privilege_escalation` into `detect_privesc_patterns`
  - Merged `analyze_attack_paths` into `build_attack_chains`
  - Merged `detect_cross_account_access` into `analyze_cross_account_movement`
  - Merged `detect_service_role_risks` into `detect_permissive_roles`
  - Merged `scan_for_backdoors` into `detect_persistence_mechanisms`

#### New Privesc Patterns Added
- **PassRole Abuse (7 patterns):**
  - PassRole → Lambda, EC2, Glue, CloudFormation, CodeBuild, SageMaker, ECS

- **Policy Manipulation (6 patterns):**
  - AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, CreatePolicyVersion, SetDefaultPolicyVersion

- **Credential Access (4 patterns):**
  - CreateAccessKey, CreateLoginProfile, UpdateLoginProfile, UpdateAssumeRolePolicy

- **EKS Abuse (5 patterns):**
  - IRSA pod execution abuse, Node role credential theft, EKS cluster admin access, Fargate profile PassRole, EKS wildcard describe

- **Lambda Abuse (3 patterns):**
  - UpdateFunctionCode, Lambda layer backdoor, Environment variable secrets

- **SSM Abuse (3 patterns):**
  - SendCommand, StartSession, GetParameters

- **S3 Abuse (2 patterns):**
  - Data exfiltration via replication, Bucket policy modification

- **Defense Evasion (3 patterns):**
  - CloudTrail stop/delete, GuardDuty disable

### Changed
- Total tools: **48** (up from 43)
- Total privesc patterns: **50+**
- Enhanced EKS security analysis with attack vectors

### Technical Details
- New interfaces: `PrivescPattern`, `AttackChain`, `AttackChainStep`
- Attack chain templates with step-by-step paths
- Blast radius calculation algorithm
- Permission matching with wildcard support
- Group policy enumeration for comprehensive permission analysis

---

## [1.4.2] - 2026-01-12

### Changed
- **Cleaner report output** - Professional text-based formatting for better readability
- **TRA Report** - Supports CIS, NIST, PCI-DSS compliance frameworks

---

## [1.4.0] - 2026-01-11

### Added

#### Caching & Performance (2 new tools)
- **cache_stats** - View cache statistics (hit/miss ratio, cached keys)
- **cache_clear** - Clear cached data (all or by pattern)

#### Production Features
- Integrated caching system from `utils.ts`
- Automatic retry logic with exponential backoff
- Rate limiting protection for AWS APIs
- Cache TTLs: EC2 (2min), IAM (10min), S3 (10min)

### Changed
- Total tools: **43** (cache tools replace manual cache management)
- Key functions now use cache for faster repeated scans
- API calls wrapped with retry logic for reliability

### Benefits
- ⚡ Repeated scans return instantly from cache
- 🛡️ Avoids AWS API throttling on multi-region scans
- 🔄 Automatic retry on transient failures

---

## [1.3.0] - 2026-01-11

### Added

#### Multi-Region Scanning (2 new tools)
- **scan_all_regions** - Scan multiple AWS regions for resources in parallel
  - Supports: EC2, Lambda, RDS, EKS, Secrets Manager, GuardDuty, ElastiCache, VPC
  - **Custom regions**: `--regions "us-east-1,eu-west-1"` for specific regions
  - **Presets**: 'common' (11 regions) or 'all' (30+ regions)
  - Configurable parallelism (1-10 concurrent scans)
  - Aggregated findings with critical issues highlighted
  - Security analysis per region with risk ratings

- **list_active_regions** - Quick discovery of regions with resources
  - Fast parallel scan to identify active regions
  - **Custom regions**: `--regions "us-east-1"` for single region check
  - Shows EC2, Lambda, RDS counts per region
  - Helps prioritize which regions to deep-scan

#### Infrastructure
- Added AWS_REGIONS constant with all 30+ AWS regions
- Added COMMON_REGIONS for faster scanning (covers 90%+ of deployments)
- Parallel execution helper with configurable concurrency
- Region-specific scanner functions for each resource type
- `parseRegions()` helper for custom region parsing and validation

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
