# Permissions Reference

Sentinel requires different AWS IAM permissions based on which features you enable. This document covers all permission requirements and how to generate IAM policies.

## Overview

Sentinel has 10 features across 8 subsystems. Each feature requires specific IAM actions. Enable only what you need to follow the principle of least privilege.

## Quick Reference

| Feature | Required Actions | Resource |
|---------|------------------|----------|
| `policy_load` | ssm:GetParameter, ssm:GetParameters, ssm:GetParametersByPath | arn:aws:ssm:*:*:parameter/sentinel/policies/* |
| `credential_issue` | sts:AssumeRole, sts:GetCallerIdentity | arn:aws:iam::*:role/*, * |
| `approval_workflow` | dynamodb:PutItem, GetItem, DeleteItem, Query | arn:aws:dynamodb:*:*:table/sentinel-requests |
| `breakglass` | dynamodb:PutItem, GetItem, DeleteItem, Query | arn:aws:dynamodb:*:*:table/sentinel-breakglass |
| `notify_sns` | sns:Publish | arn:aws:sns:*:*:sentinel-* |
| `notify_webhook` | (none - HTTP only) | N/A |
| `audit_verify` | cloudtrail:LookupEvents | * |
| `enforce_analyze` | iam:GetRole | arn:aws:iam::*:role/* |
| `session_tracking` | dynamodb:PutItem, GetItem, UpdateItem, Query | arn:aws:dynamodb:*:*:table/sentinel-sessions |
| `bootstrap_plan` | ssm:GetParameter, ssm:GetParametersByPath | arn:aws:ssm:*:*:parameter/sentinel/* |
| `bootstrap_apply` | ssm:PutParameter, DeleteParameter, AddTagsToResource, RemoveTagsFromResource | arn:aws:ssm:*:*:parameter/sentinel/* |

## Minimal Setup

For basic credential issuance without approval workflows or break-glass:

**Required features:** `policy_load`, `credential_issue`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyLoad",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
    },
    {
      "Sid": "SentinelCredentialIssue",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/*"
    },
    {
      "Sid": "SentinelIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

## Full Setup

For all features including approval workflows, break-glass, and audit verification:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyLoad",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
    },
    {
      "Sid": "SentinelCredentialIssue",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/*"
    },
    {
      "Sid": "SentinelIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    },
    {
      "Sid": "SentinelApprovalWorkflow",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-requests",
        "arn:aws:dynamodb:*:*:table/sentinel-requests/index/*"
      ]
    },
    {
      "Sid": "SentinelBreakGlass",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass",
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass/index/*"
      ]
    },
    {
      "Sid": "SentinelNotifySNS",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:*:*:sentinel-*"
    },
    {
      "Sid": "SentinelAuditVerify",
      "Effect": "Allow",
      "Action": "cloudtrail:LookupEvents",
      "Resource": "*"
    },
    {
      "Sid": "SentinelEnforceAnalyze",
      "Effect": "Allow",
      "Action": "iam:GetRole",
      "Resource": "arn:aws:iam::*:role/*"
    },
    {
      "Sid": "SentinelBootstrap",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "ssm:DeleteParameter",
        "ssm:AddTagsToResource",
        "ssm:RemoveTagsFromResource"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/sentinel/*"
    },
    {
      "Sid": "SentinelSessionTracking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-sessions",
        "arn:aws:dynamodb:*:*:table/sentinel-sessions/index/*"
      ]
    }
  ]
}
```

## Using the Permissions Command

Sentinel includes a `permissions` command that generates IAM policies based on your feature selection. Running `sentinel permissions` defaults to `sentinel permissions list`.

### Human-Readable Output

```bash
sentinel permissions
# or explicitly:
sentinel permissions list
```

Shows all features and their required IAM actions in a readable format.

### JSON IAM Policy

```bash
sentinel permissions --format json
```

Outputs IAM policy JSON suitable for direct use in AWS.

### Terraform Format

```bash
sentinel permissions --format terraform
```

Outputs Terraform `aws_iam_policy_document` data source.

### CloudFormation Format

```bash
sentinel permissions --format cloudformation
# or
sentinel permissions --format cf
```

Outputs CloudFormation IAM policy document.

### Filter by Feature or Subsystem

```bash
# Single feature
sentinel permissions --feature policy_load

# Single subsystem (all features in that subsystem)
sentinel permissions --subsystem approvals

# Exclude optional features (notify_sns, notify_webhook)
sentinel permissions --required-only
```

### Auto-Detection

Detect which features you're using based on your AWS resources:

```bash
sentinel permissions --detect
```

This checks:
- SSM for `/sentinel/policies/*` (policy_load, bootstrap_plan)
- DynamoDB for `sentinel-requests` table (approval_workflow)
- DynamoDB for `sentinel-breakglass` table (breakglass)

And outputs permissions only for detected features.

## Validating Permissions

The `permissions check` command validates your AWS credentials have the required permissions.

### Check All Features

```bash
sentinel permissions check
```

### Check with Auto-Detection

```bash
sentinel permissions check --auto-detect
```

Detects which features you use and validates only those permissions.

### Check Specific Features

```bash
sentinel permissions check --feature policy_load,credential_issue
```

### AWS SSO Support

Permission checking works with AWS SSO credentials. The CLI automatically converts
assumed-role session ARNs to IAM role ARNs for the SimulatePrincipalPolicy API.

**Required permission:** Your SSO role needs `iam:SimulatePrincipalPolicy` to check permissions:

```json
{
  "Effect": "Allow",
  "Action": "iam:SimulatePrincipalPolicy",
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/YOUR_SSO_ROLE_NAME"
}
```

If this permission is not available, you'll see a message indicating
permission checking requires SimulatePrincipalPolicy.

### JSON Output

```bash
sentinel permissions check --output json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All permission checks passed |
| 1 | One or more checks failed or errored |

**Example CI/CD usage:**

```bash
sentinel permissions check --auto-detect || {
  echo "Permission validation failed"
  exit 1
}
```

## Feature Details

### policy_load (Core)

**Purpose:** Load access policies from SSM Parameter Store.

**Required for:** All Sentinel operations (credential issuance, exec).

| Action | Resource | Purpose |
|--------|----------|---------|
| ssm:GetParameter | /sentinel/policies/* | Load specific policy |
| ssm:GetParameters | /sentinel/policies/* | Batch policy load |
| ssm:GetParametersByPath | /sentinel/policies/* | List policies |

### credential_issue (Credentials)

**Purpose:** Issue AWS credentials via STS AssumeRole with SourceIdentity.

**Required for:** `sentinel credentials`, `sentinel exec`.

| Action | Resource | Purpose |
|--------|----------|---------|
| sts:AssumeRole | arn:aws:iam::*:role/* | Assume target role |

### approval_workflow (Approvals)

**Purpose:** Manage access request lifecycle in DynamoDB.

**Required for:** `sentinel request`, `sentinel approve`, `sentinel deny`, `sentinel list`, `sentinel check`.

| Action | Resource | Purpose |
|--------|----------|---------|
| dynamodb:PutItem | sentinel-requests | Create/update requests |
| dynamodb:GetItem | sentinel-requests | Read request details |
| dynamodb:DeleteItem | sentinel-requests | Cancel requests |
| dynamodb:Query | sentinel-requests, sentinel-requests/index/* | List and filter requests |

### breakglass (Break-Glass)

**Purpose:** Manage emergency access events in DynamoDB.

**Required for:** `sentinel breakglass`, `sentinel breakglass-list`, `sentinel breakglass-check`, `sentinel breakglass-close`.

| Action | Resource | Purpose |
|--------|----------|---------|
| dynamodb:PutItem | sentinel-breakglass | Create/update events |
| dynamodb:GetItem | sentinel-breakglass | Read event details |
| dynamodb:DeleteItem | sentinel-breakglass | Admin cleanup |
| dynamodb:Query | sentinel-breakglass, sentinel-breakglass/index/* | List and filter events |

### notify_sns (Notifications - Optional)

**Purpose:** Publish notification events to SNS topics.

**Required for:** SNS-based alerting on approvals, break-glass, etc.

| Action | Resource | Purpose |
|--------|----------|---------|
| sns:Publish | sentinel-* | Publish to Sentinel topics |

### notify_webhook (Notifications - Optional)

**Purpose:** Send notifications via HTTP webhooks.

**Required permissions:** None (uses HTTPS, no AWS API calls).

### audit_verify (Audit)

**Purpose:** Query CloudTrail for session verification.

**Required for:** `sentinel audit verify`.

| Action | Resource | Purpose |
|--------|----------|---------|
| cloudtrail:LookupEvents | * | Query CloudTrail events |

Note: CloudTrail LookupEvents does not support resource-level permissions.

### enforce_analyze (Enforcement)

**Purpose:** Analyze IAM role trust policies for Sentinel enforcement.

**Required for:** `sentinel enforce plan`.

| Action | Resource | Purpose |
|--------|----------|---------|
| iam:GetRole | arn:aws:iam::*:role/* | Read trust policies |

### bootstrap_plan (Bootstrap)

**Purpose:** Plan bootstrap operations by checking existing SSM parameters.

**Required for:** `sentinel init bootstrap --plan`, `sentinel init status`.

| Action | Resource | Purpose |
|--------|----------|---------|
| ssm:GetParameter | /sentinel/* | Check individual parameters |
| ssm:GetParametersByPath | /sentinel/* | List existing parameters |

### bootstrap_apply (Bootstrap)

**Purpose:** Create and manage SSM parameters during bootstrap.

**Required for:** `sentinel init bootstrap` (apply mode).

| Action | Resource | Purpose |
|--------|----------|---------|
| ssm:PutParameter | /sentinel/* | Create/update parameters |
| ssm:DeleteParameter | /sentinel/* | Remove parameters |
| ssm:AddTagsToResource | /sentinel/* | Tag parameters |
| ssm:RemoveTagsFromResource | /sentinel/* | Untag parameters |

### session_tracking (Server Mode)

**Purpose:** Track and manage server mode sessions for real-time revocation.

**Required for:** `sentinel exec --server --session-table`, `sentinel server-sessions`, `sentinel server-session`, `sentinel server-revoke`.

| Action | Resource | Purpose |
|--------|----------|---------|
| dynamodb:PutItem | sentinel-sessions | Create/update sessions |
| dynamodb:GetItem | sentinel-sessions | Read session details |
| dynamodb:UpdateItem | sentinel-sessions | Touch and revoke sessions |
| dynamodb:Query | sentinel-sessions, sentinel-sessions/index/* | List and filter sessions |

## Restricting Resource Scope

The default IAM policies use wildcards for region and account ID for portability. You can restrict scope:

### Region-Specific

```json
"Resource": "arn:aws:ssm:us-west-2:*:parameter/sentinel/policies/*"
```

### Account-Specific

```json
"Resource": "arn:aws:ssm:*:123456789012:parameter/sentinel/policies/*"
```

### Both

```json
"Resource": "arn:aws:ssm:us-west-2:123456789012:parameter/sentinel/policies/*"
```

## Related Documentation

- [Bootstrap Guide](BOOTSTRAP.md) - SSM parameter setup
- [CLI Reference](guide/commands.md) - All commands including permissions
- [Getting Started](guide/getting-started.md) - Full setup walkthrough
