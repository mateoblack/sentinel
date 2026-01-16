# Bootstrap Guide

Sentinel bootstrap automates the setup of SSM policy parameters in your AWS account. This guide covers command usage, IAM requirements, security properties, and adoption paths.

## Overview

### What Bootstrap Does

The `sentinel init bootstrap` command creates SSM parameters that store Sentinel policy YAML. When Sentinel evaluates an access request, it reads the policy for that profile from SSM.

**Key components:**
- **SSM Parameters**: One parameter per profile, storing policy YAML
- **Policy Root**: Default path prefix `/sentinel/policies` (customizable)
- **IAM Policies**: Generated policy documents for reader and admin access

### How Sentinel Uses Policies

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User Request   │────>│  Sentinel        │────>│  AWS SSM        │
│                 │     │                  │     │                 │
│ "I need prod    │     │ 1. Load policy   │     │ GetParameter    │
│  access"        │     │    from SSM      │     │ /sentinel/      │
│                 │     │ 2. Evaluate      │     │   policies/prod │
│                 │     │ 3. Issue or deny │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Quick Start

### First Time Setup

1. **Preview what will be created:**
   ```bash
   sentinel init bootstrap --profile dev --plan
   ```

2. **Create the SSM parameters:**
   ```bash
   sentinel init bootstrap --profile dev
   ```

3. **Verify status:**
   ```bash
   sentinel init status
   ```

### Auto-Approve (Non-Interactive)

For CI/CD pipelines or scripted setup:

```bash
sentinel init bootstrap --profile dev --profile staging --profile prod --yes
```

## Command Reference

### `sentinel init bootstrap`

Creates or updates SSM parameters for Sentinel policies.

| Flag | Description | Default |
|------|-------------|---------|
| `--profile` | AWS profile to bootstrap (required, repeatable) | - |
| `--plan` | Show plan without applying (dry-run) | false |
| `--yes` / `-y` | Auto-approve, skip confirmation prompt | false |
| `--policy-root` | SSM parameter path prefix | `/sentinel/policies` |
| `--region` | AWS region for SSM operations | AWS default |
| `--generate-iam-policies` | Output IAM policy documents | false |
| `--json` | Machine-readable JSON output | false |
| `--description` | Description for generated policy comments | - |

**Examples:**

```bash
# Preview changes for single profile
sentinel init bootstrap --profile myapp --plan

# Create parameters for multiple profiles
sentinel init bootstrap --profile dev --profile staging --profile prod

# Auto-approve with IAM policy output
sentinel init bootstrap --profile myapp --yes --generate-iam-policies

# Custom policy root
sentinel init bootstrap --profile myapp --policy-root /myorg/sentinel/policies

# JSON output for scripting
sentinel init bootstrap --profile myapp --json
```

### `sentinel init status`

Shows current Sentinel policy status from SSM.

| Flag | Description | Default |
|------|-------------|---------|
| `--policy-root` | SSM parameter path prefix | `/sentinel/policies` |
| `--region` | AWS region for SSM operations | AWS default |
| `--json` | Machine-readable JSON output | false |

**Examples:**

```bash
# Human-readable status
sentinel init status

# JSON output
sentinel init status --json

# Check custom policy root
sentinel init status --policy-root /myorg/sentinel/policies
```

**Sample Output:**

```
Sentinel Policy Status
======================

Policy Root: /sentinel/policies

Profiles:
  dev        v3  (last modified: 2026-01-15 14:30:22)
  staging    v1  (last modified: 2026-01-15 14:30:25)
  prod       v5  (last modified: 2026-01-16 09:15:00)

Total: 3 policy parameters
```

## What Gets Created

### SSM Parameters

Bootstrap creates one SSM parameter per profile:

| Parameter | Description |
|-----------|-------------|
| `{policy_root}/{profile}` | Policy YAML for the profile |

**Example for `--profile dev` with default policy root:**

```
/sentinel/policies/dev
```

### Initial Policy Content

Each parameter is initialized with a default-deny policy:

```yaml
# Sentinel policy for profile: dev
# Generated: 2026-01-16T10:30:00Z
# Customize this policy to match your access requirements.

version: "1"
rules:
  - name: default-deny
    effect: deny
    conditions:
      profiles:
        - dev
    reason: Default deny - customize this policy
```

**Important:** The initial policy denies all access. You must customize it after bootstrap.

### Parameter Properties

| Property | Value | Rationale |
|----------|-------|-----------|
| Type | String | Policy YAML is not sensitive data |
| Tier | Standard | Sufficient for policy storage |
| Overwrite | false (create) | Prevents accidental overwrites |

### Version History

SSM maintains version history for each parameter:
- Every update creates a new version
- Previous versions are retained
- Supports rollback via AWS Console or CLI
- Provides audit trail of policy changes

## IAM Requirements

### SentinelPolicyReader

Attach to roles that read policies (e.g., Sentinel CLI, Lambda functions):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyRead",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
      ]
    }
  ]
}
```

### SentinelPolicyAdmin

Attach to roles that manage policies (e.g., CI/CD pipelines, admin users):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyAdmin",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "ssm:DeleteParameter",
        "ssm:AddTagsToResource",
        "ssm:RemoveTagsFromResource"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
      ]
    }
  ]
}
```

### Restricting ARN Scope

The generated policies use wildcards for region and account ID for portability. To restrict scope:

```json
"Resource": [
  "arn:aws:ssm:us-west-2:123456789012:parameter/sentinel/policies/*"
]
```

### Custom Policy Root

If using a custom policy root (e.g., `/myorg/sentinel/policies`), update the ARN pattern:

```json
"Resource": [
  "arn:aws:ssm:*:*:parameter/myorg/sentinel/policies/*"
]
```

## Security Properties

### Centralized Policy Storage

- **Single source of truth**: Policies stored in SSM, not scattered across local files
- **IAM-protected access**: AWS IAM controls who can read/write policies
- **Cross-region availability**: SSM parameters are regional; replicate across regions if needed

### Audit Trail

- **Version history**: SSM maintains all parameter versions
- **CloudTrail logging**: All SSM API calls are logged
- **Change tracking**: Who changed what, when

### Policy Content Security

| Consideration | Sentinel Approach |
|---------------|-------------------|
| Parameter type | String (not SecureString) |
| Encryption | At-rest encryption via SSM default |
| Sensitivity | Policy YAML defines rules, not secrets |

**Why String, not SecureString?**

Policy YAML contains access rules (users, conditions, effects) - this is configuration data, not sensitive credentials. Using String type:
- Simplifies debugging (visible in AWS Console)
- Reduces KMS costs
- Policy rules are not secrets (IAM controls access to the parameter itself)

### IAM Policy Wildcards

Generated IAM policies use `*` for region and account:

```
arn:aws:ssm:*:*:parameter/sentinel/policies/*
```

**Rationale:**
- Portable across environments (dev/staging/prod accounts)
- Works with cross-region deployments
- Can be restricted after generation if needed

## Multi-Profile Bootstrap

Bootstrap multiple profiles in a single command:

```bash
sentinel init bootstrap --profile dev --profile staging --profile prod
```

**Output:**

```
Bootstrap Plan
==============
Policy Root: /sentinel/policies
Region: default

Resources:
  + /sentinel/policies/dev      (SSM Parameter - create)
  + /sentinel/policies/staging  (SSM Parameter - create)
  + /sentinel/policies/prod     (SSM Parameter - create)

Summary: 3 to create, 0 to update, 0 existing

Do you want to apply these changes? [y/N]: y

Apply complete:
  Created: 3
    + /sentinel/policies/dev
    + /sentinel/policies/staging
    + /sentinel/policies/prod
  Updated: 0
  Skipped: 0
  Failed:  0
```

## Custom Policy Root

Organizations can use a custom path prefix:

```bash
sentinel init bootstrap --profile myapp --policy-root /myorg/sentinel/policies
```

**When to use custom policy root:**
- Multi-tenant environments (separate by org: `/acme/sentinel/policies`)
- Environment isolation (separate by env: `/prod/sentinel/policies`)
- Migration scenarios (new root alongside existing)

**Remember:** Update IAM policies to match the custom path.

## Adoption Guide

### Step 1: Bootstrap Profiles

Create SSM parameters with default-deny policies:

```bash
# Preview first
sentinel init bootstrap --profile dev --profile staging --profile prod --plan

# Apply
sentinel init bootstrap --profile dev --profile staging --profile prod --yes
```

### Step 2: Customize Policies

Edit SSM parameters directly or via Infrastructure as Code:

**AWS Console:**
1. Navigate to AWS Systems Manager > Parameter Store
2. Find `/sentinel/policies/{profile}`
3. Click Edit, update policy YAML
4. Save (creates new version)

**AWS CLI:**
```bash
# Download current policy
aws ssm get-parameter \
  --name /sentinel/policies/dev \
  --query 'Parameter.Value' \
  --output text > policy.yaml

# Edit policy.yaml to add your rules

# Upload updated policy
aws ssm put-parameter \
  --name /sentinel/policies/dev \
  --value file://policy.yaml \
  --type String \
  --overwrite
```

**Terraform Example:**
```hcl
resource "aws_ssm_parameter" "sentinel_policy_dev" {
  name  = "/sentinel/policies/dev"
  type  = "String"
  value = file("policies/dev.yaml")
}
```

### Step 3: Configure AWS Config

Update `~/.aws/config` to use Sentinel:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev

[profile staging]
credential_process = sentinel credentials --profile staging

[profile prod]
credential_process = sentinel credentials --profile prod
```

### Step 4: Test Credentials

Verify Sentinel issues credentials correctly:

```bash
# Test credential issuance
sentinel credentials --profile dev

# Test with AWS CLI
aws sts get-caller-identity --profile dev
```

### Step 5: Enable Enforcement (Optional)

For mandatory Sentinel usage, configure IAM trust policies or SCPs:

```bash
# See enforcement patterns documentation
cat docs/ENFORCEMENT.md
```

## Troubleshooting

### "NoCredentialProviders" Error

**Symptom:** Bootstrap fails with "NoCredentialProviders: no valid providers in chain"

**Cause:** No AWS credentials available to call SSM API

**Solution:**
1. Configure AWS credentials (environment variables, credentials file, or IAM role)
2. Verify credentials work: `aws sts get-caller-identity`
3. Retry bootstrap

### "AccessDenied" on SSM Operations

**Symptom:** Bootstrap fails with "AccessDeniedException" from SSM

**Cause:** IAM permissions missing for SSM operations

**Solution:**
1. Attach SentinelPolicyAdmin policy to your IAM role/user
2. Verify policy resource ARN matches your policy root
3. Check for SCPs that might deny SSM access
4. Retry bootstrap

### "Parameter Already Exists"

**Symptom:** Bootstrap reports parameter exists but status doesn't show expected profile

**Cause:** Parameter exists at the path but wasn't created by Sentinel

**Solution:**
1. Run `--plan` to see current state: `sentinel init bootstrap --profile myapp --plan`
2. Check parameter content in AWS Console
3. Either delete existing parameter or use different policy root

### "Policy Syntax Errors"

**Symptom:** Sentinel fails to load policy after manual edit

**Cause:** Invalid YAML or policy schema violation

**Solution:**
1. SSM stores raw YAML - syntax errors only surface at runtime
2. Validate policy before uploading:
   ```bash
   # Download policy
   aws ssm get-parameter --name /sentinel/policies/dev --query 'Parameter.Value' --output text > policy.yaml

   # Validate YAML syntax
   python -c "import yaml; yaml.safe_load(open('policy.yaml'))"
   ```
3. Check Sentinel logs for validation errors

### "Region Mismatch"

**Symptom:** Status shows no profiles but parameters exist in AWS Console

**Cause:** Querying wrong region

**Solution:**
1. Specify region explicitly: `sentinel init status --region us-west-2`
2. Or set AWS_REGION environment variable
3. Verify region matches where parameters were created

### "Connection Timeout"

**Symptom:** Bootstrap hangs or times out

**Cause:** Network connectivity to AWS SSM endpoint

**Solution:**
1. Check network connectivity to SSM endpoint
2. For VPC environments, verify VPC endpoint for SSM exists
3. Check security groups allow HTTPS outbound
4. Try different region if regional issues suspected

## Related Documentation

- [Enforcement Patterns](ENFORCEMENT.md) - Trust policies and SCPs for mandatory Sentinel usage
- [CloudTrail Integration](CLOUDTRAIL.md) - Auditing Sentinel-issued credentials
