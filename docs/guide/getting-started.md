# Getting Started

This guide walks you through installing Sentinel, creating your first policy, and issuing policy-gated AWS credentials.

## Prerequisites

### Required

- **Go 1.25+** - For building from source
- **AWS Account** - With permissions to create SSM parameters
- **AWS Credentials** - For initial setup (see [Configuring AWS Credentials](#configuring-aws-credentials) below)

### Optional

- **aws-vault** - Sentinel shares the same keyring backend
- **DynamoDB tables** - For approval workflows and break-glass features

## Configuring AWS Credentials

Sentinel needs AWS credentials to read policies from SSM and assume roles. Choose the method that matches your organization's setup.

### Option 1: AWS IAM Identity Center (SSO) - Recommended

Most organizations use SSO. Configure your profile in `~/.aws/config`:

```ini
[profile dev-sso]
sso_start_url = https://your-org.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = DeveloperAccess
region = us-west-2
```

Then just run Sentinel - it handles SSO login automatically:

```bash
sentinel init bootstrap --profile dev-sso --plan
```

Sentinel opens your browser for SSO authentication when needed, caches the token, and refreshes it automatically. No separate `aws sso login` required.

### Option 2: IAM User Credentials

For IAM users with access keys, configure `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Option 3: Environment Variables

Export credentials directly:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-west-2
```

### Option 4: IAM Role (EC2/ECS/Lambda)

When running on AWS infrastructure, Sentinel automatically uses the attached IAM role. No configuration needed.

### Required IAM Permissions

Sentinel needs these minimum permissions to operate:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelReadPolicies",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
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

For bootstrapping (creating policies), also add:

```json
{
  "Sid": "SentinelBootstrap",
  "Effect": "Allow",
  "Action": "ssm:PutParameter",
  "Resource": "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
}
```

See [Deployment](deployment.md) for complete IAM policies including approval workflows and break-glass.

## Installation

### From Source

```bash
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest
```

### Verify Installation

```bash
sentinel --version
sentinel --help
```

## Quick Start

### Step 1: Bootstrap SSM Parameters

Create policy parameters in AWS Systems Manager Parameter Store:

```bash
# Preview what will be created
sentinel init bootstrap --profile dev --plan

# Create the parameters
sentinel init bootstrap --profile dev

# Verify status
sentinel init status
```

This creates an SSM parameter at `/sentinel/policies/dev` with a default-deny policy.

### Step 2: Customize Your Policy

The initial policy denies all access. Edit it to match your requirements.

**Using AWS CLI:**

```bash
# Download current policy
aws ssm get-parameter \
  --name /sentinel/policies/dev \
  --query 'Parameter.Value' \
  --output text > policy.yaml

# Edit policy.yaml (see example below)

# Upload updated policy
aws ssm put-parameter \
  --name /sentinel/policies/dev \
  --value file://policy.yaml \
  --type String \
  --overwrite
```

**Example policy.yaml:**

```yaml
version: "1"
rules:
  - name: allow-dev-team
    effect: allow
    conditions:
      profiles:
        - dev
      users:
        - alice
        - bob
    reason: Development team access

  - name: default-deny
    effect: deny
    conditions: {}
    reason: No matching rule
```

### Step 3: Configure credential_process

Update `~/.aws/config` to use Sentinel:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev
```

### Step 4: Test Credentials

```bash
# Test credential issuance
aws sts get-caller-identity --profile dev

# Or use sentinel exec for interactive shell
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev
```

## Using sentinel exec

The `exec` command runs a command (or shell) with policy-gated credentials:

```bash
# Start a shell with credentials
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev

# Run a specific command
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev -- aws s3 ls
```

**Environment Variables Set:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_CREDENTIAL_EXPIRATION`
- `AWS_SENTINEL` - Set to profile name (prevents nested sessions)

**Common Flags:**

| Flag | Description |
|------|-------------|
| `--profile` | AWS profile name (required) |
| `--policy-parameter` | SSM parameter path (required) |
| `--duration` / `-d` | Session duration (default: 1h) |
| `--no-session` / `-n` | Skip GetSessionToken |
| `--region` | AWS region for SSM |
| `--log-file` | Write decision logs to file |
| `--log-stderr` | Write decision logs to stderr |
| `--server` / `-s` | Enable server mode for per-request policy evaluation |
| `--auto-login` | Automatically trigger SSO login when needed |

**Server Mode:**

For sensitive profiles requiring real-time revocation capability:

```bash
sentinel exec --server --profile prod --policy-parameter /sentinel/policies/prod -- terraform plan
```

Server mode evaluates policy on every credential request, enabling instant access revocation when policies change. See [CLI Reference](commands.md#server-mode) for details.

## Using credential_process

For seamless integration with AWS SDK and CLI, configure `credential_process`:

```ini
[profile production]
credential_process = sentinel credentials --profile production --policy-parameter /sentinel/policies/default
```

**How it works:**

1. AWS SDK/CLI calls the `credential_process` command
2. Sentinel loads policy from SSM
3. Sentinel evaluates policy against current user and profile
4. If allowed, Sentinel assumes the role and returns JSON credentials
5. AWS SDK/CLI uses the returned credentials

**Output format:**

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-01-17T11:30:00Z"
}
```

## Verifying It Works

### Check Your Identity

First, verify which AWS identity Sentinel sees for policy evaluation:

```bash
sentinel whoami
```

Output:
```
AWS Identity
============

ARN:             arn:aws:iam::123456789012:user/alice
Account:         123456789012
Identity Type:   iam-user
Raw Username:    alice
Policy Username: alice

The policy username is used for matching against Sentinel policy rules.
```

The "Policy Username" is what matches against the `users` condition in your policies.

### Check Policy Status

```bash
sentinel init status
```

Output:
```
Sentinel Policy Status
======================

Policy Root: /sentinel/policies

Profiles:
  dev    v1  (last modified: 2026-01-17 10:30:22)

Total: 1 policy parameter
```

### Test with AWS CLI

```bash
aws sts get-caller-identity --profile dev
```

If successful, you'll see your assumed role identity.

### Check Decision Logs

Enable logging to see policy evaluation:

```bash
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev --log-stderr
```

## Multi-Profile Setup

Bootstrap multiple profiles at once:

```bash
sentinel init bootstrap --profile dev --profile staging --profile prod
```

Configure each in `~/.aws/config`:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev

[profile staging]
credential_process = sentinel credentials --profile staging --policy-parameter /sentinel/policies/staging

[profile prod]
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod
```

## Enabling Approval Workflows

For sensitive profiles, require human approval:

```yaml
version: "1"
rules:
  - name: prod-requires-approval
    effect: require_approval
    conditions:
      profiles:
        - prod
    reason: Production access requires approval
```

See [Approval Workflows](approval-workflows.md) for complete setup.

## Enabling Break-Glass Access

For emergency access that bypasses normal policy:

```bash
sentinel breakglass \
  --profile prod \
  --reason-code incident \
  --justification "Production outage, need immediate access" \
  --breakglass-table sentinel-breakglass
```

See [Break-Glass Access](break-glass.md) for complete setup.

## Next Steps

- [Core Concepts](concepts.md) - Understand policy evaluation and effects
- [CLI Reference](commands.md) - Complete command reference
- [Policy Reference](policy-reference.md) - Full YAML schema documentation
- [Deployment](deployment.md) - Production deployment guide
