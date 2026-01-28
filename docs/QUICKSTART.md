# Quickstart

Get Sentinel running in 5 minutes.

Sentinel gates AWS credential issuance through policies stored in SSM Parameter Store.

## Prerequisites

- AWS credentials configured (SSO, IAM user, or environment variables)
- Go 1.25+ (for building from source)

## Install

```bash
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest
```

## Quick Setup

### Step 1: Generate configs

```bash
sentinel config generate --template basic --profile dev
```

This outputs starter policy YAML. Save it locally or pipe to a file.

### Step 2: Bootstrap SSM parameters

```bash
sentinel init bootstrap --profile dev
```

This creates `/sentinel/policies/dev` in SSM Parameter Store.

### Step 3: Test it works

```bash
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev
```

If successful, you get a shell with AWS credentials.

## Alternative: Interactive Setup

For guided configuration:

```bash
sentinel init wizard
```

The wizard discovers your AWS profiles, helps you select features, and generates IAM policies.

## Configure credential_process

Add to `~/.aws/config` for seamless SDK integration:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev
```

## Optional: Set Up DynamoDB Tables

If you plan to use approval workflows, break-glass access, or server mode with session tracking, create the required DynamoDB tables:

### Approval Workflows

```bash
# Preview what will be created
sentinel init approvals --plan --region us-east-1

# Create the approval requests table
sentinel init approvals --region us-east-1
```

### Break-Glass Emergency Access

```bash
sentinel init breakglass --region us-east-1
```

### Server Mode Session Tracking

```bash
sentinel init sessions --region us-east-1
```

### All Tables at Once

Use the unified bootstrap command with `--with-*` flags:

```bash
sentinel init bootstrap --profile dev \
  --with-approvals \
  --with-breakglass \
  --with-sessions \
  --region us-east-1
```

Or use `--all` to enable all optional infrastructure:

```bash
sentinel init bootstrap --profile dev --all --region us-east-1
```

### Generate IAM Policies

Each init command can generate the required IAM policy:

```bash
sentinel init approvals --generate-iam --region us-east-1
```

### Check Infrastructure Status

View the status of your Sentinel deployment including DynamoDB tables:

```bash
sentinel init status --check-tables --region us-east-1
```

## Verify Permissions

Check your IAM permissions are sufficient:

```bash
sentinel permissions check --auto-detect
```

## Daily Usage: Shell Functions

Typing full `sentinel exec --profile ... --policy-parameter ...` commands is tedious for daily use. Sentinel can generate shell wrapper functions for all your configured profiles.

### One-Time Setup

Add to your shell profile:

```bash
# Add to ~/.bashrc or ~/.zshrc:
eval "$(sentinel shell init)"
```

Then restart your shell or run `source ~/.bashrc` (or `~/.zshrc`).

### Usage

```bash
# Instead of:
sentinel exec --profile production --policy-parameter /sentinel/policies/production -- aws s3 ls

# Just use:
sentinel-production aws s3 ls
```

Shell functions are automatically created for each profile found under your policy root.

### Server Mode (Optional)

For real-time revocation capability on long-running processes, generate server mode variants:

```bash
# Add to ~/.bashrc or ~/.zshrc:
eval "$(sentinel shell init --include-server)"

# Then use:
sentinel-production-server terraform plan
```

Server mode re-evaluates policy on every credential request, enabling instant revocation.

See [CLI Reference](guide/commands.md#shell-init) for full details.

## v1.21 Features

### Policy Signing (Optional)

For production environments, enable KMS-based policy signing to ensure policy integrity:

```bash
# Sign a policy with KMS
sentinel policy sign --kms-key-id alias/sentinel-policy-signing \
  --input policy.yaml --output policy.yaml.sig

# Verify signature before loading
sentinel policy verify --kms-key-id alias/sentinel-policy-signing \
  --input policy.yaml --signature policy.yaml.sig
```

See [Policy Signing Guide](POLICY_SIGNING.md) for KMS key setup and integration.

### Device Posture (Optional)

Require device security state verification before issuing credentials:

```bash
# Check device posture
sentinel device check

# Use with exec (automatically checked when policy requires device posture)
sentinel exec --profile prod --policy-parameter /sentinel/policies/prod \
  -- aws sts get-caller-identity
```

Supports Jamf Pro and Microsoft Intune MDM providers.

See [Device Posture Guide](DEVICE_POSTURE.md) for MDM integration.

## What's Next

- [Getting Started Guide](guide/getting-started.md) - Full setup walkthrough
- [Policy Reference](guide/policy-reference.md) - YAML schema documentation
- [Permissions Reference](PERMISSIONS.md) - Complete IAM requirements
- [CLI Reference](guide/commands.md) - All commands and flags
