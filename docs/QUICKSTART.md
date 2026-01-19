# Quickstart

Get Sentinel running in 5 minutes.

Sentinel gates AWS credential issuance through policies stored in SSM Parameter Store.

## Prerequisites

- AWS credentials configured (SSO, IAM user, or environment variables)
- Go 1.21+ (for building from source)

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

## Verify Permissions

Check your IAM permissions are sufficient:

```bash
sentinel permissions check --auto-detect
```

## What's Next

- [Getting Started Guide](guide/getting-started.md) - Full setup walkthrough
- [Policy Reference](guide/policy-reference.md) - YAML schema documentation
- [Permissions Reference](PERMISSIONS.md) - Complete IAM requirements
- [CLI Reference](guide/commands.md) - All commands and flags
