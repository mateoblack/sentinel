# Sentinel User Guide

Sentinel is a policy-based credential gateway for AWS. It intercepts AWS credential requests, evaluates access policies, and issues credentials with embedded identity fingerprints for complete audit trails.

## Quick Navigation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Installation, prerequisites, first policy |
| [Core Concepts](concepts.md) | Policy evaluation, effects, conditions, SourceIdentity |
| [CLI Reference](commands.md) | Complete reference for all 17 commands |
| [Policy Reference](policy-reference.md) | Full YAML schema for all policy types |
| [Approval Workflows](approval-workflows.md) | Request/approve flow, auto-approval |
| [Break-Glass Access](break-glass.md) | Emergency access, rate limiting |
| [Deployment](deployment.md) | SSM setup, IAM policies, production checklist |
| [Troubleshooting](troubleshooting.md) | Common issues, debugging, FAQ |

## Key Features

- **Policy-gated credentials** - Define who can access which AWS profiles, when
- **Approval workflows** - Require human approval for sensitive access
- **Break-glass access** - Emergency bypass with mandatory justification
- **CloudTrail correlation** - Every session fingerprinted for audit
- **Trust policy enforcement** - Make Sentinel usage mandatory via IAM

## Common Tasks

### First-time setup
```bash
# 1. Install Sentinel
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest

# 2. Bootstrap policy parameters
sentinel init bootstrap --profile dev --profile staging --profile prod

# 3. Configure credential_process in ~/.aws/config
```

See [Getting Started](getting-started.md) for complete instructions.

### Request access to a profile
```bash
sentinel exec --profile prod --policy-parameter /sentinel/policies/default
```

### Submit an access request
```bash
sentinel request --profile prod --justification "Deploy hotfix for incident INC-123" --request-table sentinel-requests
```

### Invoke break-glass access
```bash
sentinel breakglass --profile prod --reason-code incident --justification "Production database outage, need immediate access" --breakglass-table sentinel-breakglass
```

## Specialized Documentation

For in-depth coverage of specific topics:

| Document | Description |
|----------|-------------|
| [Bootstrap Guide](../BOOTSTRAP.md) | Detailed SSM parameter setup and IAM requirements |
| [Enforcement Patterns](../ENFORCEMENT.md) | Trust policies and SCPs for mandatory Sentinel usage |
| [CloudTrail Correlation](../CLOUDTRAIL.md) | Correlating Sentinel logs with AWS activity |
| [Assurance Guide](../ASSURANCE.md) | Verifying Sentinel enforcement is working |

## Architecture Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User Request   │────>│  Sentinel        │────>│  AWS STS        │
│                 │     │                  │     │                 │
│ credential_     │     │ 1. Load policy   │     │ AssumeRole +    │
│ process or exec │     │    from SSM      │     │ SourceIdentity  │
│                 │     │ 2. Evaluate      │     │                 │
│                 │     │ 3. Issue or deny │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │
                                v
                        ┌──────────────────┐
                        │  CloudTrail      │
                        │                  │
                        │ sourceIdentity:  │
                        │ sentinel:user:id │
                        └──────────────────┘
```

## Command Categories

### Credential Operations
- `credentials` - Output credentials as JSON for credential_process
- `exec` - Execute a command with policy-gated credentials

### Access Requests
- `request` - Submit access request for approval
- `list` - List access requests
- `check` - Check request status
- `approve` - Approve a pending request
- `deny` - Deny a pending request

### Break-Glass
- `breakglass` - Invoke emergency access
- `breakglass-list` - List break-glass events
- `breakglass-check` - Check break-glass event details
- `breakglass-close` - Close active break-glass

### Infrastructure
- `init bootstrap` - Create SSM policy parameters
- `init status` - Show current policy status

### Enforcement
- `enforce plan` - Analyze role trust policies
- `enforce generate trust-policy` - Generate trust policy JSON

### Audit
- `audit verify` - Verify CloudTrail sessions

## Getting Help

- [Troubleshooting Guide](troubleshooting.md) - Common issues and solutions
- [GitHub Issues](https://github.com/byteness/aws-vault/issues) - Report bugs or request features
