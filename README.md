# Sentinel

Policy-based credential gateway for AWS. Know not just *what* happened, but *why* it was allowed.

## The Problem

CloudTrail tells you Alice deleted the prod database at 2am. She's a senior dev - she's *supposed* to have access. But CloudTrail doesn't tell you:
- What was the business justification?
- Did she follow proper process or bypass controls?
- Was this an emergency, or did she fat-finger prod instead of dev?

**[Read the full story &rarr;](docs/WHY.md)**

## Quick Start

```bash
# Install
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest

# Bootstrap policy in SSM
sentinel init bootstrap --aws-profile dev --profile dev --plan
sentinel init bootstrap --aws-profile dev --profile dev

# Use it
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev \
  -- aws sts get-caller-identity

# Or with server mode (real-time revocation)
sentinel exec --server --profile dev --policy-parameter /sentinel/policies/dev \
  -- terraform apply
```

## How It Works

```
Request access --> Sentinel evaluates policy --> Credentials issued (or denied)
                                                        |
                                                        v
                                    SourceIdentity stamped: sentinel:alice:a1b2c3d4
                                                        |
                                                        v
                                           CloudTrail shows WHO + WHY
```

Every credential issued through Sentinel is stamped with a `SourceIdentity` that appears in CloudTrail. Combined with Sentinel's decision logs, you get complete audit trails.

## Features

### Core

| Feature | Description |
|---------|-------------|
| **Policy evaluation** | Allow, deny, or require approval based on user, profile, time windows |
| **SourceIdentity stamping** | Every session traceable to specific request |
| **Time-based access** | Restrict access by day of week and hour (e.g., business hours only) |
| **SSO integration** | Full AWS IAM Identity Center support with auto-login |

### Access Control

| Feature | Description |
|---------|-------------|
| **Approval workflows** | Require human approval for sensitive access |
| **Break-glass access** | Emergency bypass with mandatory justification and rate limiting |
| **Trust policy enforcement** | AWS rejects bypass attempts via IAM conditions |
| **SCP enforcement** | Dangerous actions require Sentinel org-wide |

### Real-time Revocation (Server Mode)

| Feature | Description |
|---------|-------------|
| **Server mode** | `--server` flag for per-request policy evaluation |
| **Instant revocation** | Change policy or revoke session, next request denied |
| **Session tracking** | Track active sessions in DynamoDB |
| **require_server effect** | Force server mode for sensitive profiles |

```bash
# Long-running process with revocation capability
sentinel exec --server --session-table sentinel-sessions \
  --profile prod --policy-parameter /sentinel/policies/prod \
  -- terraform apply

# Revoke a session instantly
sentinel server-revoke SESSION_ID --reason "Suspicious activity" \
  --table sentinel-sessions --region us-east-1
```

### Operations & Onboarding

| Feature | Description |
|---------|-------------|
| **Bootstrap commands** | `sentinel init bootstrap` creates SSM parameters |
| **Init wizard** | `sentinel init wizard` for interactive setup |
| **Permissions discovery** | `sentinel permissions` shows required IAM with Terraform/CloudFormation output |
| **Permission validation** | `sentinel permissions check` validates your credentials |
| **Config validation** | `sentinel config validate` checks policy YAML before deploy |
| **Quick start templates** | `sentinel config generate` creates starter policies |
| **Audit verify** | `sentinel audit verify` checks CloudTrail for non-Sentinel sessions |
| **Identity debugging** | `sentinel whoami` shows your AWS identity and policy username |

## Example Policy

```yaml
version: "1"
rules:
  # Developers get dev access anytime
  - name: dev-allow
    effect: allow
    conditions:
      profiles: [dev, staging]
    reason: Development access

  # AI agents only during business hours
  - name: ai-business-hours
    effect: allow
    conditions:
      profiles: [ai-readonly]
      time:
        days: [monday, tuesday, wednesday, thursday, friday]
        hours:
          start: "09:00"
          end: "17:00"
        timezone: America/New_York
    reason: AI access during business hours only

  # Production requires server mode (instant revocation)
  - name: prod-server-only
    effect: require_server
    conditions:
      profiles: [prod]
    reason: Production requires server mode

  # Everything else needs approval
  - name: default-approval
    effect: require_approval
    conditions: {}
    reason: Requires approval
```

## Documentation

| Guide | Description |
|-------|-------------|
| **[Why Sentinel?](docs/WHY.md)** | The problem we're solving and how |
| [Quick Start](docs/QUICKSTART.md) | 5-minute setup guide |
| [Getting Started](docs/guide/getting-started.md) | Installation and first policy |
| [CLI Reference](docs/guide/commands.md) | All commands documented |
| [Policy Reference](docs/guide/policy-reference.md) | Full YAML schema |
| [Permissions](docs/PERMISSIONS.md) | IAM permissions matrix |
| [Approval Workflows](docs/guide/approval-workflows.md) | Request/approve flow |
| [Break-Glass Access](docs/guide/break-glass.md) | Emergency access |
| [Enforcement Patterns](docs/ENFORCEMENT.md) | Trust policies and SCPs |
| [Troubleshooting](docs/guide/troubleshooting.md) | Common issues and fixes |

## Built On

Sentinel extends [aws-vault](https://github.com/99designs/aws-vault), adding policy evaluation while inheriting:
- Secure credential storage via system keyring
- AWS SSO integration
- Session caching with expiration
- Cross-platform support (macOS, Linux, Windows)

Supported credential stores:
* [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac)
* [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
* Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
* [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
* [Pass](https://www.passwordstore.org/)
* [Passage](https://github.com/FiloSottile/passage)
* Encrypted file
* [1Password Connect](https://developer.1password.com/docs/connect/)
* [1Password Service Accounts](https://developer.1password.com/docs/service-accounts)

## Requirements

- Go 1.21+ (for building from source)
- AWS account with SSM Parameter Store access
- AWS credentials (SSO, IAM user, or instance role)

## Limitations

- **Console access** is not controlled by Sentinel. Use trust policies requiring SourceIdentity to block console from sensitive roles.
- **Standard exec/credentials mode** issues credentials valid until expiry. Use server mode (`--server`) for instant revocation capability.

## License

MIT

---

**The problem:** CloudTrail shows what happened.
**The solution:** Sentinel shows why it was allowed.
