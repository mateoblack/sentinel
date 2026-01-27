# Sentinel

[![Security Tests](https://img.shields.io/github/actions/workflow/status/mateoblack/sentinel/test-security.yml?branch=main)](https://github.com/mateoblack/sentinel/actions/workflows/test-security.yml)
[![Gosec](https://img.shields.io/github/actions/workflow/status/mateoblack/sentinel/goseccheck.yml?branch=main&label=gosec)](https://github.com/mateoblack/sentinel/actions/workflows/goseccheck.yml)
[![Vulnerability Check](https://img.shields.io/github/actions/workflow/status/mateoblack/sentinel/govulncheck.yml?branch=main&label=govulncheck)](https://github.com/mateoblack/sentinel/actions/workflows/govulncheck.yml)

> **v2.1** - TVM-only mode. Server-verified security.

Policy-based credential gateway for AWS. Know not just *what* happened, but *why* it was allowed.

> **Sentinel v2.1+ requires Lambda TVM for verified security.** The Lambda isn't overhead - it's where the intelligence lives. Client-side credential handling is fakeable; server-side (TVM) is verified. We don't ship fakeable security. See [Migration Guide](docs/TVM_MIGRATION.md) for upgrading from v2.0.

## The Problem

CloudTrail tells you Alice deleted the prod database at 2am. She's a senior dev - she's *supposed* to have access. But CloudTrail doesn't tell you:
- What was the business justification?
- Did she follow proper process or bypass controls?
- Was this an emergency, or did she fat-finger prod instead of dev?

**[Read the full story &rarr;](docs/WHY.md)**

## Installation

### Via Go Install (Recommended)
```bash
go install github.com/byteness/aws-vault/v7/cmd/sentinel@latest
```

Make sure `~/go/bin` is in your PATH:
```bash
# Add to ~/.zshrc or ~/.bashrc
export PATH="$HOME/go/bin:$PATH"
```

### Via Homebrew (Coming Soon)
```bash
brew install byteness/tap/sentinel
```

### Manual Build
```bash
git clone https://github.com/mateoblack/sentinel
cd sentinel
go build -o sentinel .
sudo mv sentinel /usr/local/bin/  # Or: cp sentinel ~/bin/
```

### Download Pre-built Binary
Download from [Releases](https://github.com/mateoblack/sentinel/releases) and add to your PATH.

## Quick Start

**Prerequisites:**
1. Install Sentinel (see [Installation](#installation) above)
2. Deploy Lambda TVM (see [Lambda TVM Deployment](docs/LAMBDA_TVM_DEPLOYMENT.md))

```bash
# 1. Deploy Lambda TVM (one-time setup)
cd terraform/sentinel-tvm
terraform init && terraform apply -var="region=us-east-1"
export SENTINEL_TVM_URL=$(terraform output -raw api_gateway_url)

# 2. Create a policy (see docs/examples/policy-getting-started.yaml)
cat > my-policy.yaml <<EOF
version: "1"
rules:
  - name: dev-access
    effect: allow
    conditions:
      profiles: [dev]
    reason: Development access
EOF

# 3. Validate and push your policy
sentinel policy validate my-policy.yaml
sentinel init bootstrap --aws-profile my-admin --profile dev

# 4. Use it with TVM
sentinel exec --remote-server "$SENTINEL_TVM_URL" dev -- aws sts get-caller-identity
```

**Want more features?** Add them progressively:
- `--with-approvals` → Enable request/approval workflow
- `--with-sessions` → Enable real-time session revocation
- `--with-breakglass` → Enable emergency access tracking
- `--with-all` → Enable all features

See [docs/examples/](docs/examples/) for policy examples.

## How It Works

```
Client request --> Lambda TVM --> Policy evaluation --> Credentials issued (or denied)
                      |                  |
                      v                  v
            Device posture check    Server-verified policy
                      |                  |
                      v                  v
            SourceIdentity stamped: sentinel:alice:direct:a1b2c3d4
                                         |
                                         v
                              CloudTrail shows WHO + WHY
```

Every credential issued through Sentinel's Lambda TVM is stamped with a `SourceIdentity` that appears in CloudTrail. Policy evaluation happens server-side where it cannot be bypassed. Combined with Sentinel's decision logs, you get complete audit trails.

## Features

### Core

| Feature | Description |
|---------|-------------|
| **Policy evaluation** | Allow, deny, or require approval based on user, profile, time windows |
| **SourceIdentity stamping** | Every session traceable to specific request |
| **Time-based access** | Restrict access by day of week and hour (e.g., business hours only) |
| **SSO integration** | Full AWS IAM Identity Center support with auto-login |
| **Lambda TVM** | Server-side credential vending via Lambda (trust boundary enforcement) |

### Access Control

| Feature | Description |
|---------|-------------|
| **Approval workflows** | Require human approval for sensitive access |
| **Break-glass access** | Emergency bypass with mandatory justification and rate limiting |
| **Device posture verification** | Verify device security state (MDM enrollment, disk encryption) before issuing credentials |
| **Policy signing** | KMS-based cryptographic policy integrity verification |
| **Trust policy enforcement** | AWS rejects bypass attempts via IAM conditions |
| **SCP enforcement** | Dangerous actions require Sentinel org-wide |

### Lambda TVM (Server-Side Credential Vending)

| Feature | Description |
|---------|-------------|
| **Server-side policy** | Policy evaluation happens in Lambda, not on client |
| **Instant revocation** | Change policy or revoke session, next request denied |
| **Session tracking** | Track active sessions in DynamoDB |
| **Device posture verification** | MDM checks enforced server-side |
| **Trust boundary enforcement** | Clients cannot bypass policy |

```bash
# Use Lambda TVM for credential vending
sentinel exec --remote-server "$SENTINEL_TVM_URL" prod -- terraform apply

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
| **Policy management** | `sentinel policy pull/push/diff/validate/sign/verify` for policy lifecycle |
| **Audit verify** | `sentinel audit verify` checks CloudTrail for non-Sentinel sessions |
| **Identity debugging** | `sentinel whoami` shows your AWS identity and policy username |
| **Lambda TVM** | Terraform module and CDK example for Lambda TVM deployment |
| **TVM Migration** | Migration guide from classic mode to TVM-only |

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
| [Policy Signing](docs/POLICY_SIGNING.md) | KMS-based policy integrity |
| [Device Posture](docs/DEVICE_POSTURE.md) | MDM integration and device verification |
| [Security Hardening](docs/SECURITY_HARDENING.md) | Timing attacks, rate limiting, encryption |
| [TVM Migration](docs/TVM_MIGRATION.md) | Upgrading from v2.0 to TVM-only mode |
| [Troubleshooting](docs/guide/troubleshooting.md) | Common issues and fixes |

## Built On

Sentinel is a fork of [aws-vault](https://github.com/99designs/aws-vault) by 99designs. It adds policy evaluation, approval workflows, and session tracking while inheriting aws-vault's battle-tested credential management:

- Secure credential storage via system keyring
- AWS SSO integration
- Session caching with expiration
- Cross-platform support (macOS, Linux, Windows)

**Upstream:** Based on aws-vault v7.x

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
- **Lambda TVM required** (v2.1+): Client-side credential handling was removed because it's fakeable. All credential vending now requires Lambda TVM deployment.

## License

MIT - See [LICENSE](LICENSE) for details.

Sentinel is a fork of [aws-vault](https://github.com/99designs/aws-vault) by 99designs, also MIT licensed.

---

**The problem:** CloudTrail shows what happened.
**The solution:** Sentinel shows why it was allowed.
