# Sentinel

Policy-based credential gateway for AWS. Know not just *what* happened, but *why* it was allowed.

![Sentinel](image.png)

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
sentinel init bootstrap --profile dev --plan
sentinel init bootstrap --profile dev

# Use it
sentinel exec --profile dev --policy-parameter /sentinel/policies/dev \
  -- aws sts get-caller-identity
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

| Feature | Description |
|---------|-------------|
| **Policy evaluation** | Allow, deny, or require approval based on user, profile, time windows |
| **SourceIdentity stamping** | Every session traceable to specific request |
| **Approval workflows** | Require human approval for sensitive access |
| **Break-glass access** | Emergency bypass with mandatory justification |
| **Trust policy enforcement** | AWS rejects bypass attempts |
| **SCP enforcement** | Dangerous actions require Sentinel org-wide |

## Example Policy

```yaml
version: "1"
rules:
  - name: dev-allow
    effect: allow
    conditions:
      profiles: [dev, staging]
    reason: Development access

  - name: prod-approval
    effect: require_approval
    conditions:
      profiles: [prod]
    reason: Production requires approval

  - name: default-deny
    effect: deny
    conditions: {}
    reason: No matching rule
```

## Documentation

| Guide | Description |
|-------|-------------|
| **[Why Sentinel?](docs/WHY.md)** | The problem we're solving and how |
| [Getting Started](docs/guide/getting-started.md) | Installation and first policy |
| [CLI Reference](docs/guide/commands.md) | All 17 commands documented |
| [Policy Reference](docs/guide/policy-reference.md) | Full YAML schema |
| [Approval Workflows](docs/guide/approval-workflows.md) | Request/approve flow |
| [Break-Glass Access](docs/guide/break-glass.md) | Emergency access |
| [Enforcement Patterns](docs/ENFORCEMENT.md) | Trust policies and SCPs |

## Built On

Sentinel extends [aws-vault](https://github.com/99designs/aws-vault), adding policy evaluation while inheriting:
- Secure credential storage via system keyring
- AWS SSO integration
- Session caching with expiration
- Cross-platform support (macOS, Linux, Windows)

## Requirements

- Go 1.21+ (for building from source)
- AWS account with SSM Parameter Store access
- AWS credentials (SSO, IAM user, or instance role)

## Limitations

- **Session duration** is bounded by AWS role limits, not policy. Policy-level `max_duration` planned for v1.8.
- **Console access** is not controlled by Sentinel. Use trust policies requiring SourceIdentity to block console from sensitive roles.
- **Session revocation** not yet supported. Credentials are valid until expiry (default 1h, break-glass max 4h).

## License

MIT

---

**The problem:** CloudTrail shows what happened.
**The solution:** Sentinel shows why it was allowed.
