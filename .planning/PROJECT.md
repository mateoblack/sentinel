# Sentinel

![alt text](image.png)

## What This Is

Sentinel is an intent-aware access control layer for AWS credentials, built on top of aws-vault. It evaluates policy rules before issuing credentials, allowing teams to use powerful AWS tooling without handing out unchecked access. Sentinel integrates at the credential boundary via `credential_process` and `exec` commands, making it invisible to downstream tools.

## Core Value

Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.

## Requirements

### Validated

- ✓ Secure credential storage via system keyring — existing (aws-vault)
- ✓ AWS SSO integration — existing (aws-vault)
- ✓ Session caching with expiration — existing (aws-vault)
- ✓ EC2/ECS metadata server emulation — existing (aws-vault)
- ✓ Cross-platform support (macOS, Linux, Windows) — existing (aws-vault)
- ✓ Policy evaluation before credential issuance — v1.0
- ✓ AWS-native policy store (SSM Parameter Store) — v1.0
- ✓ `credential_process` integration (`sentinel credentials --profile X`) — v1.0
- ✓ Decision logging (user, profile, allow/deny, rule matched) — v1.0
- ✓ `sentinel exec` command for direct invocation — v1.0
- ✓ Compatibility with existing aws-vault profiles — v1.0

### Active

(None — all v1.0 requirements validated)

### Out of Scope

- Approval workflows — deferred (requires DynamoDB + notification integration)
- Break-glass mode — deferred (standard access only for v1)
- User management — AWS SSO handles identity
- Authorization inside AWS resources — IAM/SCPs handle that
- Daemon mode — CLI-first, no background process

## Context

Shipped v1.0 with 10,762 LOC Go.
Tech stack: Go 1.25, aws-sdk-go-v2, aws-vault, kingpin CLI framework.

Built on aws-vault, a battle-tested credential management CLI. The existing codebase provides:
- Credential storage abstraction (keyring backends)
- AWS SDK v2 integration
- Provider chain pattern for credential resolution
- Local metadata servers for SDK compatibility

Sentinel adds the policy evaluation "brain" with:
- YAML policy schema with time windows and conditions
- SSM Parameter Store integration for centralized policy
- First-match-wins rule evaluation with default deny
- Structured JSON Lines logging for audit trails

Target users: Platform engineers and security teams who need guardrails without slowing developers down.

## Constraints

- **Existing profiles**: Must work with existing `~/.aws/config` without requiring profile changes
- **CLI-first**: No daemon, no background process, simple invocation model
- **AWS-native policy**: Policies stored in SSM Parameter Store (already exists in most orgs)
- **Go**: Building on existing aws-vault codebase (Go 1.25)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Build on aws-vault | Battle-tested credential plumbing, focus on policy layer | ✓ Good |
| Policy in SSM | Centralized, versioned, IAM-protected, already deployed | ✓ Good |
| credential_process first | Invisible to tools, proves full integration | ✓ Good |
| Use kingpin (not cobra) | Match existing aws-vault codebase patterns | ✓ Good |
| String type aliases for Effect/Weekday | Type safety with IsValid() validation methods | ✓ Good |
| Hour range [start, end) semantics | Inclusive start, exclusive end for intuitive business hours | ✓ Good |
| Empty list = wildcard matching | Enable rules like "any user on staging profile" | ✓ Good |
| Default deny on no match | Security-first approach | ✓ Good |
| 5-minute cache TTL | Balance API calls vs freshness | ✓ Good |
| JSON Lines logging format | Log aggregation compatibility | ✓ Good |

---
*Last updated: 2026-01-14 after v1.0 milestone*
