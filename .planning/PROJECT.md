# Sentinel

## What This Is

Sentinel is an intent-aware access control layer for AWS credentials, built on top of aws-vault. It evaluates policy rules before issuing credentials, allowing teams to use powerful AWS tooling without handing out unchecked access. Sentinel integrates at the credential boundary via `credential_process`, making it invisible to downstream tools.

## Core Value

Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.

## Requirements

### Validated

- ✓ Secure credential storage via system keyring — existing (aws-vault)
- ✓ AWS SSO integration — existing (aws-vault)
- ✓ Session caching with expiration — existing (aws-vault)
- ✓ EC2/ECS metadata server emulation — existing (aws-vault)
- ✓ Cross-platform support (macOS, Linux, Windows) — existing (aws-vault)

### Active

- [ ] Policy evaluation before credential issuance
- [ ] AWS-native policy store (SSM Parameter Store or S3)
- [ ] `credential_process` integration (`sentinel credentials --profile X`)
- [ ] Decision logging (user, profile, allow/deny, rule matched)
- [ ] `sentinel exec` command for direct invocation
- [ ] Compatibility with existing aws-vault profiles

### Out of Scope

- Approval workflows — deferred (requires DynamoDB + notification integration)
- Break-glass mode — deferred (standard access only for v1)
- User management — AWS SSO handles identity
- Authorization inside AWS resources — IAM/SCPs handle that
- Daemon mode — CLI-first, no background process

## Context

Building on aws-vault, a battle-tested credential management CLI. The existing codebase provides:
- Credential storage abstraction (keyring backends)
- AWS SDK v2 integration
- Provider chain pattern for credential resolution
- Local metadata servers for SDK compatibility

Sentinel adds the "brain" — policy evaluation before credentials are issued.

Target users: Platform engineers and security teams who need guardrails without slowing developers down.

## Constraints

- **Existing profiles**: Must work with existing `~/.aws/config` without requiring profile changes
- **CLI-first**: No daemon, no background process, simple invocation model
- **AWS-native policy**: Policies stored in SSM Parameter Store (already exists in most orgs)
- **Go**: Building on existing aws-vault codebase (Go 1.25)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Build on aws-vault | Battle-tested credential plumbing, focus on policy layer | — Pending |
| Policy in SSM | Centralized, versioned, IAM-protected, already deployed | — Pending |
| credential_process first | Invisible to tools, proves full integration | — Pending |

---
*Last updated: 2026-01-13 after initialization*
