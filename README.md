# Sentinel

![alt text](image.png)

## What This Is

Sentinel is an intent-aware access control layer for AWS credentials, built on top of aws-vault. It evaluates policy rules before issuing credentials, allowing teams to use powerful AWS tooling without handing out unchecked access. Sentinel integrates at the credential boundary via `credential_process` and `exec` commands, making it invisible to downstream tools. Includes approval workflows for sensitive access and break-glass emergency bypass for incident response.

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
- ✓ SourceIdentity stamping on all role assumptions — v1.1
- ✓ CloudTrail correlation via request-id in decision logs — v1.1
- ✓ IAM trust policy enforcement patterns documented — v1.1
- ✓ SCP enforcement patterns for organization-wide control — v1.1
- ✓ Approval request/approve workflow with DynamoDB state machine — v1.2
- ✓ SNS and Webhook notification hooks for request lifecycle events — v1.2
- ✓ Approval policies with auto-approve conditions and approver routing — v1.2
- ✓ Approval audit trail logging for compliance — v1.2
- ✓ CLI commands: request, list, check, approve, deny — v1.2
- ✓ Break-glass emergency access with mandatory justification — v1.3
- ✓ Time-bounded break-glass sessions with automatic duration capping — v1.3
- ✓ Break-glass rate limiting with cooldowns and quotas — v1.3
- ✓ Break-glass notifications for immediate security awareness — v1.3
- ✓ Break-glass policies for authorization control — v1.3
- ✓ Post-incident review commands: breakglass-list, breakglass-check, breakglass-close — v1.3
- ✓ Enforcement analyzer for trust policy verification — v1.5
- ✓ Trust policy generation for enforcement patterns A/B/C — v1.5
- ✓ CloudTrail session verification with audit command — v1.5
- ✓ Drift detection with --require-sentinel flag — v1.5

### Active

(None — all v1.5 requirements validated)

### Out of Scope
- User management — AWS SSO handles identity
- Authorization inside AWS resources — IAM/SCPs handle that
- Daemon mode — CLI-first, no background process

## Context

Shipped v1.5 with 49,588 LOC Go.
Tech stack: Go 1.25, aws-sdk-go-v2, aws-vault, kingpin CLI framework, DynamoDB.

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

v1.1 added credential provenance via Sentinel Fingerprint:
- SourceIdentity stamping (sentinel:<user>:<request-id>) on all role assumptions
- Two-hop credential flow: aws-vault base creds → SentinelAssumeRole → fingerprinted credentials
- CloudTrail correlation via request-id matching between Sentinel logs and AWS events
- Optional IAM enforcement via trust policies and SCPs

v1.2 adds approval workflows:
- Request/approve flow with DynamoDB state machine (pending → approved/denied/expired/cancelled)
- SNS and Webhook notification hooks for request lifecycle events
- Approval policies with auto-approve conditions and profile-based approver routing
- Approval audit trail logging parallel to decision logging
- CLI commands: request, list, check, approve, deny

v1.3 adds break-glass emergency access:
- Emergency bypass when policy denies access with mandatory justification
- Time-bounded sessions with automatic duration capping
- Rate limiting with cooldowns, per-user/per-profile quotas, and escalation thresholds
- Immediate SNS/Webhook notifications for security team awareness
- Post-incident review commands for auditing and closing events
- Break-glass policies for controlling who can invoke emergency access

v1.5 adds enforcement and assurance:
- Trust policy analyzer with enforcement status (Full/Partial/None)
- Trust policy generator for patterns A/B/C
- CloudTrail session verifier for compliance auditing
- Drift detection at credential time with --require-sentinel flag

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
| SourceIdentity format sentinel:<user>:<request-id> | Unique per-request correlation, fits AWS 64-char limit | ✓ Good |
| Two-hop credential flow | Enables SourceIdentity stamping on all role assumptions | ✓ Good |
| Crypto/rand for request-id | Security-first entropy for correlation IDs | ✓ Good |
| User sanitization at call time | Allows raw user storage, sanitizes for AWS constraints | ✓ Good |
| omitempty for new log fields | Backward compatibility with existing log consumers | ✓ Good |
| DynamoDB single-table design | GSIs for flexible query patterns, TTL for expiration | ✓ Good |
| Request state machine | Finite states (pending/approved/denied/expired/cancelled) with clear transitions | ✓ Good |
| Notifier interface | Common interface for SNS/Webhook, NotifyStore wrapper | ✓ Good |
| EffectRequireApproval policy effect | Extends existing policy schema, triggers approval flow | ✓ Good |
| Auto-approve conditions | User lists, time windows, max duration for self-service | ✓ Good |
| Profile-based approver routing | Specific approvers per profile pattern | ✓ Good |
| Approval audit trail | Parallel to decision logging, same JSON Lines format | ✓ Good |
| Break-glass state machine | active → closed/expired (no pending - immediate access) | ✓ Good |
| 4-hour max break-glass TTL | Shorter than approval (incidents need brief access) | ✓ Good |
| Five reason codes | incident, maintenance, security, recovery, other for categorization | ✓ Good |
| Access stacking prevention | FindActiveByInvokerAndProfile rejects duplicates | ✓ Good |
| Elevated audit logging | Separate BreakGlassLogEntry with all incident fields | ✓ Good |
| Duration capping | Automatic cap to remaining break-glass time | ✓ Good |
| Best-effort notifications | Errors logged but don't fail break-glass command | ✓ Good |
| Rate limit check order | cooldown → user quota → profile quota → escalation flag | ✓ Good |
| Escalation threshold | Flags for notification only, doesn't block                                                                 | ✓ Good |
| Empty lists = wildcards | AllowedReasonCodes, Profiles: empty = all allowed | ✓ Good |
| Break-glass policy integration | Check after profile validation, before rate limit | ✓ Good |                         
          
---
*Last updated: 2026-01-16 after v1.5 milestone*
                                                                                                                           `                         