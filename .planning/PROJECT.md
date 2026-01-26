# Sentinel

## What This Is

Sentinel is an intent-aware access control layer for AWS credentials, built on top of aws-vault. It evaluates policy rules before issuing credentials, allowing teams to use powerful AWS tooling without handing out unchecked access. Sentinel integrates at the credential boundary via `credential_process` and `exec` commands, making it invisible to downstream tools. Includes approval workflows for sensitive access, break-glass emergency bypass for incident response, self-service tooling for permissions discovery and configuration validation, and server-side credential vending via Lambda TVM where Lambda IS the trust boundary.

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
- ✓ Bootstrap system for automated SSM parameter setup — v1.4
- ✓ Sample policy generation from profile configuration — v1.4
- ✓ IAM policy document generation for least-privilege access — v1.4
- ✓ Bootstrap status command for deployment health checks — v1.4
- ✓ IAM trust policy analysis and enforcement status reporting — v1.5
- ✓ Trust policy template generation (Pattern A/B/C) — v1.5
- ✓ CloudTrail session verification for SourceIdentity compliance — v1.5
- ✓ `sentinel audit verify` command for unmanaged session detection — v1.5
- ✓ Drift detection with --require-sentinel flag — v1.5
- ✓ Enforcement and assurance documentation (ENFORCEMENT.md, ASSURANCE.md) — v1.5
- ✓ Comprehensive test infrastructure with mock framework — v1.6
- ✓ >80% test coverage on all Sentinel packages (94.1% average) — v1.6
- ✓ Security regression test suite for denial path validation — v1.6
- ✓ Performance benchmarks for policy evaluation and identity generation — v1.6
- ✓ Pre-release validation with GO recommendation — v1.6
- ✓ Permission schema mapping features to IAM actions — v1.7
- ✓ `sentinel permissions` CLI with Terraform/CloudFormation output formats — v1.7
- ✓ Feature auto-detection for minimal permission discovery — v1.7
- ✓ `sentinel permissions check` for validating credentials via IAM SimulatePrincipalPolicy — v1.7
- ✓ `sentinel init wizard` for interactive first-time setup — v1.7
- ✓ Structured error types with actionable fix suggestions — v1.7
- ✓ `sentinel config validate` for pre-runtime configuration validation — v1.7
- ✓ Quick start templates (basic, approvals, full) for rapid deployment — v1.7
- ✓ Streamlined onboarding documentation (QUICKSTART.md, PERMISSIONS.md) — v1.7
- ✓ AWS identity-based policy evaluation (STS GetCallerIdentity) — v1.7.1
- ✓ `sentinel whoami` command for identity debugging — v1.7.1
- ✓ Security regression tests for identity extraction — v1.7.1
- ✓ CHANGELOG.md and SECURITY.md with vulnerability advisory — v1.7.1
- ✓ SSO profile resolution for credentials and exec commands via AWS SDK credential provider chain — v1.8
- ✓ Auto SSO login triggering with OIDC device code flow when sessions expire — v1.8
- ✓ All CLI commands support --profile/--aws-profile for SSO credential loading — v1.9
- ✓ Whoami command --profile flag for identity debugging with SSO profiles — v1.9
- ✓ Server mode with per-request policy evaluation via --server flag — v1.10
- ✓ CredentialMode-aware policies (server/cli/credential_process conditions) — v1.10
- ✓ 15-minute default server sessions with MaxServerDuration policy caps — v1.10
- ✓ Session tracking via DynamoDB with create/touch/expire/revoke lifecycle — v1.10
- ✓ Real-time session revocation with fail-closed security — v1.10
- ✓ require_server policy effect for enforcing server mode on sensitive profiles — v1.10
- ✓ `sentinel shell init` command for auto-generating shell wrapper functions — v1.11
- ✓ SSM-based profile discovery from /sentinel/policies/* for shell functions — v1.11
- ✓ Server mode variants with --include-server flag for shell integration — v1.11
- ✓ Bash and zsh tab completion for generated shell functions — v1.11
- ✓ DynamoDB table provisioning for approval workflows via `sentinel init approvals` — v1.12
- ✓ DynamoDB table provisioning for break-glass via `sentinel init breakglass` — v1.12
- ✓ DynamoDB table provisioning for sessions via `sentinel init sessions` — v1.12
- ✓ Unified bootstrap with `--with-approvals`, `--with-breakglass`, `--with-sessions`, `--all` flags — v1.12
- ✓ Enhanced `init status --check-tables` for infrastructure health monitoring — v1.12
- ✓ Graceful degradation for permission-less onboarding (--plan without DynamoDB permissions) — v1.12
- ✓ IAM policy generation via `--generate-iam` flag for all table provisioning commands — v1.12
- ✓ `require_server_session` policy effect for enforcing server mode with session tracking — v1.13
- ✓ `SENTINEL_SESSION_TABLE` environment variable for default session table configuration — v1.13
- ✓ Policy-level `session_table` field for per-profile table override — v1.13
- ✓ `sentinel audit untracked-sessions` command for CloudTrail compliance detection — v1.13
- ✓ `sentinel audit session-compliance` command for per-profile compliance reporting — v1.13
- ✓ CSV export and `--since` filtering for `sentinel server-sessions` audit exports — v1.13
- ✓ Lambda TVM with STS AssumeRole and SourceIdentity stamping — v1.14
- ✓ Policy evaluation on Lambda (trust boundary enforcement) — v1.14
- ✓ Session tracking with session tags for real-time revocation — v1.14
- ✓ API Gateway HTTP API with IAM auth and profile discovery — v1.14
- ✓ `sentinel exec --remote-server <url>` for remote TVM — v1.14
- ✓ SCP patterns to enforce TVM-only access (block direct AssumeRole) — v1.14
- ✓ Terraform module and CDK example for Lambda TVM deployment — v1.14
- ✓ Device posture schema with DeviceID and PostureStatus types — v1.15
- ✓ MDM Provider interface with Jamf Pro implementation for server-side device verification — v1.15
- ✓ Lambda TVM queries MDM APIs on credential requests with fail-open/fail-closed modes — v1.15
- ✓ Policy device conditions (require_mdm, require_encryption, require_mdm_compliant) — v1.15
- ✓ Session device binding with DeviceID field and ListByDeviceID query — v1.15
- ✓ Device audit commands (device-sessions, devices) with anomaly detection — v1.15
- ✓ Timing-safe bearer token comparison via crypto/subtle.ConstantTimeCompare — v1.16
- ✓ AWS Secrets Manager for MDM API token with client-side caching — v1.16
- ✓ CI/CD security scanning with govulncheck, gosec, and Trivy — v1.16
- ✓ DynamoDB KMS encryption by default for all Sentinel tables — v1.16
- ✓ API rate limiting (100 req/min) for Lambda TVM and credential servers — v1.16
- ✓ Error sanitization across all credential endpoints — v1.16
- ✓ Security integration tests for hardening validation — v1.16
- ✓ Policy schema Version type with validation helpers (IsValid, IsCurrent) — v1.17
- ✓ MarshalPolicy YAML serialization for policy export — v1.17
- ✓ `sentinel policy pull <profile>` fetches policy from SSM to stdout or file — v1.17
- ✓ `sentinel policy push <profile> <file>` validates and uploads to SSM with confirmation — v1.17
- ✓ `sentinel policy diff <profile> <file>` shows unified diff with color output — v1.17
- ✓ `sentinel policy validate <file>` validates locally without AWS credentials — v1.17
- ✓ KMS-based policy signing with PolicySigner and RSASSA_PSS_SHA_256 algorithm — v1.18 Phase 126
- ✓ VerifyingLoader for signature-validated policy loading with fail-closed security — v1.18 Phase 126
- ✓ `sentinel policy sign <file>` creates detached KMS signatures — v1.18 Phase 126
- ✓ `sentinel policy verify <file> <signature>` validates signatures locally — v1.18 Phase 126
- ✓ `sentinel policy push --sign` uploads both policy and signature to SSM — v1.18 Phase 126
- ✓ Lambda TVM signature verification integration with SSM → Verifying → Cached pipeline — v1.18 Phase 126
- ✓ Security regression tests for policy tampering and cache poisoning prevention — v1.18 Phase 126
- ✓ Break-glass MFA enforcement (TOTP + SMS) to prevent emergency access abuse — v1.18 Phase 127
- ✓ MFA Verifier interface with timing-safe verification and RFC 6238 compliance — v1.18 Phase 127
- ✓ HMAC-SHA256 signed audit logs with CloudWatch forwarding — v1.18 Phase 128
- ✓ `sentinel audit verify-logs` command for tamper detection — v1.18 Phase 128
- ✓ Unix socket credential servers with process authentication (SO_PEERCRED/LOCAL_PEERCRED) — v1.18 Phase 129
- ✓ AWS ISO and ISO-B partition support in ARN validation — v1.18 Phase 130
- ✓ DynamoDB optimistic locking fix and state transition validation — v1.18 Phase 131
- ✓ Keyring protection hardening (macOS ACLs, Linux keyctl permissions, iCloud sync prevention) — v1.18 Phase 132
- ✓ Distributed rate limiting with DynamoDB atomic counters — v1.18 Phase 133
- ✓ Input validation (profile names, shell escaping, log sanitization) — v1.18 Phase 134
- ✓ Security test infrastructure (153 regression tests, CI workflow, documentation) — v1.18 Phase 135
- ✓ CHANGELOG completion for v1.13-v1.18 releases with accurate ship dates — v1.19 Phase 136
- ✓ Policy CLI documentation (pull, push, diff, validate, sign, verify) in commands.md — v1.19 Phase 137
- ✓ Policy signing guide (POLICY_SIGNING.md) with KMS setup and Lambda TVM integration — v1.19 Phase 138
- ✓ Device posture guide (DEVICE_POSTURE.md) with Jamf Pro MDM setup — v1.19 Phase 139
- ✓ Security hardening guide (SECURITY_HARDENING.md) for v1.16 features — v1.19 Phase 140
- ✓ README feature tables updated through v1.18, example files for device posture and signing — v1.19 Phase 141
- ✓ Deployment guide updated with KMS encryption and v1.17 policy commands — v1.19 Phase 142

### Active

**v2.0 Planning** — Define next milestone goals

Potential focus areas:
- Multi-account support and cross-account credential management
- Web UI for policy management and approval workflows
- Kubernetes integration with credential injection
- Enhanced observability with metrics and dashboards

### Out of Scope
- User management — AWS SSO handles identity
- Authorization inside AWS resources — IAM/SCPs handle that
- Daemon mode — CLI-first, no background process

## Context

Shipped v1.19 with complete documentation for all v1.13-v1.18 features. Added ~5,500 lines of documentation across 4 new guides (POLICY_SIGNING.md, DEVICE_POSTURE.md, SECURITY_HARDENING.md), updated commands.md, CHANGELOG.md, deployment.md, README.md, and Terraform modules.
Tech stack: Go 1.25, aws-sdk-go-v2, aws-vault, kingpin CLI framework, DynamoDB, CloudTrail, IAM SimulatePrincipalPolicy, aws-lambda-go, API Gateway v2.

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

v1.4 adds Sentinel bootstrapping:
- Bootstrap planner to analyze existing SSM parameters
- Automated SSM parameter creation for policy storage
- Sample policy generation based on profile configuration
- IAM policy document generation for least-privilege access
- Status command for deployment health monitoring

v1.5 adds enforcement and assurance:
- IAM trust policy analysis to verify SourceIdentity enforcement
- Trust policy template generation (Pattern A/B/C) for different security postures
- CloudTrail session verification to audit SourceIdentity compliance
- `sentinel audit verify` command for detecting unmanaged sessions
- Drift detection with --require-sentinel flag for credential requests
- Complete enforcement documentation (ENFORCEMENT.md, ASSURANCE.md)

v1.6 adds comprehensive testing and hardening:
- Test infrastructure with mock framework and 80% coverage enforcement
- 94.1% average coverage across all 11 Sentinel packages
- Security regression test suite validating denial paths
- Performance benchmarks (policy eval ~50ns, identity gen ~64ns)
- 1,085 total tests with race detector validation
- Pre-release validation confirming production readiness

v1.7 adds permissions discovery and onboarding:
- Permission schema mapping 10 features to required IAM actions
- `sentinel permissions` CLI with Terraform/CloudFormation/JSON output for IAM policy creation
- Feature auto-detection probing SSM and DynamoDB for minimal permissions
- `sentinel permissions check` validating credentials via IAM SimulatePrincipalPolicy
- `sentinel init wizard` for interactive first-time setup with profile discovery
- Structured error types with 17 error codes and actionable suggestions
- `sentinel config validate` for pre-runtime configuration validation
- Quick start templates for rapid deployment via `sentinel config generate`
- Streamlined onboarding: QUICKSTART.md, PERMISSIONS.md, updated commands.md

v1.7.1 adds critical security fix:
- CRITICAL: Fixed policy evaluation using OS username instead of AWS identity
- AWS identity extraction via STS GetCallerIdentity for all CLI commands
- ARN parsing for all identity types (IAM user, SSO, assumed-role, federated-user, root)
- `sentinel whoami` command for identity debugging
- 1,072 lines of security regression tests
- CHANGELOG.md and SECURITY.md with vulnerability advisory (SENTINEL-2026-001)

v1.8 adds credential flow UX improvements:
- SSO profile resolution from ~/.aws/config for automatic profile detection
- Auto SSO login triggering with OIDC device code flow when sessions expire
- Generic retry wrapper for SSO credential resolution

v1.9 fixes systemic SSO profile support:
- All CLI commands now properly load SSO credentials when --profile is specified
- Added config.WithSharedConfigProfile pattern for AWS SDK integration
- Added --aws-profile flag to approval workflow, break-glass, infrastructure, and audit commands
- Added --profile flag to whoami command for SSO identity debugging

v1.10 adds real-time credential revocation via server mode:
- SentinelServer HTTP server evaluates policy on every credential request
- --server flag for sentinel exec with AWS_CONTAINER_CREDENTIALS_FULL_URI
- CredentialMode type for mode-aware policy rules (server/cli/credential_process)
- 15-minute default sessions with MaxServerDuration policy caps
- Session tracking (DynamoDB) with create/touch/expire/revoke lifecycle
- Real-time revocation with fail-closed security and fail-open availability
- require_server policy effect for enforcing server mode on sensitive profiles

v1.11 adds shell integration for developer UX:
- `sentinel shell init` command with SSM-based profile discovery
- Auto-generated shell wrapper functions (sentinel-{profile}) for one-command AWS access
- Server mode variants with --include-server flag (sentinel-{profile}-server functions)
- Bash and zsh tab completion registrations for all generated functions
- Shell integration documentation in commands.md and QUICKSTART.md

v1.12 adds infrastructure provisioning for self-service setup:
- DynamoDB table provisioning for all three Sentinel workflows (approvals, break-glass, sessions)
- `init approvals`, `init breakglass`, `init sessions` commands with --plan dry-run and --generate-iam IAM policy output
- Unified bootstrap extension with --with-approvals, --with-breakglass, --with-sessions, --all flags
- Enhanced `init status --check-tables` for infrastructure health monitoring
- Graceful degradation: --plan works without DynamoDB permissions, access denied shows UNKNOWN status
- IAM policy generation outputs even after user cancels at confirmation prompt

v1.13 adds enforced session tracking for compliance:
- `require_server_session` policy effect enforces server mode with session tracking
- `SENTINEL_SESSION_TABLE` environment variable for default session table (reduces CLI verbosity)
- Policy-level `session_table` field for per-profile table routing
- `sentinel audit untracked-sessions` detects credential usage bypassing session tracking via CloudTrail
- `sentinel audit session-compliance` shows per-profile compliance against require_server_session policies
- CSV export and `--since` filtering for server-sessions audit reports

v1.14 adds server-side credential vending via Lambda TVM:
- Lambda Token Vending Machine (TVM) with STS AssumeRole and SourceIdentity stamping
- Policy evaluation moved to Lambda trust boundary (clients cannot bypass enforcement)
- Session tracking with DynamoDB and session tags for real-time revocation
- API Gateway HTTP API with IAM auth (SigV4) and profile discovery endpoint (/profiles)
- `sentinel exec --remote-server <url>` for SDK integration via AWS_CONTAINER_CREDENTIALS_FULL_URI
- SCP patterns to enforce TVM-only access (block direct AssumeRole calls)
- Complete Terraform module and CDK TypeScript example for deployment automation
- Security regression tests validating policy bypass prevention
- Migration guide comparing CLI server mode vs Lambda TVM deployment models

v1.15 adds device posture verification:
- Device posture schema with DeviceID (64-char hex) and PostureStatus types
- MDM Provider interface with Jamf Pro implementation for server-side verification
- Lambda TVM queries MDM on credential requests (fail-open default, fail-closed optional)
- Policy device conditions integrate into rule matching (require_mdm, require_encryption)
- Session device binding for forensic correlation and device-based revocation
- Device audit commands (device-sessions, devices) with anomaly detection

v1.16 adds comprehensive security hardening:
- Timing attack mitigation via crypto/subtle.ConstantTimeCompare for bearer token validation
- AWS Secrets Manager integration for MDM API token with 1-hour client-side caching
- CI/CD security scanning with govulncheck, gosec, and Trivy in GitHub Actions
- DynamoDB KMS encryption by default for all Sentinel tables
- API rate limiting with sliding window algorithm (100 req/min)
- Error sanitization across all credential endpoints (log details, return generic messages)
- Security integration tests validating hardening patterns

v1.17 adds policy developer experience:
- Policy schema Version type with IsValid() and IsCurrent() validation methods
- MarshalPolicy for YAML serialization and round-trip policy editing
- `sentinel policy pull <profile>` fetches policy from SSM to stdout or file
- `sentinel policy push <profile> <file>` validates and uploads to SSM with confirmation prompt
- `sentinel policy diff <profile> <file>` shows unified diff with color output (exit 0=same, 1=different)
- `sentinel policy validate <file>` validates locally without AWS credentials

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
| Escalation threshold | Flags for notification only, doesn't block | ✓ Good |
| Empty lists = wildcards | AllowedReasonCodes, Profiles: empty = all allowed | ✓ Good |
| Break-glass policy integration | Check after profile validation, before rate limit | ✓ Good |
| Bootstrap ResourceState | 'exists' and 'skip' as separate states for clarity | ✓ Good |
| SSM String type | Not SecureString since policy YAML is not sensitive | ✓ Good |
| ssmAPI interface pattern | Follows notification/sns.go pattern for testability | ✓ Good |
| EnforcementStatus levels | Full/Partial/None with clear definitions | ✓ Good |
| Trust policy Pattern A/B/C | Different SourceIdentity strictness levels | ✓ Good |
| CloudTrail pass rate metric | 100% for zero sessions (no issues is success) | ✓ Good |
| Drift detection advisory-only | Warnings logged but credentials still issued | ✓ Good |
| Three-level assurance model | Deployment, runtime, continuous verification | ✓ Good |
| 8 subsystems, 10 features | Complete permission coverage for all Sentinel capabilities | ✓ Good |
| Terraform aws_iam_policy_document format | Most common Terraform pattern for IAM policies | ✓ Good |
| Always-detected features | credential_issue, audit_verify, enforce_analyze (universal) | ✓ Good |
| SimulatePrincipalPolicy for validation | Checks actual IAM permissions without credential scope | ✓ Good |
| Wizard as subcommand | Kingpin limitation with parent command default actions | ✓ Good |
| SentinelError interface | Unwrap() for error chain compatibility (errors.Is/errors.As) | ✓ Good |
| Error string matching | Reliable AWS error detection across SDK versions | ✓ Good |
| Warnings don't fail validation | Valid with warnings returns exit 0 for CI friendliness | ✓ Good |
| Config type auto-detection | Check distinctive fields in first rule to determine type | ✓ Good |
| No explicit default-deny in templates | Policy engine already denies on no match | ✓ Good |
| STSAPI interface for identity extraction | Enables mock injection for unit tests without AWS credentials | ✓ Good |
| Username from AWS ARN, not OS user | Prevents policy bypass via local user impersonation | ✓ Good |
| TestSecurityRegression_ prefix | CI/CD filtering of security tests | ✓ Good |
| Attack scenario demonstration tests | Explicitly show vulnerability and verify fix | ✓ Good |
| Shell function sentinel-{profile} naming | Clear namespace, sanitized for shell safety | ✓ Good |
| Server variants with -server suffix | Distinct names for server mode, user can choose | ✓ Good |
| Same bash/zsh output | POSIX-compatible functions work in both shells | ✓ Good |
| Script to stdout, status to stderr | eval-compatible output for shell rc integration | ✓ Good |
| Shell detection via $SHELL | Auto-detect format, explicit --format override available | ✓ Good |
| Completion via -o default -o bashdefault (bash) | Standard fallback for file/command completion | ✓ Good |
| Completion via compdef _command_names (zsh) | Standard zsh completion approach | ✓ Good |
| Dual-condition effect (server + session) | require_server_session needs both flags | ✓ Good |
| Env var only in server mode | SENTINEL_SESSION_TABLE only applies with --server | ✓ Good |
| Policy override for session_table | Policy is source of truth over CLI/env | ✓ Good |
| Scan for GetBySourceIdentity | Acceptable for infrequent audit queries | ✓ Good |
| Non-zero exit for compliance gaps | CI/CD integration for audit commands | ✓ Good |
| UntrackedCategory enum | Clear classification of untracked session types | ✓ Good |
| aws-lambda-go v1.47.0 | Latest stable version for Lambda handler types | ✓ Good |
| AWS container credentials format | SDK compatibility via AccessKeyId, SecretAccessKey, Token, Expiration | ✓ Good |
| Lambda handler (response, error) returns | All paths return tuple for consistent error handling | ✓ Good |
| TVMConfig environment loading | Configuration via environment variables for Lambda | ✓ Good |
| Router POST / and GET /profiles | Credential vending and profile discovery endpoints | ✓ Good |
| ARM64 architecture for Lambda | Graviton2 cost optimization | ✓ Good |
| SentinelProtected- role prefix | TVM policy matching pattern for protected roles | ✓ Good |
| Trust policy requires TVM principal + SourceIdentity | Dual condition for protected role security | ✓ Good |
| Security tests use SECURITY VIOLATION markers | Explicit failure identification in test output | ✓ Good |
| Gradual rollout strategy | 4-phase migration from CLI server to Lambda TVM | ✓ Good |
| DeviceID 64-char hex format | HMAC-SHA256 via machineid for cross-platform device fingerprinting | ✓ Good |
| Pointer bools for device posture | Distinguishes not checked (nil) from checked and false | ✓ Good |
| Fail-open MDM by default | RequireDevicePosture=false allows rollout before MDM enforcement | ✓ Good |
| Device conditions affect rule matching | Rule doesn't match if posture fails (first-match-wins preserved) | ✓ Good |
| Nil posture fails device conditions | Security: no posture data = rule doesn't match | ✓ Good |
| Device ID as query parameter | Simple API design (?device_id=...) for MDM lookup | ✓ Good |
| Device-bound session logging | Log device_bound=true flag rather than actual ID for privacy | ✓ Good |
| Anomaly detection thresholds | MULTI_USER at >1 user, HIGH_PROFILE_COUNT at >5 profiles | ✓ Good |
| crypto/subtle.ConstantTimeCompare for bearer tokens | Prevent timing attacks on token comparison | ✓ Good |
| AWS Secrets Manager with 1-hour cache TTL | Optimized for Lambda cold start patterns | ✓ Good |
| Sliding window rate limiting | Simpler than token bucket for request-response | ✓ Good |
| Rate limit by IAM ARN, not IP | IAM auth identifies caller, avoids NAT issues | ✓ Good |
| Fail-open on rate limiter errors | Availability preferred over strict limiting | ✓ Good |
| Error sanitization pattern | Log details internally, return generic messages | ✓ Good |
| AWS managed KMS encryption | Simpler than customer CMK, no key management | ✓ Good |
| Version as type alias (type Version string) | YAML serialization compatibility with existing policies | ✓ Good |
| SupportedVersions as slice | Future extensibility when schema evolves | ✓ Good |
| ValidatePolicy distinguishes parse vs validation errors | Better CLI UX with actionable error messages | ✓ Good |
| Extended SSMAPI interface with PutParameter | Unified read/write interface for testing | ✓ Good |
| ParameterTypeString (not SecureString) | Policy YAML is not sensitive, matches bootstrap pattern | ✓ Good |
| Confirmation prompt with --force bypass | Safety default with automation support | ✓ Good |
| Exit code 0=no changes, 1=changes for diff | Scripting-friendly exit codes | ✓ Good |
| Normalize policies via parse/marshal before diff | Avoid false positives from formatting differences | ✓ Good |
| LCS algorithm for unified diff | Standard unified diff format with @@ markers | ✓ Good |
| Color output default with --no-color flag | Terminal readability with pipe compatibility | ✓ Good |

v1.18 adds comprehensive security hardening:
- KMS-based policy signing prevents cache poisoning (VerifyingLoader with fail-closed security)
- Break-glass MFA enforcement (TOTP + SMS) prevents emergency access abuse
- HMAC-SHA256 signed audit logs with CloudWatch forwarding for tamper detection
- Unix socket credential servers with process authentication prevent local credential theft
- DynamoDB optimistic locking fix and state transition validation prevent state manipulation
- Keyring protection hardening (macOS ACLs, Linux keyctl permissions) prevents credential theft
- Distributed rate limiting with DynamoDB atomic counters prevents bypass across Lambda instances
- Input validation (profile names, shell escaping) prevents command injection
- 153 security regression tests across 13 packages with CI enforcement

---
*Last updated: 2026-01-26 after v1.19 milestone*
