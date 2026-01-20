# Project Milestones: Sentinel

## v1.11 Shell Integration (Shipped: 2026-01-20)

**Delivered:** Developer UX improvement with `sentinel shell init` command that auto-generates shell wrapper functions for all configured Sentinel profiles, reducing daily boilerplate.

**Phases completed:** 84-87 (4 plans total)

**Key accomplishments:**
- `sentinel shell init` command with SSM-based profile discovery from /sentinel/policies/*
- Auto-generated shell wrapper functions (sentinel-{profile}) for one-command AWS access
- Server mode variants with --include-server flag (-server suffix functions for real-time revocation)
- Bash and zsh tab completion registrations for all generated functions
- Shell integration documentation in commands.md and QUICKSTART.md

**Stats:**
- 17 files created/modified
- 101,101 lines of Go (total codebase, +1,380 from v1.10)
- 4 phases, 4 plans
- 1 day (2026-01-20)

**Git range:** `feat(84-01)` → `docs(87-01)`

**What's next:** Production deployment ready. Consider v2.0 for UI dashboard, multi-account federation, or policy versioning.

---

## v1.10 Real-time Revocation (Shipped: 2026-01-20)

**Delivered:** Server mode enabling instant credential revocation - each credential request evaluates policy in real-time, allowing immediate blocking when sessions are revoked or policies change.

**Phases completed:** 78-83 (15 plans total)

**Key accomplishments:**
- SentinelServer HTTP server with policy evaluation on every credential request
- --server flag for sentinel exec enabling per-request policy evaluation via AWS_CONTAINER_CREDENTIALS_FULL_URI
- CredentialMode type (server/cli/credential_process) for mode-aware policy rules
- 15-minute default server sessions with MaxServerDuration policy caps for rapid revocation
- Session tracking via DynamoDB with create/touch/expire lifecycle and revocation support
- require_server policy effect forcing server mode for sensitive profiles (cannot be bypassed)

**Stats:**
- 48 files created/modified
- 99,721 lines of Go (total codebase, +6,773 from v1.9)
- 6 phases, 15 plans
- 2 days (2026-01-19 → 2026-01-20)

**Git range:** `feat(78-01)` → `test(83-03)`

**What's next:** Production deployment ready. Server mode enables real-time credential revocation for high-security environments.

---

## v1.10.1 SSO Credential Fixes (Shipped: 2026-01-19)

**Delivered:** Test coverage for SSO credential loading patterns in bootstrap and whoami commands, verifying the --aws-profile and --profile flags correctly flow to WithSharedConfigProfile.

**Phases completed:** 78.1 (2 plans total)

**Key accomplishments:**
- Added TestBootstrapCommand_UsesAWSProfileForCredentials with three sub-tests verifying SSO profile handling
- Added TestWhoamiCommand_UsesProfileForAWSConfig with three sub-tests verifying SSO profile handling
- Verified vault.LoadConfig recognizes SSO settings (SSOStartURL, SSORegion, SSOAccountID, SSORoleName)
- Established SSO profile test patterns for future credential testing

**Stats:**
- 8 files created/modified
- 94,537 lines of Go (total codebase, +186 test lines)
- 1 phase, 2 plans
- Same day as v1.9

**Git range:** `test(78.1-01)` → `docs(78.1-02)`

**What's next:** Continue v1.10 Real-time Revocation (Phase 79: Server Policy Integration).

---

## v1.9 SSO Profile Support (Shipped: 2026-01-19)

**Delivered:** Fixed systemic bug where --profile flag didn't load SSO credentials, ensuring all Sentinel commands work seamlessly with SSO profiles like AWS CLI does.

**Phases completed:** 76-77 (6 plans total)

**Key accomplishments:**
- Fixed --profile flag not loading SSO credentials across all Sentinel CLI commands
- Added config.WithSharedConfigProfile pattern for AWS SDK credential provider chain integration
- Added --aws-profile flag to approval workflow commands (approve, deny, list)
- Added --aws-profile flag to break-glass commands (breakglass-check, breakglass-close, breakglass-list)
- Added --aws-profile flag to infrastructure commands (bootstrap, status, config validate)
- Added --aws-profile flag to permissions and audit commands
- Added --profile flag to whoami command (completes SSO profile support)

**Stats:**
- 34 files created/modified
- 92,948 lines of Go (total codebase, +2,408 from v1.8)
- 2 phases, 6 plans
- Same day as v1.8

**Git range:** `feat(76-01)` → `docs(77-01)`

**What's next:** Production deployment ready. All Sentinel CLI commands now fully support SSO profiles.

---

## v1.8 Credential Flow UX (Shipped: 2026-01-19)

**Delivered:** Developer experience improvements for credential handling with automatic SSO profile resolution and login triggering when SSO sessions expire.

**Phases completed:** 73-75 (3 plans total)

**Key accomplishments:**
- SSO profile resolution from ~/.aws/config for automatic profile detection
- Auto SSO login triggering with OIDC device code flow when sessions expire
- Generic retry wrapper for SSO credential resolution across different return types
- AWS auth error enhancement (Phase 75 deferred to v1.9)

**Stats:**
- 23 files created/modified
- 90,540 lines of Go (total codebase)
- 3 phases, 3 plans
- Same day as v1.7.1

**Git range:** `feat(73-01)` → `docs(74-02)`

**What's next:** v1.9 SSO Profile Support for --profile flag credential loading across all commands.

---

## v1.7.1 Security Patch (Shipped: 2026-01-19)

**Delivered:** Critical security fix replacing OS username (`os/user.Current()`) with AWS-authenticated identity (STS GetCallerIdentity) for policy evaluation across all CLI commands.

**Phases completed:** 69-72 (7 plans total)

**Key accomplishments:**
- AWS identity core with ARN parsing for all identity types (IAM user, SSO, assumed-role, federated-user, root)
- Replaced `user.Current()` with AWS STS GetCallerIdentity in credential flow
- Added `sentinel whoami` command for identity debugging
- Updated all approval workflow commands (approve, deny, request, list) to use AWS identity
- Updated all break-glass commands (breakglass, breakglass-close, breakglass-list) to use AWS identity
- Created 1,072 lines of security regression tests with attack scenario demonstrations
- Published CHANGELOG.md and SECURITY.md with vulnerability advisory (SENTINEL-2026-001)

**Stats:**
- 28 files created/modified
- 90,540 lines of Go (total codebase, +3,649 from v1.7)
- 4 phases, 7 plans
- 2 days from v1.7 to v1.7.1

**Git range:** `feat(69-01)` -> `docs(72-04)`

**What's next:** Production deployment ready. v1.7.1 addresses critical security vulnerability - all users should upgrade immediately.

---

## v1.7 Permissions Discovery (Shipped: 2026-01-18)

**Delivered:** Self-service permissions discovery with IAM policy generation, permission validation via SimulatePrincipalPolicy, interactive setup wizard, structured error messages with actionable suggestions, and streamlined onboarding documentation.

**Phases completed:** 60-68 (10 plans total)

**Key accomplishments:**
- Permission schema mapping all 10 Sentinel features to required IAM actions with query functions
- `sentinel permissions` CLI with Terraform HCL, CloudFormation YAML, and JSON output formats
- Feature auto-detection probing SSM and DynamoDB to discover configured features
- `sentinel permissions check` for validating credentials have required permissions via IAM SimulatePrincipalPolicy
- `sentinel init wizard` for interactive first-time setup with profile discovery and IAM policy generation
- Structured error types with 17 error codes and actionable fix suggestions for AWS errors
- `sentinel config validate` for validating policy, approval, breakglass, ratelimit configs before runtime
- Quick start templates (basic, approvals, full) via `sentinel config generate` for rapid deployment
- Streamlined onboarding: QUICKSTART.md (5-minute setup), PERMISSIONS.md (full IAM matrix), updated commands.md

**Stats:**
- 62 files created/modified
- 86,891 lines of Go (total codebase, +12,261 from v1.6)
- 9 phases, 10 plans
- 1 day from v1.6 to v1.7

**Git range:** `feat(60-01)` -> `docs(68-01)`

**What's next:** Production deployment ready. Consider v2.0 for UI dashboard, multi-account federation, policy versioning, or event-driven policy updates.

---

## v1.6 Testing & Hardening (Shipped: 2026-01-17)

**Delivered:** Comprehensive test coverage and validation with >80% coverage on all Sentinel packages, security regression suite, performance benchmarks, and pre-release validation confirming production readiness.

**Phases completed:** 50-59 (25 plans total)

**Key accomplishments:**
- Test infrastructure with mock framework and 80% coverage enforcement on all Sentinel packages
- Policy engine testing achieving 99% coverage with security invariant validation
- Break-glass security testing covering rate limiting, state machine, and audit trail integrity
- Performance benchmarks establishing baselines (policy eval ~50ns, identity gen ~64ns)
- Security regression suite with TestSecurityRegression_ prefix for CI/CD filtering
- Pre-release validation: 94.1% average coverage, 1,085 tests, GO recommendation

**Stats:**
- 99 files created/modified
- 74,630 lines of Go (total codebase)
- 10 phases, 25 plans
- 2 days from v1.5 to v1.6

**Git range:** `feat(50-01)` → `docs(59-03)`

**What's next:** Production deployment ready. Consider v2.0 for UI dashboard, multi-account federation, or policy versioning.

---

## v1.5 Enforcement & Assurance (Shipped: 2026-01-16)

**Delivered:** IAM trust policy analysis, enforcement status reporting, CloudTrail session verification, and drift detection for comprehensive security assurance.

**Phases completed:** 43-49 (8 plans total)

**Key accomplishments:**
- IAM trust policy analysis with enforcement status levels (Full/Partial/None)
- Trust policy template generation for Pattern A/B/C security postures
- CloudTrail session verification for SourceIdentity compliance auditing
- `sentinel audit verify` command for unmanaged session detection
- Drift detection with --require-sentinel flag (advisory warnings)
- Complete enforcement documentation (ENFORCEMENT.md, ASSURANCE.md)

**Stats:**
- 38 files created/modified
- 49,588 lines of Go (total codebase)
- 7 phases, 8 plans
- 1 day from v1.4 to v1.5

**Git range:** `feat(43-01)` → `docs(49-01)`

**What's next:** v1.6 Testing & Hardening for comprehensive test coverage before production release

---

## v1.4 Sentinel Bootstrapping (Shipped: 2026-01-16)

**Delivered:** Automated bootstrap system for SSM parameter setup, sample policy generation, and IAM policy documents for least-privilege access.

**Phases completed:** 35-42 (8 plans total)

**Key accomplishments:**
- Bootstrap planner analyzing existing SSM parameters with state detection
- Automated SSM parameter creation with String type for policy YAML
- Sample policy generation from profile configuration
- IAM policy document generation with least-privilege actions
- Status command for deployment health monitoring
- Bootstrap documentation with quick start guide

**Stats:**
- 42 files created/modified
- 44,813 lines of Go (total codebase)
- 8 phases, 8 plans
- 1 day from v1.3 to v1.4

**Git range:** `feat(35-01)` → `docs(42-01)`

**What's next:** v1.5 Enforcement & Assurance for IAM trust policy analysis and CloudTrail verification

---

## v1.3 Break-Glass (Shipped: 2026-01-16)

**Delivered:** Emergency access bypass with mandatory justification, time-bounded sessions, rate limiting, and immediate security notifications for incident response.

**Phases completed:** 27-34 (15 plans total)

**Key accomplishments:**
- Break-glass event model with state machine (active → closed/expired) and reason codes
- DynamoDB storage with access stacking prevention (one active event per user/profile)
- Elevated audit logging with BreakGlassLogEntry for comprehensive incident records
- Time-bounded sessions with automatic duration capping to remaining break-glass time
- Immediate SNS/Webhook notifications for security team awareness
- Post-incident review commands: breakglass-list, breakglass-check, breakglass-close
- Rate limiting with cooldowns, per-user/per-profile quotas, and escalation thresholds
- Break-glass policies controlling who can invoke emergency access and under what conditions

**Stats:**
- 66 files created/modified
- 35,726 lines of Go (total codebase)
- 8 phases, 15 plans, ~40 tasks
- 1 day from v1.2 to v1.3

**Git range:** `feat(27-01)` → `feat(34-02)`

**What's next:** Consider multi-account policy federation, policy versioning, or UI dashboard for v2.0

---

## v1.2 Approval Workflows (Shipped: 2026-01-15)

**Delivered:** Request/approve flow for sensitive access with DynamoDB state machine, SNS/Webhook notification hooks, and approval policies with auto-approve conditions.

**Phases completed:** 18-26 (18 plans total)

**Key accomplishments:**
- Request schema with state machine (pending → approved/denied/expired/cancelled)
- DynamoDB backend with GSI query patterns and TTL expiration
- CLI commands: request, list, check, approve, deny
- SNS and Webhook notifiers with NotifyStore wrapper for automatic notifications
- Approval policies with EffectRequireApproval, auto-approve conditions, and approver routing
- Approval audit trail logging parallel to decision logging

**Stats:**
- 81 files created/modified
- 23,657 lines of Go (total codebase)
- 9 phases, 18 plans, ~45 tasks
- 1 day from v1.1 to v1.2

**Git range:** `feat(18-01)` → `feat(26-02)`

**What's next:** v1.3 Break-Glass for emergency access bypass with enhanced audit

---

## v1.1 Sentinel Fingerprint (Shipped: 2026-01-15)

**Delivered:** Enforceable credential provenance via SourceIdentity stamping on all role assumptions, enabling CloudTrail correlation and optional IAM enforcement.

**Phases completed:** 9-17 (12 plans total)

**Key accomplishments:**
- SourceIdentity type (sentinel:<user>:<request-id>) with crypto-random request-id generation
- SentinelAssumeRole function that stamps SourceIdentity on all role assumptions
- TwoHopCredentialProvider chaining aws-vault base credentials through Sentinel fingerprinting
- Both credential_process and exec commands now stamp SourceIdentity automatically
- Enhanced decision logging with CloudTrail correlation fields (request_id, source_identity, role_arn)
- Complete documentation for CloudTrail correlation and IAM trust policy/SCP enforcement patterns

**Stats:**
- 43 files created/modified
- 13,986 lines of Go (total codebase)
- 9 phases, 12 plans, ~30 tasks
- 1 day from v1.0 to v1.1

**Git range:** `feat(09-01)` → `docs(17-01)`

**What's next:** Consider approval workflows, break-glass mode, or multi-account policy federation for v2.0

---

## v1.0 MVP (Shipped: 2026-01-14)

**Delivered:** Intent-aware access control layer for AWS credentials with policy evaluation, SSM-based policy storage, and integration via credential_process and exec commands.

**Phases completed:** 1-8 (16 plans total)

**Key accomplishments:**
- CLI foundation with kingpin framework and aws-vault credential provider integration
- Policy schema with YAML parsing, validation, and type-safe Effect/Weekday handling
- SSM Parameter Store policy loading with TTL-based caching
- Rule matching engine with time windows, timezone support, and first-match-wins semantics
- credential_process and exec commands with policy-gated credential issuance
- Structured JSON Lines decision logging with configurable destinations

**Stats:**
- 57 files created/modified
- 10,762 lines of Go
- 8 phases, 16 plans, ~40 tasks
- 1 day from start to ship

**Git range:** `feat(01-01)` → `feat(08-02)`

**What's next:** Consider approval workflows, break-glass mode, or additional policy features for v1.1

---
