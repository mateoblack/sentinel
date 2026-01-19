# Project Milestones: Sentinel

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
