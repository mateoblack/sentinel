# Project Milestones: Sentinel

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
