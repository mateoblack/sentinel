# Project Milestones: Sentinel

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
