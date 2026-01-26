# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-26)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.19 Documentation & Completeness Audit

## Current Position

Phase: 128-audit-log-integrity
Plan: 03 of 03 (Log Verification CLI & Security Tests) - COMPLETE
Status: Phase 128 complete, all 3 plans shipped
Last activity: 2026-01-26 — Plan 128-03 completed (verify-logs CLI, security tests)

Progress: ████████████████████░░ 89% (233/263 estimated total plans)

## Milestone Summary

**v1.19 Documentation & Completeness Audit (IN PROGRESS):**
- 7 phases (136-142), documentation milestone
- Close documentation gaps for v1.13-v1.18 features
- Update CHANGELOG, commands.md, create guides for policy signing, device posture, security hardening
- Update README and examples, review deployment guides

**v1.18 Policy Integrity (SHIPPED 2026-01-26):**
- 1 phase (126), 3 plans
- KMS-based policy signing to prevent cache poisoning
- VerifyingLoader for signature validation
- Lambda TVM signature verification integration

**v1.17 Policy Developer Experience (SHIPPED 2026-01-26):**
- 5 phases (121-125), 5 plans
- Policy schema Version type with validation helpers
- Policy CLI commands: pull, push, diff, validate
- Complete workflow for editing SSM-backed policies locally

**v1.16 Security Hardening (SHIPPED 2026-01-26):**
- 8 phases (113-120), 9 plans
- Timing attack mitigation, Secrets Manager, rate limiting
- DynamoDB encryption, error sanitization
- Security integration tests

**v1.15 Device Posture (SHIPPED 2026-01-25):**
- 9 phases (104-112), 12 plans
- Server-verified device posture via MDM APIs in Lambda TVM
- MDM Provider interface with Jamf Pro implementation
- Policy device conditions for rule matching

**Previous milestones (18 shipped):**
See complete history in ROADMAP.md

## Performance Metrics

**Velocity:**
- Total plans completed: 231
- Estimated remaining: ~32 plans (documentation work)
- Average duration: ~3.5 min per plan

**By Milestone:**

Last 5 milestones:
- v1.14: 7 phases, 19 plans, ~49 min
- v1.15: 9 phases, 12 plans, ~41 min
- v1.16: 8 phases, 9 plans, ~21 min
- v1.17: 5 phases, 5 plans, ~25 min
- v1.18: 1 phase, 3 plans, ~11 min

*Note: v1.19 is documentation-focused, may have different velocity characteristics*

## Accumulated Context

### Decisions

Key decisions logged in PROJECT.md Key Decisions table. Recent decisions:

**Phase 128 Audit Log Integrity (Plan 01-03):**
- Entry stored as json.RawMessage to preserve exact bytes for verification after JSON round-trip
- Signature covers entry + timestamp + key_id for replay protection
- Fail-open on signing errors (log to stderr, continue with unsigned entries)
- Minimum key length 32 bytes (256 bits) for HMAC-SHA256
- Fail-open on CloudWatch errors (availability over security)
- Logger selection: CloudWatch+signing > CloudWatch > signing > stdout
- Default stream name from AWS_LAMBDA_FUNCTION_NAME
- verify-logs command: exit 0 for all valid, 1 for any failures
- Security tests: AST verification for timing-safe comparison
- Key from --key-file preferred for security (avoids CLI history)

**v1.18 Critical Security Hardening (Phase 126):**
- Use MessageType RAW for KMS signing (KMS handles hashing internally)
- RawPolicyLoader interface for signature verification on raw bytes
- SignatureEnvelope JSON format with Base64-encoded signatures
- SSM → VerifyingLoader → CachedLoader pipeline
- Fail-closed: KMS errors prevent policy loading

**v1.17 Policy Developer Experience:**
- Version as type alias for YAML compatibility
- Extended SSMAPI interface with PutParameter
- Confirmation prompts with --force bypass
- Exit codes: 0=valid/no-changes, 1=invalid/changes
- Normalize policies before diff comparison

**v1.16 Security Hardening:**
- crypto/subtle.ConstantTimeCompare for bearer tokens
- 1-hour Secrets Manager cache TTL for Lambda optimization
- AWS managed KMS encryption by default
- Sliding window rate limiting by IAM ARN
- Error sanitization: log details, return generic messages

**v1.15 Device Posture:**
- DeviceID 64-char hex via HMAC-SHA256 with machineid
- Fail-open MDM by default (RequireDevicePosture=false)
- Device conditions affect rule matching (nil posture fails conditions)
- Device audit commands with anomaly detection

### Pending Todos

None — fresh documentation milestone.

### Blockers/Concerns

None — v1.19 is documentation work with no code dependencies.

## Session Continuity

Last session: 2026-01-26
Stopped at: Phase 128-03 complete (verify-logs CLI, security tests)
Resume file: None
Next: Phase 128 complete - proceed to next phase or documentation milestone
