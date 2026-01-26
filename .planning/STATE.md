# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-26)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.18 Critical Security Hardening (phases 129-135 remaining)

## Current Position

Phase: 131-dynamodb-security
Plan: 2 of 2 complete in current phase (PHASE COMPLETE)
Status: Ready for next phase (132-keyring-protection)
Last activity: 2026-01-26 — Completed 131-02 (Security regression tests for all DynamoDB stores)

Progress: ████████████████████░░ 89% (235/263 estimated total plans)

## Milestone Summary

**v1.18 Critical Security Hardening (IN PROGRESS):**
- 10 phases (126-135), security milestone
- Phases 126-128 complete (Policy Integrity, Break-Glass MFA, Audit Log Integrity)
- Phase 131 COMPLETE (DynamoDB Security - 2/2 plans complete)
- Phases 132-135 pending (Keyring Protection, Rate Limit Hardening, Input Sanitization, Security Validation)
- Addresses P0 security threats from STRIDE threat model

**v1.19 Documentation & Completeness Audit (PENDING v1.18):**
- 7 phases (136-142), documentation milestone
- Waiting for v1.18 security work to complete
- Close documentation gaps for v1.13-v1.18 features

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
- Total plans completed: 229
- Estimated remaining: ~35 plans (7 security + ~28 documentation)
- Average duration: ~3.5 min per plan

**By Milestone:**

Last 5 milestones:
- v1.14: 7 phases, 19 plans, ~49 min
- v1.15: 9 phases, 12 plans, ~41 min
- v1.16: 8 phases, 9 plans, ~21 min
- v1.17: 5 phases, 5 plans, ~25 min
- v1.18: 5 phases complete (126-130), 5 phases remaining (131-135)

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

**Phase 127 Break-Glass MFA (Plan 01-03):**
- TOTP verifier using RFC 6238 with 30-second windows
- SMS verifier via SNS direct publish
- MFA requirements in break-glass policy schema
- SSM-based MFA configuration for CLI

**Phase 126 Policy Integrity (Plan 01-03):**
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

**Phase 129 Local Server Security (Plan 01-04):**
- Use golang.org/x/sys/unix for SO_PEERCRED (already indirect dependency)
- Separate syscall implementations per platform with build tags
- Return typed errors (ErrNotUnixSocket, ErrPeerCredentialsUnavailable)
- macOS requires two separate syscalls (LOCAL_PEERCRED + LOCAL_PEERPID)
- Constant-time token comparison using crypto/subtle to prevent timing attacks
- Token binding: PID=0 tokens get bound on first successful use
- Fallback mode for backward compatibility during migration
- Default socket permissions 0600 (owner only)
- EcsServer Unix mode uses process authentication with UID binding
- EC2 server cannot use Unix sockets due to AWS SDK IMDS expectations
- Security tests organized by threat category with AST verification

**Phase 130 Identity Hardening (Plan 01):**
- AWS ISO (DoD) and ISO-B (C2S) partition support added to ARN validation
- Lambda TVM identity extraction consolidated to use identity.ExtractUsername
- Security regression tests with TestSecurityRegression_ prefix for CI filtering
- Sanitized usernames are alphanumeric-only (a-z, A-Z, 0-9)

**Phase 131 DynamoDB Security (Plan 01-02):**
- Fixed optimistic locking bug: Update() now saves originalUpdatedAt before overwriting
- Added ValidTransition() method to RequestStatus and BreakGlassStatus types
- Added ErrInvalidStateTransition sentinel error to request and breakglass stores
- Security regression tests: TestSecurityRegression_* prefix covers all DynamoDB stores
- Tests verify conditional writes, optimistic locking, and state transition validation

### Pending Todos

None — Phase 131 complete, ready for Phase 132 (Keyring Protection)

### Blockers/Concerns

None — phases 129-135 are security implementation work.

## Session Continuity

Last session: 2026-01-26
Stopped at: Completed Phase 131 (DynamoDB Security - both plans)
Resume file: None
Next: Phase 132 (Keyring Protection)
