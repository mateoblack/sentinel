---
phase: 11-two-hop-orchestration
plan: 01
subsystem: sentinel
tags: [aws-vault, credentials-provider, source-identity, two-hop]

# Dependency graph
requires:
  - phase: 09-source-identity-schema
    provides: SourceIdentity type, SanitizeUser, NewRequestID
  - phase: 10-assume-role-provider
    provides: SentinelAssumeRole function with SourceIdentity stamping
provides:
  - TwoHopCredentialProvider implementing aws.CredentialsProvider
  - Credential chaining from aws-vault base credentials through SentinelAssumeRole
  - Unique SourceIdentity generation per Retrieve() call
affects: [12-credential-process-update, 13-exec-command-update]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Provider pattern matching vault/assumeroleprovider.go"
    - "Input validation with provider-specific errors"
    - "User sanitization at provider level before SentinelAssumeRole"

key-files:
  created:
    - sentinel/provider.go
    - sentinel/provider_test.go
  modified: []

key-decisions:
  - "User sanitization in provider, not at creation time - allows raw user storage"
  - "Session duration default applied in Retrieve(), not constructor - follows aws-vault pattern"
  - "Tasks 1-2 merged into single commit since both target same file"

patterns-established:
  - "TwoHop credential flow: aws-vault base creds -> SentinelAssumeRole -> fingerprinted credentials"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-14
---

# Phase 11 Plan 01: Two-Hop Orchestration Summary

**TwoHopCredentialProvider chains aws-vault base credentials through SentinelAssumeRole to stamp unique SourceIdentity on every credential request**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-14T19:15:00Z
- **Completed:** 2026-01-14T19:18:00Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- Created TwoHopCredentialProvider implementing aws.CredentialsProvider interface
- Provider chains aws-vault credentials (SSO, session tokens, stored creds) through SentinelAssumeRole
- Each Retrieve() generates unique request-id for SourceIdentity (sentinel:<user>:<request-id>)
- User is sanitized for AWS SourceIdentity constraints (alphanumeric, max 20 chars)
- Comprehensive table-driven unit tests covering validation, defaults, and interface compliance

## Task Commits

Each task was committed atomically:

1. **Task 1: Create TwoHopCredentialProvider type and Retrieve method** - `dc79c84` (feat)
2. **Task 2: Add input validation and NewTwoHopProvider helper** - included in Task 1 (same file)
3. **Task 3: Add unit tests for TwoHopCredentialProvider** - `31c8525` (test)

**Plan metadata:** (this commit)

## Files Created/Modified

- `sentinel/provider.go` - TwoHopCredentialProvider type, TwoHopCredentialProviderInput, Retrieve method, validation
- `sentinel/provider_test.go` - Table-driven tests for validation, defaults, SourceIdentity format, interface compliance

## Decisions Made

- **User sanitization at Retrieve time:** The provider stores the raw user string and sanitizes during each Retrieve() call. This follows the pattern from vault/assumeroleprovider.go where transformation happens at call time.
- **Tasks 1-2 merged:** Both tasks target provider.go and share the same input/validation types, so implemented together as in Phase 10.
- **No caching in provider:** Caching is handled by CachedSessionProvider wrapper (existing aws-vault pattern), keeping TwoHopCredentialProvider stateless and simple.

## Deviations from Plan

None - plan executed exactly as written. Task 2 (validation and NewTwoHopProvider helper) was implemented alongside Task 1 since both target the same file, following the same pattern as Phase 10.

## Issues Encountered

None

## Next Phase Readiness

- TwoHopCredentialProvider ready for integration into credential_process and exec commands
- Phase 12 (Credential Process Update) can wire TwoHopCredentialProvider into the credential_process flow
- Phase 13 (Exec Command Update) can wire TwoHopCredentialProvider into the exec flow
- All Sentinel-issued credentials will now carry SourceIdentity for CloudTrail correlation

---
*Phase: 11-two-hop-orchestration*
*Completed: 2026-01-14*
