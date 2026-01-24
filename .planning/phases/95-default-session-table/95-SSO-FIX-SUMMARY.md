---
phase: 95-default-session-table
plan: SSO-FIX
subsystem: cli
tags: [bug-fix, sso, server-mode, credential-profile]

requires:
  - phase: 94-require-server-session
    provides: sentinelCredentialProviderAdapter
provides:
  - Fixed SSO credential profile in server mode
  - credentialProfile field on adapter
affects: [server-mode, sso-users]

tech-stack:
  added: []
  patterns: []

key-files:
  created: []
  modified: [cli/sentinel_exec.go]

key-decisions:
  - "Adapter stores credentialProfile from --aws-profile flag"
  - "Uses credentialProfile for credential retrieval, not req.ProfileName"

patterns-established:
  - "Credential profile separation: SSO profile vs policy target profile"

issues-created: []

duration: 5min
completed: 2026-01-24
---

# Phase 95-SSO-FIX: Server Mode SSO Credential Profile Bug Fix Summary

**Fixed server mode to use --aws-profile for SSO credentials instead of policy target profile**

## Performance

- **Duration:** 5 min
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- Added credentialProfile field to sentinelCredentialProviderAdapter
- Adapter uses credentialProfile for credential retrieval
- Fixes "InvalidClientTokenId" errors when using SSO with --server

## Files Created/Modified
- `cli/sentinel_exec.go` - Added credentialProfile field and usage in adapter

## Decisions Made
- credentialProfile passed from computed value (AWSProfile || ProfileName)
- Falls back to req.ProfileName if credentialProfile is empty (backward compatible)

## Deviations from Plan
None - plan executed exactly as written

## Issues Encountered
None

## Bug Impact
- **Before fix:** User runs `sentinel exec --aws-profile sso-dev --profile prod-policy --server`
  - Non-server mode: Uses `sso-dev` for credentials (works)
  - Server mode: Uses `prod-policy` for credentials (fails - wrong profile for SSO login)
- **After fix:** Server mode correctly uses `sso-dev` for credential retrieval

---
*Phase: 95-default-session-table*
*Completed: 2026-01-24*
