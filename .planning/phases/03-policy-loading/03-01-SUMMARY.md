---
phase: 03-policy-loading
plan: 01
subsystem: policy
tags: [aws-sdk-go-v2, ssm, parameter-store]

# Dependency graph
requires:
  - phase: 02-policy-schema
    provides: ParsePolicy function and Policy types
provides:
  - SSM-based Loader type for fetching policies
  - ErrPolicyNotFound sentinel error for error handling
affects: [policy-caching, credential-process, policy-evaluation]

# Tech tracking
tech-stack:
  added: [github.com/aws/aws-sdk-go-v2/service/ssm]
  patterns: [SSM client creation via NewFromConfig]

key-files:
  created: [policy/loader.go, policy/loader_test.go]
  modified: [go.mod, go.sum]

key-decisions:
  - "Caller provides aws.Config (no config.LoadDefaultConfig in Loader)"
  - "WithDecryption: true for SecureString support"
  - "ErrPolicyNotFound wraps parameter name for context"

patterns-established:
  - "SSM client creation follows vault.go pattern (NewFromConfig)"
  - "errors.As for AWS SDK error type checking"

issues-created: []

# Metrics
duration: 1min
completed: 2026-01-14
---

# Phase 3 Plan 01: SSM Client and Policy Loader Summary

**SSM Parameter Store Loader type with GetParameter fetch, decryption support, and ErrPolicyNotFound error handling**

## Performance

- **Duration:** 1 min
- **Started:** 2026-01-14T03:52:35Z
- **Completed:** 2026-01-14T03:53:59Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Created Loader struct with SSM client for fetching policies from Parameter Store
- Implemented Load method with GetParameter and WithDecryption support
- Added ErrPolicyNotFound sentinel error with parameter name wrapping
- Basic smoke tests for exported API

## Task Commits

Each task was committed atomically:

1. **Task 1: Add SSM dependency and create Loader type** - `7134e9c` (feat)
2. **Task 2: Implement Load method with error handling** - `d1af4a8` (test)

## Files Created/Modified
- `policy/loader.go` - Loader struct with NewLoader constructor and Load method
- `policy/loader_test.go` - Smoke tests for ErrPolicyNotFound and NewLoader
- `go.mod` - Added aws-sdk-go-v2/service/ssm dependency
- `go.sum` - Updated checksums

## Decisions Made
- Caller provides aws.Config rather than loading config in Loader (matches vault.go pattern)
- WithDecryption always true to support SecureString parameters (ignored for String type)
- ErrPolicyNotFound wraps parameter name for better error context

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- Loader type ready for use by policy caching layer (Plan 03-02)
- ErrPolicyNotFound can be used with errors.Is for proper error handling
- Integration tests will require AWS credentials (deferred to Phase 5)

---
*Phase: 03-policy-loading*
*Completed: 2026-01-14*
