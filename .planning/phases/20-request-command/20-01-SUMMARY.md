---
phase: 20-request-command
plan: 01
subsystem: cli
tags: [kingpin, dynamodb, aws-sdk-go-v2, approval-workflow]

# Dependency graph
requires:
  - phase: 19-dynamodb-backend
    provides: Store interface and DynamoDB implementation for request persistence
provides:
  - sentinel request command for submitting access requests
  - JSON output with request_id, profile, status, expires_at
  - Duration capping at 8h max
  - Profile validation before request submission
affects: [21-list-check-commands, 22-approve-deny-commands, 23-request-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Request command follows credentials.go pattern (user.Current, ValidateProfile, JSON output)
    - Mock store for testability via Store interface injection

key-files:
  created:
    - cli/request.go
    - cli/request_test.go
  modified:
    - cmd/sentinel/main.go

key-decisions:
  - "Store interface injected via RequestCommandInput for testability"
  - "Duration capped with warning rather than error for UX"

patterns-established:
  - "CLI commands accept Store interface for testing without DynamoDB"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-14
---

# Phase 20 Plan 01: Request Command Summary

**CLI command `sentinel request` for submitting approval requests with profile validation, duration capping, and DynamoDB storage**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-14T23:04:00Z
- **Completed:** 2026-01-14T23:14:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `sentinel request` command with --profile, --duration, --justification, --request-table, --region flags
- Implemented request creation with profile validation, duration capping at 8h, and DynamoDB storage
- Added comprehensive test suite with 7 test cases covering success and error paths
- JSON output format enables scripting and automation

## Task Commits

Each task was committed atomically:

1. **Task 1: Create request command with CLI configuration and core logic** - `df9b1db` (feat)
2. **Task 2: Wire command in main.go and add unit tests** - `87cb773` (test)

## Files Created/Modified

- `cli/request.go` - Request command implementation with ConfigureRequestCommand and RequestCommand
- `cli/request_test.go` - Test suite with mock store and 7 test cases
- `cmd/sentinel/main.go` - Wire ConfigureRequestCommand

## Decisions Made

- **Store interface injection**: RequestCommandInput accepts optional Store for testability, avoiding real DynamoDB in tests
- **Duration capping with warning**: Rather than erroring on >8h duration, cap it and warn the user for better UX

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Request command complete and tested
- Ready for Phase 21: List/Check Commands to build on request query patterns

---
*Phase: 20-request-command*
*Completed: 2026-01-14*
