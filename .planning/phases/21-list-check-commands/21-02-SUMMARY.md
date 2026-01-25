---
phase: 21-list-check-commands
plan: 02
subsystem: cli
tags: [kingpin, dynamodb, aws-sdk-go-v2, approval-workflow, json-output]

# Dependency graph
requires:
  - phase: 21-01
    provides: List command pattern and mockStore for testing
  - phase: 20-request-command
    provides: Request command pattern with Store interface injection
provides:
  - sentinel check command for viewing single request status
  - Request ID validation before store call
  - JSON output with all request fields including Approver
  - Human-readable duration formatting (1h30m style)
affects: [22-approve-deny-commands, 23-request-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Check command follows request command pattern
    - Positional argument for request ID (vs flags for list)
    - Duration formatted as human-readable string

key-files:
  created:
    - cli/check.go
    - cli/check_test.go
  modified:
    - cmd/sentinel/main.go

key-decisions:
  - "Positional argument for request ID (required, not a flag)"
  - "Duration formatted as human-readable string (1h30m) for user clarity"
  - "Request ID validation before store call to fail fast on bad input"

patterns-established:
  - "Check command uses positional args for required lookup parameters"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-15
---

# Phase 21 Plan 02: Check Command Summary

**CLI command `sentinel check <request-id>` for viewing single request status with full details including approver, justification, and human-readable duration**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-15T04:35:05Z
- **Completed:** 2026-01-15T04:37:25Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `sentinel check` command with positional request ID argument
- Request ID validation using request.ValidateRequestID before store call
- Full request details output in JSON including Duration as human-readable string
- 7 test cases covering success, not found, invalid ID, store error, and output format

## Task Commits

Each task was committed atomically:

1. **Task 1: Create check command with CLI configuration and core logic** - `9f6b8ce` (feat)
2. **Task 2: Wire command in main.go and add unit tests** - `21563ad` (test)

## Files Created/Modified

- `cli/check.go` - Check command with ConfigureCheckCommand, CheckCommand, and formatDuration
- `cli/check_test.go` - Test suite with 7 test cases reusing mockStore from request_test.go
- `cmd/sentinel/main.go` - Wire ConfigureCheckCommand after ConfigureSentinelListCommand

## Decisions Made

- **Positional argument for request ID**: Unlike list command flags, check takes request ID as positional argument since it's the primary required input
- **Duration formatting**: Converted time.Duration to human-readable format (e.g., "1h30m") for better CLI output
- **Request ID validation**: Validate format before calling store.Get to fail fast with clear error message

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Phase 21 complete (2/2 plans)
- Ready for Phase 22: Approve/Deny Commands

---
*Phase: 21-list-check-commands*
*Completed: 2026-01-15*
