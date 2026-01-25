---
phase: 18-request-schema
plan: 01
subsystem: request
tags: [go, state-machine, validation, approval-workflow]

# Dependency graph
requires:
  - phase: 09-source-identity
    provides: identity types pattern and request ID generation
  - phase: 02-policy-schema
    provides: Effect type pattern for status types
provides:
  - Request struct with approval workflow fields
  - RequestStatus state machine (pending -> terminal)
  - Validation for all request fields
  - NewRequestID for unique 16-char hex IDs
affects: [19-dynamodb-backend, 20-request-command, 22-approve-deny-commands, 23-request-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "RequestStatus as string type with IsValid/IsTerminal methods"
    - "State machine transitions via CanTransitionTo method"
    - "16-char hex request IDs (vs 8-char identity request IDs)"

key-files:
  created:
    - request/types.go
    - request/validate.go
    - request/types_test.go
    - request/validate_test.go
  modified: []

key-decisions:
  - "16-char request IDs (64 bits entropy) vs 8-char identity IDs for namespace separation"
  - "IsTerminal() helper method for cleaner state machine checks"
  - "MaxDuration of 8 hours for requested access windows"

patterns-established:
  - "Request types follow policy/types.go and identity/types.go patterns"
  - "State machine with single non-terminal state (pending) for simpler transitions"
  - "Comprehensive boundary testing for validation limits"

issues-created: []

# Metrics
duration: 2 min
completed: 2026-01-15
---

# Phase 18 Plan 01: Request Schema Summary

**Request type with state machine, validation, and 16-char hex ID generation for approval workflows**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-15T03:45:14Z
- **Completed:** 2026-01-15T03:47:26Z
- **Tasks:** 2
- **Files created:** 4

## Accomplishments

- Request struct with all approval workflow fields (ID, requester, profile, justification, duration, status, timestamps, approver fields)
- RequestStatus type with state machine (pending -> approved/denied/expired/cancelled)
- Complete validation for all fields including boundary checks
- NewRequestID generates 16-char lowercase hex IDs with crypto/rand
- Comprehensive test coverage with table-driven tests

## Task Commits

Each task was committed atomically:

1. **Task 1: Create request types with state machine** - `6fbc1fc` (feat)
2. **Task 2: Implement validation with comprehensive tests** - `316e1e8` (feat)

## Files Created/Modified

- `request/types.go` - Request struct, RequestStatus type, NewRequestID, constants
- `request/validate.go` - Validate() and CanTransitionTo() methods
- `request/types_test.go` - Tests for RequestStatus, NewRequestID, ValidateRequestID
- `request/validate_test.go` - Tests for Validate(), CanTransitionTo()

## Decisions Made

1. **16-char request IDs** - Longer than identity's 8-char request IDs to provide namespace separation and more entropy for approval requests
2. **IsTerminal() method** - Added helper on RequestStatus for cleaner state machine logic
3. **8-hour max duration** - Reasonable upper bound for access request windows

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Request type ready for DynamoDB storage (Phase 19)
- Validation ready for CLI command integration (Phase 20)
- State machine ready for approve/deny operations (Phase 22)

---
*Phase: 18-request-schema*
*Completed: 2026-01-15*
