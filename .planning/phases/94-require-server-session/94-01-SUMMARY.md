---
phase: 94-require-server-session
plan: 01
subsystem: policy
tags: [policy, effects, server-mode, session-tracking]

# Dependency graph
requires:
  - phase: 82
    provides: require_server effect pattern
provides:
  - EffectRequireServerSession policy effect
  - RequiresSessionTracking decision flag
  - SessionTableName request field
affects: [cli-error-messages, server-mode-docs]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Special effect conversion pattern (require_server_session -> allow/deny)

key-files:
  created: []
  modified:
    - policy/types.go
    - policy/evaluate.go
    - policy/evaluate_test.go

key-decisions:
  - "RequiresSessionTracking set only when mode is server but no session table"
  - "Both RequiresServerMode and RequiresSessionTracking set when mode is not server"

patterns-established:
  - "Dual-condition effect evaluation: require_server_session needs both server mode AND session tracking"

issues-created: []

# Metrics
duration: 5min
completed: 2026-01-24
---

# Phase 94 Plan 01: Add require_server_session Policy Effect Summary

**New policy effect type `require_server_session` with evaluation logic for enforcing server mode with session tracking**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-24T21:13:00Z
- **Completed:** 2026-01-24T21:18:52Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments
- Added `EffectRequireServerSession` constant to policy schema
- Added `SessionTable` field to Rule struct for optional table specification
- Added `RequiresSessionTracking` field to Decision struct
- Added `SessionTableName` field to Request struct
- Implemented dual-condition evaluation logic (server mode AND session table required)
- Added comprehensive tests for all mode/session combinations

## Task Commits

Each task was committed atomically:

1. **Task 1: Add EffectRequireServerSession to policy schema** - `ea7d7a1` (feat)
2. **Task 2: Update policy evaluation for require_server_session** - `9bf6258` (feat)
3. **Task 3: Add tests for require_server_session evaluation** - `6130e8c` (test)

## Files Created/Modified
- `policy/types.go` - Added EffectRequireServerSession constant, SessionTable field, updated IsValid()
- `policy/evaluate.go` - Added RequiresSessionTracking, SessionTableName fields, evaluation logic
- `policy/evaluate_test.go` - Added TestEvaluate_RequireServerSession with 5 test cases

## Decisions Made
- RequiresSessionTracking is true when session tracking is missing (even if mode is correct)
- RequiresServerMode is true only when mode is not server
- Both flags can be true simultaneously when mode is not server (regardless of session table)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- Policy schema and evaluation ready for require_server_session effect
- Next plan (94-02) can integrate with CLI error messages and server command

---
*Phase: 94-require-server-session*
*Completed: 2026-01-24*
