---
phase: 30-time-bounded-sessions
plan: 01
subsystem: breakglass
tags: [checker, credential-issuance, query, break-glass]

# Dependency graph
requires:
  - phase: 27-break-glass-schema
    provides: BreakGlassEvent types and state machine
  - phase: 28-break-glass-command
    provides: Store interface with ListByInvoker query method
provides:
  - FindActiveBreakGlass function for credential issuance
  - RemainingDuration helper for expiry tracking
  - isBreakGlassValid internal validation
affects: [30-time-bounded-sessions, 31-session-credentials]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Checker pattern: query store, filter for valid, return first match"
    - "Parallels request/checker.go pattern for consistency"

key-files:
  created:
    - breakglass/checker.go
    - breakglass/checker_test.go
  modified: []

key-decisions:
  - "Follow request/checker.go pattern for API consistency"
  - "Use MaxQueryLimit (1000) from store.go for query limit"
  - "Return nil,nil for no match (not error) - matches approval request behavior"

patterns-established:
  - "Break-glass checker mirrors approved request checker pattern"
  - "Validity check: status == active AND ExpiresAt > now"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-15
---

# Phase 30 Plan 01: Break-Glass Checker Summary

**FindActiveBreakGlass function with RemainingDuration helper, following request/checker.go pattern for credential issuance integration**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-15T23:06:02Z
- **Completed:** 2026-01-15T23:08:26Z
- **Tasks:** 2
- **Files created:** 2

## Accomplishments

- FindActiveBreakGlass queries store and filters for active+profile+valid events
- RemainingDuration calculates time until break-glass expires
- isBreakGlassValid internal function checks active status and not expired
- 16 test cases covering all edge cases for checker functions

## Task Commits

Each task was committed atomically:

1. **Task 1: Create FindActiveBreakGlass checker function** - `c7c65f6` (feat)
2. **Task 2: Add comprehensive tests for break-glass checker** - `8d0ad09` (test)

## Files Created/Modified

- `breakglass/checker.go` - FindActiveBreakGlass, RemainingDuration, isBreakGlassValid functions
- `breakglass/checker_test.go` - Comprehensive tests with 16 test cases

## Decisions Made

1. **Follow request/checker.go pattern**: Same structure - query by invoker, filter, return first match
2. **Use MaxQueryLimit constant**: Reuse existing limit from store.go (1000)
3. **Return nil for no match**: Consistent with FindApprovedRequest - nil means "no active event found"

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- FindActiveBreakGlass ready for credential issuance integration
- Pattern consistent with approved request checker for code maintainability
- RemainingDuration available for session duration tracking

---
*Phase: 30-time-bounded-sessions*
*Completed: 2026-01-15*
