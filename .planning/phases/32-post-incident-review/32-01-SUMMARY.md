---
phase: 32-post-incident-review
plan: 01
subsystem: cli
tags: [breakglass, cli, post-incident, audit, json, dynamo]

# Dependency graph
requires:
  - phase: 28-break-glass-command
    provides: breakglass.Store interface with ListByInvoker, ListByStatus, ListByProfile methods
  - phase: 27-break-glass-schema
    provides: breakglass.BreakGlassEvent type, ValidateBreakGlassID function
provides:
  - sentinel breakglass-list command for listing break-glass events
  - sentinel breakglass-check command for viewing event details
affects: [32-post-incident-review, security-audit, break-glass-workflow]

# Tech tracking
tech-stack:
  added: []
  patterns: [cli-command-pattern, testable-command-variant, mock-store-testing]

key-files:
  created: [cli/breakglass_list.go, cli/breakglass_list_test.go, cli/breakglass_check.go, cli/breakglass_check_test.go]
  modified: []

key-decisions:
  - "Followed sentinel_list.go pattern for breakglass-list command"
  - "Followed check.go pattern for breakglass-check command"
  - "Reused formatDuration from check.go for human-readable duration output"
  - "Query priority: status > profile > invoker (same as sentinel list)"

patterns-established:
  - "Break-glass CLI commands follow existing approval workflow patterns"
  - "BreakGlassEventSummary struct for list output, BreakGlassCheckCommandOutput for detail view"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-15
---

# Phase 32 Plan 01: Break-Glass List/Check Commands Summary

**`sentinel breakglass-list` and `sentinel breakglass-check` commands for post-incident review of emergency access events**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-15T21:00:00Z
- **Completed:** 2026-01-15T21:04:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created `sentinel breakglass-list` command with filter support for invoker, status, profile
- Created `sentinel breakglass-check` command with full event detail output
- Both commands output JSON for easy integration with tooling
- Comprehensive test coverage for all filter combinations and edge cases

## Task Commits

Each task was committed atomically:

1. **Task 1: Create breakglass-list CLI command** - `4116bb6` (feat)
2. **Task 2: Create breakglass-check CLI command** - `ea950d8` (feat)

## Files Created/Modified

- `cli/breakglass_list.go` - BreakGlassListCommand with ConfigureBreakGlassListCommand
- `cli/breakglass_list_test.go` - Table-driven tests for all filter combinations
- `cli/breakglass_check.go` - BreakGlassCheckCommand with ConfigureBreakGlassCheckCommand
- `cli/breakglass_check_test.go` - Tests for success, not found, invalid ID, all states

## Decisions Made

- **Pattern consistency**: Followed existing sentinel_list.go and check.go patterns exactly
- **Query priority**: status > profile > invoker (same as approval request list)
- **Default behavior**: If no filter specified, default to current user's events
- **Duration formatting**: Reused formatDuration from check.go for human-readable output

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Both commands registered and appearing in `sentinel --help`
- Ready for 32-02: breakglass-close command with notifications/logging
- All verification checks passing

---
*Phase: 32-post-incident-review*
*Completed: 2026-01-15*
