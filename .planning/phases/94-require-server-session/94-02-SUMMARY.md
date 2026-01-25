---
phase: 94-require-server-session
plan: 02
subsystem: cli
tags: [policy, cli, session-tracking, error-messages]

# Dependency graph
requires:
  - phase: 94
    plan: 01
    provides: EffectRequireServerSession, RequiresSessionTracking, SessionTableName
provides:
  - SessionTableName passed to policy.Request in exec command
  - SessionTableName passed to policy.Request in credentials command
  - Actionable error messages for require_server_session denials
affects: [cli-server-mode-docs, session-tracking-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Distinct error messages based on RequiresSessionTracking and RequiresServerMode flags

key-files:
  created: []
  modified:
    - cli/sentinel_exec.go
    - cli/credentials.go
    - cli/sentinel_exec_test.go
    - cli/credentials_test.go

key-decisions:
  - "Error messages guide users to exact flags needed based on decision flags"
  - "credential_process explicitly notes it doesn't support session tracking"
  - "Three distinct error scenarios: both flags, session only, server only"

patterns-established:
  - "Check RequiresSessionTracking || RequiresServerMode before approval/breakglass bypass checks"
  - "Actionable error messages include full command examples"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-24
---

# Phase 94 Plan 02: CLI Error Messages for require_server_session Summary

**CLI integration for require_server_session with actionable error messages guiding users to --server --session-table flags**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-24T21:20:36Z
- **Completed:** 2026-01-24T21:23:52Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- SessionTableName passed from input to policy.Request in exec command
- SessionTableName explicitly empty in credentials command (doesn't support sessions)
- Distinct actionable error messages for three scenarios:
  - Both server mode and session tracking required
  - Session tracking only (already in server mode)
  - Server mode only (no session tracking requirement)
- Comprehensive tests for all mode/session table combinations

## Task Commits

Each task was committed atomically:

1. **Task 1: Pass session table name to policy Request in exec command** - `411843e` (feat)
2. **Task 2: Pass session table name to policy Request in credentials command** - `b46f00d` (feat)
3. **Task 3: Add tests for require_server_session CLI enforcement** - `e27f790` (test)

## Files Created/Modified
- `cli/sentinel_exec.go` - Added SessionTableName to policy.Request, updated error handling
- `cli/credentials.go` - Set empty SessionTableName, updated error handling for credential_process
- `cli/sentinel_exec_test.go` - Added 15 new tests for require_server_session scenarios
- `cli/credentials_test.go` - Added 5 new tests for credential_process with require_server_session

## Decisions Made
- Error messages include full command examples (e.g., `sentinel exec --server --session-table <table> --profile X -- <cmd>`)
- credential_process error explicitly states it doesn't support session tracking
- RequiresSessionTracking and RequiresServerMode checks happen before approval/breakglass bypass checks (these requirements cannot be bypassed)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- CLI commands now properly enforce require_server_session policy effect
- Error messages guide users to the correct command and flags
- Ready for documentation updates or server-side session tracking integration

---
*Phase: 94-require-server-session*
*Completed: 2026-01-24*
