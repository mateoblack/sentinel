---
phase: 80-short-lived-sessions
plan: 01
subsystem: policy, credentials
tags: [server-mode, session-duration, time-based-revocation, credential-rotation]

# Dependency graph
requires:
  - phase: 79-server-mode
    provides: SentinelServer credential handler, policy evaluation per request
provides:
  - DefaultServerSessionDuration constant (15 min)
  - --server-duration CLI flag
  - MaxServerDuration per-rule policy field
  - Policy-based duration capping in server handler
affects: [credential-revocation, policy-reference-docs, cli-docs]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Server duration default: 15 min for rapid revocation"
    - "Policy cap -> break-glass cap -> final duration ordering"

key-files:
  created: []
  modified:
    - sentinel/server.go
    - cli/sentinel_exec.go
    - policy/types.go
    - policy/evaluate.go

key-decisions:
  - "DefaultServerSessionDuration=15min - balances security (rapid revocation) with performance (SDK caching)"
  - "0 value for MaxServerDuration means no policy-imposed limit"
  - "Duration capping order: policy cap first, then break-glass cap (smallest wins)"

patterns-established:
  - "Per-rule duration caps: policy rules can limit session duration via MaxServerDuration"
  - "Capping order: config -> policy -> break-glass -> final (each can only reduce, not increase)"

issues-created: []

# Metrics
duration: 5min
completed: 2026-01-20
---

# Phase 80 Plan 01: Short-Lived Sessions Summary

**15-minute default server sessions with policy-based duration caps for rapid credential revocation**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-20T01:47:10Z
- **Completed:** 2026-01-20T01:52:12Z
- **Tasks:** 4
- **Files modified:** 7

## Accomplishments
- Added DefaultServerSessionDuration constant (15 min) for server mode credentials
- Added --server-duration CLI flag for explicit session duration control
- Added MaxServerDuration field to policy Rule for per-rule duration limits
- Applied policy-based duration capping in server credential handler

## Task Commits

Each task was committed atomically:

1. **Task 1: DefaultServerSessionDuration constant and --server-duration flag** - `3a69920` (feat)
2. **Task 2: MaxServerDuration to policy Rule** - `18c8961` (feat)
3. **Task 3: Policy-based duration capping in server handler** - `bbe33c5` (feat)
4. **Task 4: Tests for server duration handling** - `626fc1e` (test)

## Files Created/Modified
- `sentinel/server.go` - Added DefaultServerSessionDuration constant (15 min) and policy cap logic
- `cli/sentinel_exec.go` - Added ServerDuration field and --server-duration flag
- `policy/types.go` - Added MaxServerDuration field to Rule struct
- `policy/evaluate.go` - Added MaxServerDuration field to Decision struct
- `sentinel/server_test.go` - Added duration capping tests
- `policy/evaluate_test.go` - Added MaxServerDuration evaluation tests
- `cli/sentinel_exec_test.go` - Added ServerDuration field tests

## Decisions Made
- **15-minute default:** Balances security (rapid revocation within 15 min) with performance (AWS SDKs cache credentials, refresh 5 min before expiry)
- **Policy cap ordering:** Policy cap applied before break-glass cap, ensuring smallest cap always wins
- **0 = no cap:** Following existing pattern from BreakGlassPolicyRule.MaxDuration

## Deviations from Plan

None - plan executed exactly as written

## Issues Encountered

None

## Next Phase Readiness
- Server mode now uses short-lived sessions by default
- Policy authors can set per-rule MaxServerDuration caps
- Ready for credential_process mode implementation (Plan 02) or policy docs update

---
*Phase: 80-short-lived-sessions*
*Plan: 01*
*Completed: 2026-01-20*
