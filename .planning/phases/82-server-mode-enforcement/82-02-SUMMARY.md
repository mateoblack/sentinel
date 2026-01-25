---
phase: 82-server-mode-enforcement
plan: 02
subsystem: cli
tags: [cli, error-handling, require_server, documentation]

# Dependency graph
requires:
  - phase: 82-server-mode-enforcement
    provides: RequiresServerMode field in policy.Decision struct
provides:
  - Actionable error messages for require_server denials in credentials command
  - Actionable error messages for require_server denials in exec command
  - Documentation for require_server effect in policy-reference.md
affects: [server, users]

# Tech tracking
tech-stack:
  added: []
  patterns: [require_server-bypass-prevention]

key-files:
  created: []
  modified: [cli/credentials.go, cli/sentinel_exec.go, docs/guide/policy-reference.md]

key-decisions:
  - "require_server denials cannot be bypassed by approval workflows or break-glass"
  - "Actionable error messages guide users to use --server flag"

patterns-established:
  - "Bypass prevention pattern: require_server check before approval/break-glass override"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-20
---

# Phase 82 Plan 02: Require Server CLI Integration Summary

**Integrated require_server denial handling in CLI commands with actionable error messages and documented the feature in policy-reference.md**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-20T02:48:20Z
- **Completed:** 2026-01-20T02:50:24Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Added require_server error handling to credentials command with guidance to use `sentinel exec --server`
- Added require_server error handling to exec command with guidance to add `--server` flag
- Documented require_server effect in policy-reference.md with examples and behavior table

## Task Commits

Each task was committed atomically:

1. **Task 1: Add require_server error handling to credentials command** - `613b096` (feat)
2. **Task 2: Add require_server error handling to exec command** - `18dfb5e` (feat)
3. **Task 3: Document require_server effect in policy reference** - `afb7edc` (docs)

## Files Created/Modified

- `cli/credentials.go` - Added RequiresServerMode check before approval/break-glass bypass
- `cli/sentinel_exec.go` - Added RequiresServerMode check before approval/break-glass bypass
- `docs/guide/policy-reference.md` - Added require_server to Effects table and explanation section

## Decisions Made

- **Bypass prevention:** require_server denials are checked BEFORE approval workflows and break-glass checks, ensuring server mode cannot be bypassed by emergency access mechanisms. This is intentional - if you need emergency access that bypasses server mode, use a separate rule with allow effect.
- **Actionable messages:** Error messages tell users exactly what to do - credentials command suggests full `sentinel exec --server <profile> -- <command>` pattern, exec command suggests adding `--server` flag.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- require_server effect fully integrated in CLI commands
- Documentation complete for users
- Ready for phase completion or additional server mode features

---
*Phase: 82-server-mode-enforcement*
*Completed: 2026-01-20*
