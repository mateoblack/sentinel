---
phase: 82-server-mode-enforcement
plan: 01
subsystem: policy
tags: [policy, effect, server-mode, evaluation]

# Dependency graph
requires:
  - phase: 79-server-policy-integration
    provides: CredentialMode schema and mode-based conditions
provides:
  - EffectRequireServer constant for server-only access enforcement
  - RequiresServerMode field for targeted error messaging
  - Evaluate function handling of require_server effect
affects: [82-02, cli, server]

# Tech tracking
tech-stack:
  added: []
  patterns: [effect-conversion-pattern]

key-files:
  created: []
  modified: [policy/types.go, policy/evaluate.go, policy/evaluate_test.go]

key-decisions:
  - "require_server converts to allow/deny based on mode, preserving rule metadata"
  - "RequiresServerMode flag enables targeted error messages for callers"

patterns-established:
  - "Effect conversion pattern: special effects convert to allow/deny with metadata flags"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-20
---

# Phase 82 Plan 01: Require Server Effect Schema Summary

**Added EffectRequireServer effect with mode-based conversion and RequiresServerMode flag for targeted error messaging**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-20T02:43:47Z
- **Completed:** 2026-01-20T02:46:25Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added EffectRequireServer constant with server-only access semantics
- Added RequiresServerMode field to Decision struct for targeted error handling
- Implemented require_server evaluation logic that converts to allow/deny based on mode
- Added comprehensive tests for require_server effect behavior

## Task Commits

Each task was committed atomically:

1. **Task 1: Add EffectRequireServer constant to policy schema** - `ed1e004` (feat)
2. **Task 2: Add RequiresServerMode field to Decision struct** - `bdd502b` (feat)
3. **Task 3: Implement require_server evaluation logic** - `5b489d3` (feat)
4. **Task 4: Add tests for require_server effect** - `e494a0b` (test)

## Files Created/Modified

- `policy/types.go` - Added EffectRequireServer constant and updated IsValid()
- `policy/evaluate.go` - Added RequiresServerMode field and evaluation logic
- `policy/evaluate_test.go` - Added TestEvaluate_RequireServerEffect and TestEffectRequireServer_IsValid

## Decisions Made

- **Effect conversion pattern:** require_server converts to EffectAllow when mode is server, or EffectDeny with RequiresServerMode=true when mode is not server. This preserves the original rule name and reason in the decision for logging/debugging.
- **RequiresServerMode flag:** Added as a boolean field rather than a reason code to enable callers (CLI, server) to provide targeted error messages without parsing reason strings.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- require_server effect fully implemented and tested
- Ready for 82-02 (CLI error handling for require_server denials)

---
*Phase: 82-server-mode-enforcement*
*Completed: 2026-01-20*
