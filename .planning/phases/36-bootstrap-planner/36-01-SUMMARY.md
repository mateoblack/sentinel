---
phase: 36-bootstrap-planner
plan: 01
subsystem: bootstrap
tags: [bootstrap, ssm, planner, dry-run, format]

# Dependency graph
requires:
  - phase: 35-bootstrap-schema
    provides: BootstrapConfig, ProfileConfig, ResourceSpec, BootstrapPlan, PlanSummary, validation
provides:
  - Planner struct with SSM existence checks
  - ssmAPI interface for testability
  - Plan() method producing BootstrapPlan
  - FormatPlan() for human-readable terraform-style output
  - FormatPlanJSON() for machine-readable JSON output
affects: [40-bootstrap-command, 41-status-command]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - SSM interface pattern (ssmAPI) following notification/sns.go
    - Mock-based testing for AWS services
    - terraform-style plan output format

key-files:
  created:
    - bootstrap/planner.go
    - bootstrap/planner_test.go
    - bootstrap/format.go
    - bootstrap/format_test.go
  modified: []

key-decisions:
  - "ssmAPI interface follows notification/sns.go pattern for testability"
  - "Planner validates config before making any SSM calls"
  - "IAM policy documents always show StateCreate (generated, not actual IAM resources)"
  - "Format symbols: + (create), ~ (update), = (exists), - (skip)"

patterns-established:
  - "AWS SDK mock pattern: interface + mockXxxAPI struct with function fields"
  - "Plan output grouped by ResourceType when multiple types present"
  - "Version captured from SSM GetParameter response for exists state"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-15
---

# Phase 36 Plan 01: Bootstrap Planner Summary

**Dry-run planner with SSM existence checks and terraform-style plan output formatting**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-15T19:42:00Z
- **Completed:** 2026-01-15T19:45:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created Planner struct with ssmAPI interface for SSM parameter existence checks
- Implemented Plan() method that validates config, checks SSM parameters, and builds BootstrapPlan
- Added checkSSMParameter() helper using errors.As for ParameterNotFound detection
- Created FormatPlan() for human-readable terraform-style output with state symbols
- Added FormatPlanJSON() for machine-readable JSON output
- Comprehensive tests with mockSSMAPI for all scenarios

## Task Commits

Each task was committed atomically:

1. **Task 1: Create SSM interface and Planner with existence checks** - `72862db` (feat)
2. **Task 2: Create plan output formatting** - `2f6c277` (feat)

## Files Created/Modified

- `bootstrap/planner.go` - Planner struct with Plan() and checkSSMParameter() methods
- `bootstrap/planner_test.go` - mockSSMAPI and comprehensive tests for all scenarios
- `bootstrap/format.go` - FormatPlan() and FormatPlanJSON() functions
- `bootstrap/format_test.go` - Tests for all format scenarios including round-trip

## Decisions Made

- **ssmAPI interface pattern**: Following notification/sns.go pattern with interface for testability
- **Validation before SSM calls**: Planner validates config first, returns error without SSM calls if invalid
- **IAM policy state**: Always StateCreate since we generate documents, not actual IAM resources
- **Format symbols**: + for create, ~ for update, = for exists, - for skip
- **Grouped output**: Resources grouped by type when multiple types present

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Planner ready for bootstrap command integration (Phase 40)
- FormatPlan output ready for CLI display
- FormatPlanJSON ready for --json flag support
- All types and methods follow established patterns

---
*Phase: 36-bootstrap-planner*
*Completed: 2026-01-15*
