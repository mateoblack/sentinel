---
phase: 89-breakglass-table-provisioning
plan: 01
subsystem: infra
tags: [dynamodb, schema, breakglass, infrastructure]

# Dependency graph
requires:
  - phase: 88-approval-table-provisioning
    provides: TableSchema types and ApprovalTableSchema pattern
provides:
  - BreakGlassTableSchema() function for break-glass table provisioning
affects: [89-02, 89-03, 90, 91, 92, 93]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - BreakGlassTableSchema follows ApprovalTableSchema pattern

key-files:
  created: []
  modified:
    - infrastructure/schema.go
    - infrastructure/schema_test.go

key-decisions:
  - "BreakGlassTableSchema uses gsi-invoker (not gsi-requester) matching breakglass/dynamodb.go"
  - "Schema structure identical to ApprovalTableSchema except first GSI partition key"

patterns-established:
  - "Predefined schema functions for each Sentinel table type"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-22
---

# Phase 89 Plan 01: Break-Glass Table Schema Summary

**BreakGlassTableSchema function for sentinel-breakglass table with gsi-invoker, gsi-status, gsi-profile GSIs**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-22T01:03:49Z
- **Completed:** 2026-01-22T01:07:30Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Added BreakGlassTableSchema(tableName string) function to infrastructure/schema.go
- Schema matches breakglass/dynamodb.go GSI constants (gsi-invoker, gsi-status, gsi-profile)
- Comprehensive test coverage verifying all schema properties

## Task Commits

Each task was committed atomically:

1. **Task 1: Add BreakGlassTableSchema function** - `b5583f0` (feat)
2. **Task 2: Add tests for BreakGlassTableSchema** - `27c2733` (test)

## Files Created/Modified
- `infrastructure/schema.go` - Added BreakGlassTableSchema function
- `infrastructure/schema_test.go` - Added TestBreakGlassTableSchema and TestBreakGlassTableSchemaGSINames

## Decisions Made
- Used gsi-invoker as first GSI name to match breakglass/dynamodb.go constants
- Schema structure mirrors ApprovalTableSchema exactly, only GSI partition key names differ

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- BreakGlassTableSchema ready for use in table creation logic (89-02)
- Schema correctly models sentinel-breakglass table
- Test coverage ensures reliable validation

---
*Phase: 89-breakglass-table-provisioning*
*Completed: 2026-01-22*
