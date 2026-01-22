---
phase: 90-session-table-provisioning
plan: 01
subsystem: infra
tags: [dynamodb, schema, session, infrastructure]

# Dependency graph
requires:
  - phase: 89-breakglass-table-provisioning
    provides: BreakGlassTableSchema pattern
provides:
  - SessionTableSchema() function for session table provisioning
affects: [90-02, 90-03, 91, 92, 93]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - SessionTableSchema follows BreakGlassTableSchema pattern with 4 GSIs

key-files:
  created: []
  modified:
    - infrastructure/schema.go
    - infrastructure/schema_test.go

key-decisions:
  - "SessionTableSchema has 4 GSIs (vs 3 for approval/breakglass) to support server instance queries"
  - "gsi-server-instance uses status as sort key (not created_at) matching session/dynamodb.go FindActiveByServerInstance query pattern"

patterns-established:
  - "Predefined schema functions for each Sentinel table type"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-22
---

# Phase 90 Plan 01: Session Table Schema Summary

**SessionTableSchema function for sentinel-sessions table with 4 GSIs: gsi-user, gsi-status, gsi-profile, gsi-server-instance**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-22T01:16:00Z
- **Completed:** 2026-01-22T01:19:01Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Added SessionTableSchema(tableName string) function to infrastructure/schema.go
- Schema matches session/dynamodb.go GSI constants (gsi-user, gsi-status, gsi-profile, gsi-server-instance)
- gsi-server-instance correctly uses server_instance_id as PK and status as SK (different from other GSIs)
- Comprehensive test coverage verifying all schema properties and unique GSI sort key

## Task Commits

Each task was committed atomically:

1. **Task 1: Add SessionTableSchema function** - `b3701a0` (feat)
2. **Task 2: Add tests for SessionTableSchema** - `1d0e0f9` (test)

## Files Created/Modified
- `infrastructure/schema.go` - Added SessionTableSchema function with 4 GSIs
- `infrastructure/schema_test.go` - Added TestSessionTableSchema, TestSessionTableSchemaGSINames, TestSessionTableSchemaGSIServerInstanceSortKey

## Decisions Made
- Used 4 GSIs for session table (vs 3 for approval/breakglass) to support server instance queries
- gsi-server-instance uses status as sort key to enable FindActiveByServerInstance queries that filter by status

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- SessionTableSchema ready for use in table creation logic (90-02)
- Schema correctly models sentinel-sessions table
- Test coverage ensures reliable validation

---
*Phase: 90-session-table-provisioning*
*Completed: 2026-01-22*
