---
phase: 91-unified-bootstrap-extension
plan: 01
subsystem: infra
tags: [dynamodb, bootstrap, cli, provisioning]

# Dependency graph
requires:
  - phase: 88-approval-table-provisioning
    provides: infrastructure.TableProvisioner and schema functions
  - phase: 89-breakglass-table-provisioning
    provides: BreakGlassTableSchema function
  - phase: 90-session-table-provisioning
    provides: SessionTableSchema function
provides:
  - Unified bootstrap command with --with-* flags for DynamoDB table provisioning
  - One-command infrastructure provisioning for all Sentinel features
affects: [documentation, onboarding, infrastructure]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - TableProvisionerInterface for testable DynamoDB provisioning
    - Unified flag resolution (--all expands to individual --with-* flags)

key-files:
  created: []
  modified:
    - cli/bootstrap.go
    - cli/bootstrap_test.go

key-decisions:
  - "Use interface TableProvisionerInterface for testable provisioning"
  - "Resolve --all flag into individual WithApprovals/WithBreakGlass/WithSessions flags"
  - "Require --region when any --with-* flag is used"
  - "Table errors are warnings, don't fail entire operation"
  - "Single confirmation prompt for SSM + DynamoDB operations"

patterns-established:
  - "Interface-based provisioner injection for testing"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-22
---

# Phase 91 Plan 01: Bootstrap Extension Summary

**Extended sentinel init bootstrap with --with-approvals, --with-breakglass, --with-sessions, and --all flags for unified DynamoDB table provisioning**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-22T01:39:12Z
- **Completed:** 2026-01-22T01:42:52Z
- **Tasks:** 3
- **Files modified:** 2

## Accomplishments

- Extended BootstrapCommandInput with DynamoDB table provisioning flags
- Implemented provisionTables function for coordinated table creation
- Added TableProvisionerInterface for testable provisioning
- Comprehensive test coverage for all flag scenarios

## Task Commits

Each task was committed atomically:

1. **Task 1: Add --with-* flags to bootstrap command** - `e3b5d68` (feat)
2. **Task 2: Implement table provisioning in BootstrapCommand** - `86bf24c` (feat)
3. **Task 3: Add tests for bootstrap table provisioning** - `864c1f0` (test)

## Files Created/Modified

- `cli/bootstrap.go` - Extended with DynamoDB table provisioning flags and logic
- `cli/bootstrap_test.go` - Added comprehensive tests for table provisioning

## Decisions Made

1. **Interface-based provisioner** - Created TableProvisionerInterface to enable mock injection for testing, following same pattern as other testable commands
2. **Flag resolution** - --all flag resolves to individual WithApprovals/WithBreakGlass/WithSessions flags in provisionTables function
3. **Region requirement** - Tables require --region flag to be set, validated early in provisionTables
4. **Error handling** - Table provisioning errors are tracked but don't fail the entire operation (warning only)
5. **Single confirmation** - Uses same confirmation as SSM apply (no separate prompt for tables)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - implementation was straightforward using existing patterns from init_approvals.go, init_breakglass.go, and init_sessions.go.

## Next Phase Readiness

- Bootstrap extension complete with all --with-* flags
- Ready for 91-02-PLAN.md (documentation updates)

---
*Phase: 91-unified-bootstrap-extension*
*Completed: 2026-01-22*
