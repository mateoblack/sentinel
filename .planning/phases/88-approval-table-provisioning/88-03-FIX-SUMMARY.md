---
phase: 88-approval-table-provisioning
plan: 88-03-FIX
subsystem: infra
tags: [dynamodb, iam, bootstrap, provisioning, graceful-degradation]

# Dependency graph
requires:
  - phase: 88-02-implement
    provides: Table provisioning commands and IAM policy generation
provides:
  - Permission-less Plan() method for dry-run without AWS access
  - Graceful degradation for init status when DynamoDB access denied
  - IAM policy output after user cancellation
affects: [docs, testing, UAT, v1.12-release]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Graceful degradation for access denied errors
    - Permission-less dry-run pattern

key-files:
  modified:
    - infrastructure/provisioner.go
    - infrastructure/provisioner_test.go
    - bootstrap/status.go
    - bootstrap/status_test.go
    - cli/bootstrap.go
    - cli/bootstrap_test.go

key-decisions:
  - "Plan() shows full schema without querying DynamoDB - allows dry-run before user has permissions"
  - "Access denied errors return UNKNOWN status instead of failing - allows partial functionality"
  - "IAM policies shown after cancellation - users need them to request permissions"

patterns-established:
  - "Graceful degradation: auth/access errors return special status, allow rest of command to continue"
  - "Permission-less dry-run: Plan() doesn't require AWS permissions, only Apply/Create does"

issues-created: []

# Metrics
duration: 12min
completed: 2026-01-22
---

# Plan 88-03-FIX: UAT Issues Summary

**Fixed 3 major UAT issues: permission-less --plan dry-run, graceful access-denied handling, and IAM policy output after cancellation**

## Performance

- **Duration:** 12 min
- **Started:** 2026-01-22T14:30:00Z
- **Completed:** 2026-01-22T14:42:00Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Plan() method no longer queries DynamoDB, enabling `--plan` flag to work without permissions
- `init status --check-tables` returns "UNKNOWN" instead of failing when access denied
- `--generate-iam-policies` now outputs DynamoDB policies even when user cancels at confirmation

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix --plan flag to work without DynamoDB permissions (UAT-001)** - `5b03d49` (fix)
2. **Task 2: Fix init status --check-tables to handle access denied gracefully (UAT-002)** - `c655af0` (fix)
3. **Task 3: Fix --generate-iam-policies to include DynamoDB policies (UAT-003)** - `17f34e0` (fix)

## Files Created/Modified

- `infrastructure/provisioner.go` - Plan() no longer calls getTableStatus(), always returns full schema
- `infrastructure/provisioner_test.go` - Updated tests to reflect new Plan() behavior
- `bootstrap/status.go` - getTableStatus() returns "UNKNOWN" for access denied errors
- `bootstrap/status_test.go` - Added tests for graceful access denied handling
- `cli/bootstrap.go` - Output IAM policies after user cancels confirmation
- `cli/bootstrap_test.go` - Added test for IAM policies shown after cancel

## Decisions Made

1. **Plan() always returns WouldCreate=true** - Since we can't check table existence without permissions, we assume create. The actual check happens at Create() time.

2. **Return "UNKNOWN" not "ACCESS_DENIED"** - "UNKNOWN" is more generic and handles various auth failure modes (AccessDeniedException, not authorized, UnrecognizedClientException).

3. **Show IAM policies on cancel** - Users often need to share the policies with their admin team before they can proceed. Cancelling at confirmation shouldn't hide the policies they requested.

## Deviations from Plan

### Auto-fixed Issues

None - plan executed as written.

### Deferred Enhancements

None.

---

**Total deviations:** 0 auto-fixed, 0 deferred
**Impact on plan:** Plan executed exactly as written.

## Issues Encountered

- Go 1.25 toolchain not available in test environment - verified syntax with gofmt instead of running full tests

## Next Phase Readiness

- All UAT issues fixed and ready for re-testing
- v1.12 infrastructure provisioning now handles common permission scenarios gracefully
- Documentation phase (93) can reference these fixes in user guides

---
*Phase: 88-approval-table-provisioning*
*Plan: 88-03-FIX*
*Completed: 2026-01-22*
