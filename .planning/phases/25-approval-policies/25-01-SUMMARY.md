---
phase: 25-approval-policies
plan: 01
subsystem: policy
tags: [approval, policy, go, yaml, json]

requires:
  - phase: 24-notification-hooks
    provides: notification infrastructure for approval events

provides:
  - EffectRequireApproval constant for policy rules
  - ApprovalPolicy struct for approval routing configuration
  - ApprovalRule struct with profiles and approvers
  - AutoApproveCondition for self-approval with constraints

affects: [25-02, 25-03, 26-approval-audit-trail]

tech-stack:
  added: []
  patterns:
    - Separate access policy (allow/deny/require_approval) from approval routing
    - AutoApproveCondition with time windows and duration caps

key-files:
  created:
    - policy/approval.go
  modified:
    - policy/types.go

key-decisions:
  - "Effect enum extended with require_approval value"
  - "Approval routing separated from access policy for flexibility"
  - "AutoApprove supports user list, time windows, and max duration caps"

patterns-established:
  - "Pattern: Access policy determines if approval needed, approval policy routes to approvers"

issues-created: []

duration: 2min
completed: 2026-01-15
---

# Phase 25 Plan 01: Approval Policy Schema Summary

**EffectRequireApproval constant and ApprovalPolicy types with profile-based approver routing and auto-approve conditions**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-15T08:00:00Z
- **Completed:** 2026-01-15T08:02:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added EffectRequireApproval constant to trigger approval workflow
- Created ApprovalPolicy, ApprovalRule, and AutoApproveCondition types
- Documented approval workflow separation from access policy

## Task Commits

Each task was committed atomically:

1. **Task 1: Add require_approval Effect constant** - `d8ea0b8` (feat)
2. **Task 2: Create ApprovalPolicy types** - `b11cf62` (feat)

## Files Created/Modified

- `policy/types.go` - Added EffectRequireApproval constant, updated IsValid()
- `policy/approval.go` - New file with ApprovalPolicy, ApprovalRule, AutoApproveCondition types

## Decisions Made

- Extended Effect enum rather than creating separate type for approval effects
- Separated approval routing from access policy for flexibility (access policy just marks require_approval, approval policy handles who can approve)
- AutoApproveCondition supports user list, time windows, and max duration caps for fine-grained auto-approval control

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Types ready for validation logic in 25-02
- Types ready for matching logic in 25-03
- No blockers

---
*Phase: 25-approval-policies*
*Completed: 2026-01-15*
