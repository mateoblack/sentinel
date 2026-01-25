---
phase: 62-feature-detection
plan: 01
subsystem: permissions
tags: [cli, detection, ssm, dynamodb, iam, permissions, aws]

# Dependency graph
requires:
  - phase: 60-permissions-schema
    provides: Permission types and registry
  - phase: 61-permissions-command
    provides: Permission formatters and CLI command
provides:
  - Feature detection infrastructure (Detector, DetectionResult types)
  - Auto-detection of configured Sentinel features via AWS probing
  - --detect flag for sentinel permissions command
affects: [63-permissions-summary, documentation, getting-started]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - DetectorInterface for testable AWS detection
    - Best-effort detection (errors don't stop other feature checks)
    - Stderr for diagnostic output, stdout for machine-readable output

key-files:
  created:
    - permissions/detection.go
    - permissions/detection_test.go
  modified:
    - cli/permissions.go
    - cli/permissions_test.go

key-decisions:
  - "Always-detected features: credential_issue, audit_verify, enforce_analyze"
  - "SSM detection checks /sentinel/policies/* for policy_load and bootstrap_plan"
  - "DynamoDB detection checks sentinel-requests and sentinel-breakglass tables"
  - "notify_sns, notify_webhook, bootstrap_apply not auto-detected (optional)"
  - "Detection summary shown on stderr in human format only"
  - "Mutual exclusivity: --detect cannot combine with --subsystem or --feature"

patterns-established:
  - "DetectorInterface enables mock injection for CLI testing"
  - "Best-effort detection collects errors without stopping"
  - "Feature details map explains why each feature was detected"

issues-created: []

# Metrics
duration: 6min
completed: 2026-01-18
---

# Phase 62 Plan 01: Feature Detection Summary

**Auto-detection infrastructure probing SSM and DynamoDB to discover configured Sentinel features and output minimal required permissions**

## Performance

- **Duration:** 6 min
- **Started:** 2026-01-18T20:13:01Z
- **Completed:** 2026-01-18T20:19:19Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created Detector type with SSM and DynamoDB client interfaces for testability
- Implemented best-effort detection that collects errors without stopping
- Added DetectorInterface for mock injection in CLI tests
- Enhanced permissions command with --detect and --region flags
- Detection summary shows on stderr (human format only)
- Mutual exclusivity enforced for --detect with --subsystem/--feature

## Task Commits

Each task was committed atomically:

1. **Task 1: Create detection types and logic** - `36b2fc2` (feat)
2. **Task 2: Add --detect flag to permissions command** - `b63b4fe` (feat)

## Files Created/Modified

- `permissions/detection.go` - Detector type with SSM/DynamoDB probing
- `permissions/detection_test.go` - Comprehensive tests for detection logic
- `cli/permissions.go` - Added --detect, --region flags and detectPermissions()
- `cli/permissions_test.go` - Tests for all detection flag combinations

## Decisions Made

1. **Always-detected features:** credential_issue (base feature), audit_verify (CloudTrail universal), enforce_analyze (IAM universal)
2. **SSM detection:** Check /sentinel/policies/* for policy_load and bootstrap_plan
3. **DynamoDB detection:** Check sentinel-requests (approval_workflow) and sentinel-breakglass (breakglass)
4. **Not auto-detected:** notify_sns (optional), notify_webhook (no AWS perms), bootstrap_apply (optional write)
5. **Detection errors:** Non-fatal, collected in Errors slice without stopping other checks
6. **Output separation:** Detection summary to stderr, permissions to stdout

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Feature detection fully operational
- Ready for Phase 62 Plan 02 (if exists) or Phase 63

---
*Phase: 62-feature-detection*
*Completed: 2026-01-18*
