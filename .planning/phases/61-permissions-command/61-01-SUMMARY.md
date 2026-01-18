---
phase: 61-permissions-command
plan: 01
subsystem: permissions
tags: [cli, iam, permissions, terraform, cloudformation, hcl, yaml, json]

# Dependency graph
requires:
  - phase: 60-permissions-schema
    provides: Permission types and registry
provides:
  - Permission formatters (human, JSON, Terraform HCL, CloudFormation YAML)
  - sentinel permissions CLI command with filtering
affects: [62-permissions-check, documentation, getting-started]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Output formatters return string, not write directly
    - groupByResource consolidation for IAM policy optimization
    - EnumVar for kingpin format validation

key-files:
  created:
    - permissions/format.go
    - permissions/format_test.go
    - cli/permissions.go
    - cli/permissions_test.go
  modified:
    - cmd/sentinel/main.go

key-decisions:
  - "Terraform uses aws_iam_policy_document data source format"
  - "CloudFormation uses AWS::IAM::ManagedPolicy resource format"
  - "groupByResource merges permissions by ARN to reduce statement count"
  - "cf alias for cloudformation format for brevity"

patterns-established:
  - "IAMPolicyDocument struct mirrors bootstrap/iam.go pattern"
  - "Format functions return string for flexibility in output"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-18
---

# Phase 61 Plan 01: Permissions Command Summary

**New `sentinel permissions` CLI command with four output formats (human, JSON, Terraform, CloudFormation) for direct use in infrastructure code**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-18T07:48:49Z
- **Completed:** 2026-01-18T07:52:49Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Created four permission formatters: human-readable, JSON IAM policy, Terraform HCL, CloudFormation YAML
- Built `sentinel permissions` CLI command with subsystem/feature filtering and required-only mode
- Implemented groupByResource helper for consolidating permissions by ARN pattern
- Added comprehensive test coverage for all formats and filter combinations

## Task Commits

Each task was committed atomically:

1. **Task 1: Create permission formatters** - `a8b010e` (feat)
2. **Task 2: Create permissions CLI command** - `1a5bcf8` (feat)

## Files Created/Modified

- `permissions/format.go` - FormatHuman, FormatJSON, FormatTerraform, FormatCloudFormation functions
- `permissions/format_test.go` - Comprehensive tests for all formatters and groupByResource
- `cli/permissions.go` - PermissionsCommand with format, subsystem, feature, required-only flags
- `cli/permissions_test.go` - Tests for all flag combinations and error cases
- `cmd/sentinel/main.go` - Added ConfigurePermissionsCommand wiring

## Decisions Made

1. **Terraform format:** Uses `data "aws_iam_policy_document" "sentinel"` data source format (most common pattern)
2. **CloudFormation format:** Uses `AWS::IAM::ManagedPolicy` resource type with PolicyDocument
3. **Statement consolidation:** groupByResource merges actions by resource ARN to produce cleaner policies
4. **Format alias:** `cf` accepted as shorthand for `cloudformation` for CLI convenience

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Permissions command fully operational
- Ready for Phase 62 (Permission Check) or Phase 61 Plan 02 (if exists)

---
*Phase: 61-permissions-command*
*Completed: 2026-01-18*
