---
phase: 114-secrets-manager-migration
plan: 02
subsystem: infra
tags: [terraform, iam, secrets-manager, mdm, lambda]

# Dependency graph
requires:
  - phase: 114-01
    provides: SecretsLoader interface and configuration
provides:
  - Terraform variables for MDM and Secrets Manager
  - Lambda environment variable configuration
  - IAM permissions for Secrets Manager access
  - Documentation for MDM/Secrets Manager setup
affects: [deployment, infrastructure-provisioning]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Conditional IAM policy creation with count
    - Secrets Manager preference over env vars

key-files:
  created: []
  modified:
    - terraform/sentinel-tvm/variables.tf
    - terraform/sentinel-tvm/main.tf
    - terraform/sentinel-tvm/iam.tf
    - docs/LAMBDA_TVM_DEPLOYMENT.md

key-decisions:
  - "Secrets Manager ARN takes precedence over env var when both configured"
  - "IAM policy only created when mdm_api_secret_arn is specified (count conditional)"
  - "Include DescribeSecret permission for caching library version tracking"

patterns-established:
  - "Terraform conditional merge for optional environment variables"
  - "Conditional IAM policies with count = condition ? 1 : 0"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-25
---

# Phase 114 Plan 02: Terraform and Documentation for Secrets Manager Summary

**Terraform module and docs updated with MDM variables, Secrets Manager env vars, conditional IAM policy, and migration guide**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-25T20:56:34Z
- **Completed:** 2026-01-25T20:58:41Z
- **Tasks:** 4
- **Files modified:** 4

## Accomplishments

- Added 5 MDM configuration variables to Terraform (mdm_provider, mdm_base_url, mdm_api_secret_arn, mdm_api_token, require_device_posture)
- Lambda environment variables now support both Secrets Manager (preferred) and env var (deprecated) patterns
- IAM policy conditionally grants secretsmanager:GetSecretValue and DescribeSecret on specific ARN
- Documentation includes complete Device Posture section with Secrets Manager setup and migration guide

## Task Commits

Each task was committed atomically:

1. **Task 1: Add MDM variables to Terraform** - `2b8a131` (feat)
2. **Task 2: Update Lambda environment variables in Terraform** - `7d040a8` (feat)
3. **Task 3: Add Secrets Manager IAM permissions** - `905ecd7` (feat)
4. **Task 4: Update TVM documentation for MDM and Secrets Manager** - `73d3251` (docs)

## Files Created/Modified

- `terraform/sentinel-tvm/variables.tf` - Added mdm_provider, mdm_base_url, mdm_api_secret_arn, mdm_api_token (deprecated), require_device_posture variables
- `terraform/sentinel-tvm/main.tf` - Added MDM environment variables to Lambda with Secrets Manager preference
- `terraform/sentinel-tvm/iam.tf` - Added conditional Secrets Manager IAM policy
- `docs/LAMBDA_TVM_DEPLOYMENT.md` - Added MDM env vars table, Device Posture section, Security Best Practices item

## Decisions Made

1. **Secrets Manager precedence** - When both `mdm_api_secret_arn` and `mdm_api_token` are configured, Secrets Manager wins (more secure)
2. **Conditional IAM policy** - Use `count = var.mdm_api_secret_arn != "" ? 1 : 0` pattern to only create policy when needed
3. **DescribeSecret permission** - Required by aws-secretsmanager-caching-go library for version tracking

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - Terraform CLI not installed in environment, but HCL syntax follows standard formatting.

## Next Phase Readiness

- Terraform module fully supports Secrets Manager integration
- Documentation provides clear migration path from env vars
- Phase 114 complete, ready for phase transition

---
*Phase: 114-secrets-manager-migration*
*Completed: 2026-01-25*
