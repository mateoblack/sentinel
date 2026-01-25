---
phase: 98-credential-vending
plan: 03
subsystem: iam
tags: [lambda, iam, trust-policy, sts, assume-role, terraform]

# Dependency graph
requires:
  - phase: 98-01
    provides: Lambda handler skeleton and AssumeRole integration design
provides:
  - Lambda execution role IAM policy template
  - Protected role trust policy templates with SourceIdentity conditions
  - IAM naming conventions for TVM roles
  - Security guidance for preventing direct AssumeRole bypass
affects: [phase-102-infrastructure-as-code, lambda-deployment]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Protected roles trust only Lambda execution role"
    - "SourceIdentity condition for trust policy enforcement"
    - "SentinelProtected-* naming convention"

key-files:
  created:
    - docs/iam/LAMBDA_ROLES.md
  modified: []

key-decisions:
  - "Lambda execution role uses wildcard SentinelProtected-* for role assumption"
  - "Protected roles require sentinel:*:*:* SourceIdentity pattern"
  - "SCP defense-in-depth pattern included for additional security"

patterns-established:
  - "Lambda execution role naming: SentinelTVMLambda"
  - "Protected role naming: SentinelProtected-<profile>"
  - "Trust policy always includes sts:SourceIdentity condition"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-25
---

# Phase 98 Plan 03: Lambda IAM Role Templates Summary

**IAM role templates and trust policies for Lambda TVM deployment with SourceIdentity enforcement**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-25T00:55:10Z
- **Completed:** 2026-01-25T00:57:01Z
- **Tasks:** 1
- **Files created:** 1

## Accomplishments

- Lambda execution role IAM policy documented with minimum permissions
- Protected role trust policy template with SourceIdentity condition
- Naming conventions established (SentinelProtected-*, SentinelTVMLambda)
- Security considerations explained (why direct AssumeRole bypass is prevented)
- Terraform example provided for Lambda TVM deployment
- Cross-account setup guidance included

## Task Commits

Each task was committed atomically:

1. **Task 1: Create Lambda IAM role documentation** - `b055cc2` (docs)

## Files Created/Modified

- `docs/iam/LAMBDA_ROLES.md` - Complete IAM role templates and security guidance for Lambda TVM

## Decisions Made

1. **Wildcard role assumption pattern** - Lambda execution role uses `SentinelProtected-*` resource pattern for AssumeRole, allowing any role following naming convention
2. **SourceIdentity condition required** - Protected role trust policies always include `sts:SourceIdentity` condition with `sentinel:*:*:*` pattern
3. **SCP defense-in-depth** - Included optional SCP pattern to block direct AssumeRole to protected roles for organizations wanting extra security

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- IAM role templates ready for Phase 102 (Infrastructure as Code) Terraform modules
- Documentation complete for Lambda TVM deployment guide
- Security patterns established for trust policy configuration

---
*Phase: 98-credential-vending*
*Completed: 2026-01-25*
