---
phase: 115-cicd-security-scanning
plan: 01
subsystem: infra
tags: [github-actions, gosec, trivy, sarif, sast, dependency-scanning]

# Dependency graph
requires:
  - phase: none
    provides: existing workflows to fix
provides:
  - Working gosec SAST workflow with SARIF output
  - Working Trivy filesystem dependency scanning with SARIF output
  - Consistent security workflow triggers (push, PR, weekly)
affects: [security-monitoring, github-security-tab]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - SARIF output format for GitHub Security tab integration
    - Weekly scheduled security scans
    - Pinned action versions for reproducibility

key-files:
  created:
    - .github/workflows/trivy-scan.yml
  modified:
    - .github/workflows/goseccheck.yml

key-decisions:
  - "Pin gosec action to v2.22.4 (was @master) for reproducible builds"
  - "Pin trivy-action to v0.29.0 for reproducible builds"
  - "Use filesystem scan for Trivy (not Docker image scan) since no Dockerfile exists"
  - "Consistent weekly schedule (Monday 9am UTC) across all security workflows"

patterns-established:
  - "Security workflows produce SARIF output for GitHub Security tab"
  - "All security workflows triggered on push/PR to main + weekly schedule"

issues-created: []

# Metrics
duration: 1min
completed: 2026-01-25
---

# Phase 115 Plan 01: Fix Security Scanning Workflows Summary

**Fixed gosec and Trivy GitHub Actions workflows with SARIF output for GitHub Security tab integration**

## Performance

- **Duration:** 1 min
- **Started:** 2026-01-25T21:09:02Z
- **Completed:** 2026-01-25T21:10:22Z
- **Tasks:** 2
- **Files modified:** 2 (1 created, 1 modified, 1 deleted)

## Accomplishments

- Fixed gosec workflow: changed branch from master to main, pinned action version, added SARIF output
- Replaced broken Trivy Docker workflow with filesystem dependency scan
- Added GitHub Security tab integration via SARIF upload for both workflows
- Aligned all security workflows with consistent triggers (push, PR, weekly schedule)

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix and enhance gosec workflow** - `5669de4` (fix)
2. **Task 2: Replace Trivy Docker workflow with filesystem scan** - `8479c6c` (fix)

## Files Created/Modified

- `.github/workflows/goseccheck.yml` - Updated SAST scanner: main branch, pinned v2.22.4, SARIF output, weekly schedule
- `.github/workflows/trivy-scan.yml` - NEW: Filesystem dependency scanner replacing broken Docker scan
- `.github/workflows/trivey-scan.yml` - DELETED: Typo filename, broken Docker references

## Decisions Made

1. **Pin action versions instead of @master** - Ensures reproducible builds and avoids breaking changes
2. **Use filesystem scan for Trivy** - Repository has no Dockerfile; filesystem scan checks go.mod/go.sum for vulnerable dependencies
3. **SARIF output format** - Enables GitHub Security tab integration for centralized vulnerability tracking
4. **Consistent weekly schedule** - Monday 9am UTC matches existing govulncheck workflow

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Security scanning workflows are ready to run on next push/PR to main
- GitHub Security tab will receive SARIF reports from gosec and Trivy
- No blockers for remaining security workflow plans

---
*Phase: 115-cicd-security-scanning*
*Completed: 2026-01-25*
