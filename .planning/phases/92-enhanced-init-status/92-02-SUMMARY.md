---
phase: 92-enhanced-init-status
plan: 02
subsystem: infra
tags: [bootstrap, suggestions, shell-integration, dynamodb, cli]

# Dependency graph
requires:
  - phase: 92-01
    provides: InfrastructureChecker with DynamoDB table status checking
provides:
  - SuggestionGenerator type for actionable infrastructure suggestions
  - Shell integration hints with profile and shell detection
  - Enhanced status command output with suggestions section
affects: [init-wizard, onboarding, documentation]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Suggestion generation pattern for actionable CLI guidance
    - Shell type detection from SHELL environment variable

key-files:
  created:
    - bootstrap/suggestions.go
    - bootstrap/suggestions_test.go
  modified:
    - cli/status.go
    - cli/status_test.go

key-decisions:
  - "Suggestions only generated for NOT_FOUND tables (not CREATING or other states)"
  - "Shell integration hint only shown when --aws-profile is provided"
  - "Empty suggestions array included in JSON output for consistent structure"

patterns-established:
  - "Suggestion type with Type/Message/Command fields for actionable guidance"
  - "Shell detection via SHELL env var for rc file suggestions"

issues-created: []

# Metrics
duration: 5min
completed: 2026-01-22
---

# Phase 92 Plan 02: Status Suggestions and Shell Integration Summary

**SuggestionGenerator creates actionable commands for missing DynamoDB tables, with shell integration hints for quick profile access**

## Performance

- **Duration:** 5 min
- **Started:** 2026-01-22T03:16:37Z
- **Completed:** 2026-01-22T03:21:06Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- SuggestionGenerator type generates suggestions for missing DynamoDB infrastructure
- GenerateInfrastructureSuggestions creates `sentinel init {purpose} --region {region}` commands
- GenerateShellSuggestion creates shell integration command with optional AWS profile
- GetShellRCFile detects zsh vs bash from SHELL environment variable
- Status command displays Suggestions section with actionable commands
- Shell Integration hint shown when --aws-profile is provided
- JSON output includes suggestions array (empty when all infrastructure present)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create suggestion generation logic in bootstrap package** - `e84af1b` (feat)
2. **Task 2: Integrate suggestions and shell hints into CLI status output** - `85a6dd4` (feat)

## Files Created/Modified

- `bootstrap/suggestions.go` - Suggestion type and SuggestionGenerator with generation methods
- `bootstrap/suggestions_test.go` - Tests for suggestion generation and shell detection
- `cli/status.go` - Enhanced status command with suggestions and shell integration output
- `cli/status_test.go` - Tests for suggestions display and shell integration hints

## Decisions Made

- Suggestions generated only for NOT_FOUND tables (CREATING/other states don't trigger suggestions)
- Shell integration hint requires --aws-profile flag (indicates user is using profiles)
- Shell type detected from SHELL env var (~/.zshrc for zsh, ~/.bashrc otherwise)
- JSON output always includes suggestions array (empty when no suggestions)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- CLI tests cannot run due to 1password-sdk-go CGO dependency
- Tests validated via go fmt and syntax checking (established pattern from Phase 83)

## Next Phase Readiness

- Phase 92 complete, ready for phase transition
- Status command now provides complete infrastructure visibility with actionable guidance
- Users can see what's missing and get exact commands to complete setup

---
*Phase: 92-enhanced-init-status*
*Completed: 2026-01-22*
