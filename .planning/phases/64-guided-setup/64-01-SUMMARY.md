---
phase: 64-guided-setup
plan: 01
subsystem: bootstrap
tags: [wizard, cli, interactive, setup, ssm, iam]

# Dependency graph
requires:
  - phase: 61-permissions-command
    provides: permissions.FormatJSON for IAM policy generation
  - phase: 63-permission-validation
    provides: permissions.Feature types and validation
provides:
  - sentinel init wizard command for guided first-time setup
  - Interactive profile and feature selection flow
  - Non-interactive mode with --profile/--feature/--format flags
  - IAM policy and sample policy generation
affects: [documentation, getting-started]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Interactive wizard flow with step-by-step guidance
    - Dual output mode (human/JSON) for scripting integration
    - Profile discovery via vault.LoadConfigFromEnv()

key-files:
  created:
    - cli/init_wizard.go
  modified:
    - cli/init_wizard_test.go
    - cmd/sentinel/main.go

key-decisions:
  - "Wizard is subcommand (sentinel init wizard) rather than parent action due to kingpin limitations"
  - "Non-interactive mode triggered when both --profile and --feature flags provided"
  - "Uses existing vault.LoadConfigFromEnv() for profile discovery from ~/.aws/config"

patterns-established:
  - "Wizard flow pattern: Welcome -> Profile Selection -> Feature Selection -> Region -> Output Options -> Summary -> Output"
  - "Prompt helpers: promptMultiSelect, promptYesNo, promptString for consistent interaction"

issues-created: []

# Metrics
duration: 6min
completed: 2026-01-18
---

# Phase 64 Plan 01: Init Wizard Summary

**Interactive setup wizard for guided Sentinel configuration with profile discovery, feature selection, and IAM/sample policy generation**

## Performance

- **Duration:** 6 min
- **Started:** 2026-01-18T21:16:31Z
- **Completed:** 2026-01-18T21:22:05Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created `sentinel init wizard` interactive command for first-time setup
- Implemented profile discovery from ~/.aws/config using vault.LoadConfigFromEnv()
- Built step-by-step wizard flow: Welcome -> Profiles -> Features -> Region -> Output Options -> Summary
- Added non-interactive mode with --profile/--feature/--format flags for scripting
- Generated IAM policy using permissions.FormatJSON() matching permissions command
- Generated sample Sentinel policies using bootstrap.GenerateSamplePolicy()
- Dual output format (human-readable and JSON) for both interactive and scripted use

## Task Commits

Each task was committed atomically:

1. **Task 1: Create wizard types and flow logic** - `628ab94` (feat)
2. **Task 2: Create `sentinel init wizard` CLI command with tests** - `afeb192` (feat)

## Files Created/Modified

- `cli/init_wizard.go` - Wizard types (WizardState, WizardStep, InitWizardCommandInput), prompt helpers, flow logic, output formatters
- `cli/init_wizard_test.go` - Tests for non-interactive mode, JSON output, prompt helpers, output generation
- `cmd/sentinel/main.go` - Wired ConfigureInitWizardCommand

## Decisions Made

1. **Wizard as subcommand** - Implemented as `sentinel init wizard` rather than making `sentinel init` itself run the wizard, due to kingpin's limitation with parent command default actions when subcommands exist
2. **Non-interactive trigger** - Non-interactive mode activates when both --profile and --feature flags are provided (allows partial interactive with just one flag)
3. **Profile discovery** - Reused vault.LoadConfigFromEnv() pattern for discovering AWS profiles rather than implementing custom parsing

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- Wizard functional for guided setup
- IAM policy generation verified against permissions.FormatJSON
- Sample policy generation verified against bootstrap.GenerateSamplePolicy
- Ready for integration testing with real AWS profiles

---
*Phase: 64-guided-setup*
*Completed: 2026-01-18*
