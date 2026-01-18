---
phase: 65-error-enhancement
plan: 01
subsystem: errors
tags: [errors, aws, ssm, dynamodb, iam, suggestions]

# Dependency graph
requires:
  - phase: 64-guided-setup
    provides: cli init wizard for setup flow
provides:
  - SentinelError interface for structured error handling
  - Error codes for SSM, DynamoDB, IAM, Policy, and Config errors
  - AWS error classifiers (WrapSSMError, WrapDynamoDBError, WrapIAMError)
  - NewPolicyDeniedError with approval workflow and break-glass alternatives
  - Fix suggestions registry for all error codes
affects: [cli-commands, credential-issuance, policy-loading, error-messages]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - SentinelError interface wrapping standard errors with Code(), Suggestion(), Context()
    - Error classifier pattern examining error strings for AWS error types
    - Fix suggestions registry mapping error codes to actionable guidance

key-files:
  created:
    - errors/types.go
    - errors/types_test.go
    - errors/suggestions.go
    - errors/suggestions_test.go
  modified: []

key-decisions:
  - "SentinelError interface provides Unwrap() for error chain compatibility"
  - "Error classifiers use string matching for AWS error detection (reliable across SDK versions)"
  - "NewPolicyDeniedError includes approval workflow and break-glass alternatives when available"
  - "All error codes have default suggestions in centralized registry"

patterns-established:
  - "Error wrapping pattern: WrapXxxError(err, context...) returns SentinelError"
  - "Context chaining: WithContext(err, key, value) returns new error without mutating original"
  - "Nil-safe classifiers: WrapXxxError(nil, ...) returns nil"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-18
---

# Phase 65 Plan 01: Structured Error Types Summary

**New errors package with SentinelError interface, AWS error classifiers, and actionable fix suggestions for SSM, DynamoDB, IAM, and policy errors**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-18T21:37:37Z
- **Completed:** 2026-01-18T21:40:47Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created SentinelError interface with Code(), Suggestion(), Context() for structured error handling
- Defined 17 error codes covering SSM, DynamoDB, IAM, Policy, and Config errors
- Implemented AWS error classifiers (WrapSSMError, WrapDynamoDBError, WrapIAMError) that detect error types and provide context
- Created NewPolicyDeniedError with approval workflow and break-glass alternative suggestions
- Built centralized fix suggestions registry with actionable guidance for each error code
- Added comprehensive tests covering all error types, classifiers, and edge cases

## Task Commits

Each task was committed atomically:

1. **Task 1: Create structured error types** - `66a23b8` (feat)
2. **Task 2: Create AWS error classification and suggestions** - `9828a2d` (feat)

## Files Created/Modified

- `errors/types.go` - SentinelError interface, sentinelError struct, error codes, New/WithContext/IsSentinelError/GetCode helpers
- `errors/types_test.go` - Tests for interface implementation, all methods, and constructors
- `errors/suggestions.go` - WrapSSMError, WrapDynamoDBError, WrapIAMError classifiers, NewPolicyDeniedError, suggestions registry, error detection helpers
- `errors/suggestions_test.go` - Tests for all classifiers, policy denied scenarios, helper functions, suggestion coverage

## Decisions Made

1. **SentinelError interface design** - Includes Unwrap() for standard error chain compatibility (errors.Is/errors.As work)
2. **String-based error detection** - Uses lowercase string matching for AWS error types (reliable across SDK versions, handles various error formats)
3. **Context immutability** - WithContext() creates new error rather than mutating original for safety
4. **Alternative suggestions** - NewPolicyDeniedError includes approval workflow and break-glass commands when those features are available

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## Next Phase Readiness

- errors package provides foundation for enhanced error messages
- Ready for integration into CLI commands and credential issuance flows
- Ready for Phase 65-02: Error integration with CLI commands

---
*Phase: 65-error-enhancement*
*Completed: 2026-01-18*
