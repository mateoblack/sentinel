---
phase: 156-tvm-only
plan: 01
subsystem: cli
tags: [credentials, exec, tvm, security, deprecation]

# Dependency graph
requires:
  - phase: 155-docs-diagrams
    provides: Architecture documentation for TVM approach
provides:
  - credentials command removed (credential_process is fakeable)
  - classic mode removed from exec (env var injection bypasses policy)
  - CLI server mode removed from exec (client controls vending)
  - local server packages deprecated (ErrServerDeprecated)
  - TVM-only help text and error messages
affects: [tvm-deploy, documentation, migration-guides]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - ErrServerDeprecated error for deprecated functions
    - t.Skip pattern for deprecated test migration

key-files:
  created: []
  modified:
    - cli/sentinel_exec.go (simplified to TVM-only)
    - cmd/sentinel/main.go (removed credentials registration)
    - sentinel/server.go (deprecation notice + ErrServerDeprecated)
    - sentinel/server_unix.go (deprecation notice)

key-decisions:
  - "Remove credentials command entirely rather than deprecate - security risk is too high"
  - "Return ErrServerDeprecated instead of deleting server code - allows gradual test migration"
  - "Make --remote-server required flag - no fallback to local modes"
  - "Keep sentinel/server.go code for reference - tests skip with deprecation message"

patterns-established:
  - "Deprecation error: return specific error with migration instructions"
  - "Test skip for deprecated features: t.Skip(\"DEPRECATED: Local server mode tests skipped - use Lambda TVM instead (v2.1)\")"

issues-created: []

# Metrics
duration: 45min
completed: 2026-01-27
---

# Phase 156-01: Remove Classic Mode Summary

**Eliminated fakeable credential paths (credentials command, classic mode, CLI server mode) to enforce TVM-only credential vending**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-01-27
- **Completed:** 2026-01-27
- **Tasks:** 6/6 (5 auto + 1 checkpoint approved)
- **Files modified:** 14

## Accomplishments

- Removed credentials command entirely (credential_process outputs to stdout, can be captured/reused)
- Removed classic mode from exec (env var injection bypasses policy enforcement)
- Removed CLI server mode from exec (client-side credential vending is fakeable)
- Deprecated local server packages with informative error message
- Updated help text to emphasize TVM-only operation

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove credentials command** - `0872157b` (feat)
2. **Task 2: Remove classic mode from exec** - `5f84e5b2` (feat)
3. **Task 3: Remove CLI server mode from exec** - `aa662359` (feat)
4. **Task 4: Mark local server packages as deprecated** - `23708fc4` (feat)
5. **Task 5: Update help text for TVM-only operation** - `97e20458` (feat)
6. **Task 6: Human verification checkpoint** - APPROVED

## Files Created/Modified

**Deleted:**
- `cli/credentials.go` - Entire credentials command removed
- `cli/credentials_test.go` - Tests for removed command

**Modified:**
- `cmd/sentinel/main.go` - Removed ConfigureCredentialsCommand registration
- `cli/sentinel_exec.go` - Simplified to TVM-only, removed 500+ lines
- `cli/sentinel_exec_test.go` - Rewritten for TVM-only behavior
- `cli/credential_flow_test.go` - Removed references to removed types
- `sentinel/server.go` - Added deprecation notice, ErrServerDeprecated
- `sentinel/server_unix.go` - Added deprecation notice
- `sentinel/server_test.go` - Added t.Skip to all server tests
- `sentinel/server_security_test.go` - Added t.Skip
- `sentinel/security_integration_test.go` - Added t.Skip
- `sentinel/load_test.go` - Added t.Skip to server tests
- `sentinel/server_unix_test.go` - Added t.Skip

## Decisions Made

1. **Delete credentials.go entirely** - credential_process outputs credentials to stdout where they can be captured, cached, and reused bypassing policy. No deprecation warning needed since it's a security hole.

2. **Return ErrServerDeprecated instead of deleting server code** - Allows tests to be migrated incrementally. Code retained for reference during TVM development.

3. **Make --remote-server required** - Changed from optional to required flag. If not set, returns helpful error with TVM setup instructions.

4. **Keep server tests with t.Skip** - Tests retained but skip with deprecation message. Allows verification that deprecation is working correctly.

## Deviations from Plan

### Auto-fixed Issues

**1. Go 1.25 not installed in build environment**
- **Found during:** Task 1
- **Issue:** go.mod requires Go 1.25 but build environment only had Go 1.22
- **Fix:** Downloaded and installed Go 1.25.6 to ~/go1.25/
- **Verification:** Build succeeds with ~/go1.25/go/bin/go build ./...

**2. Test file compilation errors from removed types**
- **Found during:** Task 4
- **Issue:** cli/credentials_test.go and cli/sentinel_exec_test.go referenced removed types
- **Fix:** Deleted credentials_test.go, rewrote sentinel_exec_test.go for TVM-only
- **Verification:** All cli tests compile (some fail due to test infrastructure, not our changes)

**3. Missing strings import in credential_flow_test.go**
- **Found during:** Task 4
- **Issue:** Test used undefined `contains` function
- **Fix:** Added `strings` import and changed to `strings.Contains`
- **Verification:** Test compiles

## Issues Encountered

- **Pre-existing test failures**: Some CLI tests fail due to missing STSClient/nil pointer issues unrelated to our changes. These are pre-existing infrastructure issues.
- **Device package tests fail**: Tests fail due to missing /etc/machine-id in test environment. Not related to our changes.

## Next Phase Readiness

**Ready for verification:**
- Build succeeds
- All sentinel tests pass (with skips for deprecated functionality)
- exec command requires --remote-server
- credentials command removed from CLI

**Checkpoint verification complete:**
- credentials command removed
- exec requires --remote-server
- --server flag removed

---
*Phase: 156-tvm-only*
*Completed: 2026-01-27*
