---
phase: 106-local-device-collector
plan: 01
subsystem: device
tags: [machineid, device-id, identification, hardware-id, sha256]

# Dependency graph
requires:
  - phase: 105-device-collector-interface
    provides: Collector interface, MultiCollector, CollectorConfig
provides:
  - GetDeviceID() function for stable hardware identification
  - ValidateDeviceIdentifier() for 64-char hex validation
  - AppID constant for application-specific HMAC isolation
affects: [107-mdm-api-integration, 108-policy-device-conditions, 109-device-attestation-flow]

# Tech tracking
tech-stack:
  added:
    - github.com/denisbrodbeck/machineid v1.0.1
  patterns:
    - "HMAC-SHA256 hashing of machine ID with app-specific key"
    - "Device identification only, NOT posture collection (CONSTRAINTS.md)"

key-files:
  created:
    - device/identity.go
    - device/identity_test.go
  modified:
    - go.mod

key-decisions:
  - "Use machineid.ProtectedID() for HMAC-SHA256 hashed device ID"
  - "AppID 'sentinel-device-posture' isolates from other apps using same library"
  - "64-char hex format (SHA256) differs from DevicePosture DeviceID (32-char)"
  - "On error return empty string, NOT random ID (defeats correlation purpose)"

patterns-established:
  - "Device identification via GetDeviceID() for CLI to TVM communication"
  - "Server-side posture verification (TVM queries MDM, not CLI)"

issues-created: []

# Metrics
duration: 3min
completed: 2026-01-25
---

# Phase 106 Plan 01: Device Identity Module Summary

**Stable hardware device identification using machineid library with HMAC-SHA256 hashing for CLI-to-TVM correlation**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-25T06:15:00Z
- **Completed:** 2026-01-25T06:18:00Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Added machineid library for cross-platform hardware ID retrieval (macOS IOPlatformUUID, Linux /etc/machine-id, Windows MachineGuid)
- Created GetDeviceID() returning HMAC-SHA256 hashed device ID (64 lowercase hex chars)
- Implemented ValidateDeviceIdentifier() for TVM to validate incoming device IDs
- AppID constant ensures Sentinel device IDs are isolated from other applications
- Comprehensive test suite verifying stability, format, and protection from raw ID exposure

## Task Commits

Each task was committed atomically:

1. **Task 1: Add machineid dependency** - `8b9d69b` (chore)
2. **Task 2: Create device identity module** - `d9df343` (feat)
3. **Task 3: Add device identity tests** - `071712a` (test)

## Files Created/Modified

- `go.mod` - Added github.com/denisbrodbeck/machineid v1.0.1 dependency
- `device/identity.go` - GetDeviceID(), ValidateDeviceIdentifier(), AppID constant
- `device/identity_test.go` - 5 test functions covering stability, format, validation

## Decisions Made

1. **machineid.ProtectedID vs machineid.ID:** Used ProtectedID() which returns HMAC-SHA256(AppID, machineID) rather than raw machine ID - follows freedesktop.org security recommendations
2. **64-char format:** SHA256 output is 64 hex chars, distinct from DevicePosture DeviceID (32 chars) - larger for stronger fingerprint uniqueness
3. **Error handling:** Return empty string on error, NOT random ID - random would defeat the purpose of stable correlation
4. **No posture collection:** Per CONSTRAINTS.md, CLI collects device ID only; TVM queries MDM for actual posture

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Go 1.25 toolchain not available in environment; used GOTOOLCHAIN=local and manual go.mod edit to add dependency. Does not affect production builds.

## Next Phase Readiness

- Device identity ready for Phase 107 (MDM API Integration)
- TVM can receive device ID from CLI and use it to query Jamf/Intune/Kandji
- ValidateDeviceIdentifier() available for TVM input validation
- Architecture ensures clients cannot fake posture - server-verified only

---
*Phase: 106-local-device-collector*
*Completed: 2026-01-25*
