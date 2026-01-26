---
phase: 132-keyring-protection
plan: 01
subsystem: security
tags: [keyring, keychain, macOS, Linux, keyctl, credential-protection]

# Dependency graph
requires:
  - phase: 129-local-server-security
    provides: Security hardening patterns for local storage
provides:
  - Hardened keyring configuration with platform-specific access controls
  - macOS Keychain items protected from other applications and iCloud sync
  - Linux keyctl items restricted to possessor-only permissions
affects: [any future keyring storage work, credential security]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - macOS Keychain defense-in-depth (config + item level settings)
    - Linux keyctl possessor-only permission mask

key-files:
  created: []
  modified:
    - cli/global.go
    - cli/sentinel.go
    - vault/credentialkeyring.go
    - vault/sessionkeyring.go
    - vault/oidctokenkeyring.go

key-decisions:
  - "Set KeychainAccessibleWhenUnlocked: false to prevent access when device locked"
  - "Set KeychainSynchronizable: false at both config and item level (defense in depth)"
  - "Use possessor-only permissions (0x3f000000) for Linux keyctl to prevent even same-user access"

patterns-established:
  - "Defense in depth: security settings at both config and item level"
  - "Platform-specific security hardening with detailed comments"

issues-created: []

# Metrics
duration: 4min
completed: 2026-01-26
---

# Phase 132 Plan 01: Keyring Protection Hardening Summary

**Hardened keyring storage with macOS Keychain and Linux keyctl platform-specific access controls to prevent credential theft by other local processes**

## Performance

- **Duration:** 4 min
- **Started:** 2026-01-26T14:50:03Z
- **Completed:** 2026-01-26T14:54:10Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- macOS Keychain config hardened with AccessibleWhenUnlocked: false and Synchronizable: false
- All keyring items (credentials, sessions, OIDC tokens) protected with KeychainNotTrustApplication and KeychainNotSynchronizable
- Linux keyctl backend configured with possessor-only permissions (0x3f000000) to prevent other processes from accessing keys

## Task Commits

Each task was committed atomically:

1. **Task 1: Harden macOS Keychain settings in config** - `2e65adb` (feat)
2. **Task 2: Add KeychainNotTrustApplication to all keyring items** - `60f2060` (feat)
3. **Task 3: Add Linux keyctl permission restrictions** - `4f91966` (feat)

## Files Created/Modified

- `cli/global.go` - Added macOS Keychain and Linux keyctl security settings to keyringConfigDefaults
- `cli/sentinel.go` - Added matching security settings to sentinelKeyringConfigDefaults
- `vault/credentialkeyring.go` - Added KeychainNotTrustApplication and KeychainNotSynchronizable to item storage
- `vault/sessionkeyring.go` - Added KeychainNotTrustApplication and KeychainNotSynchronizable to session storage
- `vault/oidctokenkeyring.go` - Added KeychainNotTrustApplication and KeychainNotSynchronizable to OIDC token storage

## Decisions Made

1. **Defense in depth for macOS Keychain**: Set security settings at both config level (KeychainAccessibleWhenUnlocked, KeychainSynchronizable) and item level (KeychainNotTrustApplication, KeychainNotSynchronizable) to ensure protection even if one layer is bypassed

2. **Possessor-only permissions for Linux keyctl**: Used `KEYCTL_PERM_ALL << KEYCTL_PERM_PROCESS` (0x3f000000) to restrict access to only the process that created the key, preventing even other processes running as the same user from accessing credentials

3. **Explicit security comments**: Added detailed comments explaining each security setting to help future maintainers understand the protection model

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

**Build verification limitation**: The 1Password SDK dependency has a platform-specific CGO issue that prevents full compilation in the CI environment. The code changes were verified by:
- Confirming field names exist in keyring.Config struct (verified from library source)
- Syntax verification via gofmt
- Grep verification of all required settings in target files

This is a pre-existing dependency issue unrelated to the security hardening changes.

## Next Phase Readiness

- Keyring protection hardening complete
- Ready for 132-02 security regression tests
- No blockers or concerns

---
*Phase: 132-keyring-protection*
*Completed: 2026-01-26*
