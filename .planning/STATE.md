# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-27)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.22 TVM Only - Remove classic mode entirely. We don't ship fakeable security.

## Current Position

Phase: 156 of 156 (Remove Classic Mode)
Plan: 2 of 2 in current phase (COMPLETE)
Status: Phase 156 complete, v1.22 TVM Only milestone complete
Last activity: 2026-01-27 — Plan 156-02 completed (documentation and migration guide)

Progress: [██████████████████████████] 100% (156/156 phases complete)

## Performance Metrics

**Velocity:**
- Total plans completed: 231 (through v1.20)
- Average duration: ~12 min per plan
- Total execution time: ~46 hours across 23 milestones

**By Recent Milestone:**

| Milestone | Plans | Total Time | Avg/Plan |
|-----------|-------|------------|----------|
| v1.18 | 24 | 1 day | ~60 min |
| v1.19 | 7 | 1 day | ~206 min |
| v1.20 | 7 | 1 day | ~206 min |

**Recent Trend:**
- Last 5 milestones averaged 1-2 days each
- Trend: Stable (consistent delivery velocity)

*Updated after each plan completion*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table (449 decisions through v1.20).
Recent decisions affecting v1.21 work:

- v1.17: Policy schema Version type with validation helpers
- v1.18: KMS-based policy signing with fail-closed security
- v1.18: Security regression test infrastructure with 153 tests
- v1.19: Documentation completeness audit patterns
- v1.20: Policy linting, trust policy validation, deployment validation patterns
- v1.21/150-01: Go toolchain directive (go1.24.1) for byteness/keyring compatibility
- v1.21/150-01: Error wrapping pattern: fmt.Errorf %w for errors.Is() compatibility
- v1.21/150-01: smithy.GenericAPIError for AWS SDK errors without specific types
- v1.21/150-02: Go 1.25 socket cleanup - use regular file to simulate stale socket in tests
- v1.21/150-02: DynamoDB expression attribute names (#pk pattern) for reserved words
- v1.21/150-02: Security sanitization strips control chars rather than rejecting
- v1.21/150-02: 1password SDK requires CGO or vendor stub for builds
- v1.21/150-03: Race detector requires CGO/gcc - use CI environment for race detection
- v1.21/150-04: STRIDE coverage documentation pattern - meta-tests verify coverage mapping
- v1.21/150-05: CLI integration test pattern - go run with help verification for all commands
- v1.21/151-01: Token refresh buffer of 5 minutes before expiry for Azure AD tokens
- v1.21/151-01: APIToken format client_id:client_secret for Intune OAuth2 credentials
- v1.21/151-01: Device lookup fallback (azureADDeviceId then deviceName)
- v1.21/152-03: File permission constants in cli/global.go for consistent security enforcement
- v1.21/152-03: SensitiveFileMode (0600) for policy/signature files, LogFileMode (0640) for logs
- v1.21/152-03: ConfigFileMode (0644) matches aws-cli defaults for ~/.aws/config interoperability
- v1.21/152-04: Security-focused fuzz test seed corpus with injection patterns
- v1.21/152-04: Property-based verification in fuzz tests for security invariants
- v1.21/152-02: SCP template command replaces direct deployment (SCP-T-01 mitigation)
- v1.21/152-02: Deprecation pattern: hidden command with informative error
- v1.21/152-01: KMS encryption required for SSM backup (SEC-05 mitigation)
- v1.21/152-01: KMSEncryptAPI interface pattern for testable KMS operations
- v1.21/153-01: Consolidated SCP documentation into single reference (SCP_REFERENCE.md)
- v1.21/153-01: Superseded LAMBDA_TVM_SCP.md with notice rather than removal
- v1.22/156-01: ErrServerDeprecated pattern for deprecated functions with migration instructions
- v1.22/156-01: t.Skip pattern for deprecated tests - preserves tests for gradual migration
- v1.22/156-02: Migration guide format: Why Changed > What Changed > Migration Steps > FAQ
- v1.22/156-02: SENTINEL_TVM_URL environment variable pattern for TVM URL configuration

### Pending Todos

None (v1.22 milestone complete).

### Blockers/Concerns

- **1password SDK CGO requirement**: The SDK v0.4.0-beta.2 has a broken build constraint. Builds without CGO fail. Either need gcc in CI or vendor directory management strategy.

## Session Continuity

Last session: 2026-01-27
Stopped at: Milestone v1.22 TVM Only complete
Resume file: None

---
*State initialized: 2026-01-27*
*Last updated: 2026-01-28 (156-02 complete, v1.22 milestone complete)*
