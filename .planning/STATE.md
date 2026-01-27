# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-27)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v2.0 Stable Release - Production-ready release with comprehensive testing, security hardening, and documentation

## Current Position

Phase: 152 of 155 (Security Hardening)
Plan: 2 of 4 in current phase
Status: Complete
Last activity: 2026-01-27 — Completed 152-02-PLAN.md (SCP template command)

Progress: [████████████████████████░] 97% (151/155 phases complete)

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
Recent decisions affecting v2.0 work:

- v1.17: Policy schema Version type with validation helpers
- v1.18: KMS-based policy signing with fail-closed security
- v1.18: Security regression test infrastructure with 153 tests
- v1.19: Documentation completeness audit patterns
- v1.20: Policy linting, trust policy validation, deployment validation patterns
- v2.0/150-01: Go toolchain directive (go1.24.1) for byteness/keyring compatibility
- v2.0/150-01: Error wrapping pattern: fmt.Errorf %w for errors.Is() compatibility
- v2.0/150-01: smithy.GenericAPIError for AWS SDK errors without specific types
- v2.0/150-02: Go 1.25 socket cleanup - use regular file to simulate stale socket in tests
- v2.0/150-02: DynamoDB expression attribute names (#pk pattern) for reserved words
- v2.0/150-02: Security sanitization strips control chars rather than rejecting
- v2.0/150-02: 1password SDK requires CGO or vendor stub for builds
- v2.0/150-03: Race detector requires CGO/gcc - use CI environment for race detection
- v2.0/150-04: STRIDE coverage documentation pattern - meta-tests verify coverage mapping
- v2.0/150-05: CLI integration test pattern - go run with help verification for all commands
- v2.0/151-01: Token refresh buffer of 5 minutes before expiry for Azure AD tokens
- v2.0/151-01: APIToken format client_id:client_secret for Intune OAuth2 credentials
- v2.0/151-01: Device lookup fallback (azureADDeviceId then deviceName)
- v2.0/152-03: File permission constants in cli/global.go for consistent security enforcement
- v2.0/152-03: SensitiveFileMode (0600) for policy/signature files, LogFileMode (0640) for logs
- v2.0/152-03: ConfigFileMode (0644) matches aws-cli defaults for ~/.aws/config interoperability
- v2.0/152-04: Security-focused fuzz test seed corpus with injection patterns
- v2.0/152-04: Property-based verification in fuzz tests for security invariants
- v2.0/152-02: SCP template command replaces direct deployment (SCP-T-01 mitigation)
- v2.0/152-02: Deprecation pattern: hidden command with informative error

### Pending Todos

None yet (v2.0 milestone just started).

### Blockers/Concerns

- **1password SDK CGO requirement**: The SDK v0.4.0-beta.2 has a broken build constraint. Builds without CGO fail. Either need gcc in CI or vendor directory management strategy.

## Session Continuity

Last session: 2026-01-27
Stopped at: Completed 152-02-PLAN.md (SCP template command)
Resume file: None

---
*State initialized: 2026-01-27*
*Last updated: 2026-01-27 (Plan 152-02 complete)*
