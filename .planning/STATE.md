# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-16)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.6 Testing & Hardening — comprehensive test coverage before production

## Current Position

Phase: 54 of 59 (SourceIdentity & Fingerprinting Tests)
Plan: 1 of 2 in current phase
Status: In progress
Last activity: 2026-01-17 — Completed 54-01-PLAN.md (Fingerprint Generation Tests)

Progress: █████░░░░░ 44% (v1.6 Testing & Hardening)

## Milestone Summary

**v1.0 MVP shipped:** 2026-01-14
- 8 phases, 16 plans, ~40 tasks
- 10,762 lines of Go
- Policy-gated credential issuance via credential_process and exec

**v1.1 Sentinel Fingerprint shipped:** 2026-01-15
- 9 phases, 12 plans, ~30 tasks
- +3,224 lines of Go (13,986 total)
- SourceIdentity stamping on all role assumptions
- CloudTrail correlation and IAM enforcement patterns

**v1.2 Approval Workflows shipped:** 2026-01-15
- 9 phases, 18 plans, ~45 tasks
- +9,671 lines of Go (23,657 total)
- Request/approve flow with DynamoDB state machine
- SNS and Webhook notification hooks
- Approval policies with auto-approve conditions
- Approval audit trail logging

**v1.3 Break-Glass shipped:** 2026-01-16
- 8 phases, 15 plans, ~40 tasks
- +12,069 lines of Go (35,726 total)
- Emergency access model with state machine
- DynamoDB storage with TTL and GSI queries
- Elevated audit logging with incident correlation
- Time-bounded sessions with duration capping
- Immediate security notifications
- Post-incident review commands
- Rate limiting with cooldowns and quotas
- Policy-based authorization control

**v1.4 Sentinel Bootstrapping shipped:** 2026-01-16
- 8 phases, 8 plans
- +9,087 lines of Go (44,813 total)
- Bootstrap planner with SSM existence checks
- Automated SSM parameter creation
- Sample policy generation
- IAM policy document generation
- Status command for deployment health

**v1.5 Enforcement & Assurance shipped:** 2026-01-16
- 7 phases, 8 plans
- +4,775 lines of Go (49,588 total)
- IAM trust policy analysis and enforcement status
- Trust policy template generation (Pattern A/B/C)
- CloudTrail session verification
- Audit verify command for compliance
- Drift detection with --require-sentinel flag
- Complete enforcement documentation

## Performance Metrics

**Velocity:**
- Total plans completed: 80
- Average duration: 3.0 min
- Total execution time: ~245 min

**By Milestone:**

| Milestone | Phases | Plans | Total Time |
|-----------|--------|-------|------------|
| v1.0 MVP | 8 | 16 | ~37 min |
| v1.1 Sentinel Fingerprint | 9 | 12 | ~29 min |
| v1.2 Approval Workflows | 9 | 17 | ~44 min |
| v1.3 Break-Glass | 8 | 15 | ~45 min |
| v1.4 Sentinel Bootstrapping | 8 | 8 | ~20 min |
| v1.5 Enforcement & Assurance | 7 | 8 | ~20 min |

## Accumulated Context

### Decisions

Key decisions from v1.0, v1.1, and v1.2 logged in PROJECT.md Key Decisions table.

**v1.3 Break-Glass decisions (Phase 33-34):**
- Rate limit check order: cooldown -> user quota -> profile quota -> escalation flag
- Escalation threshold does not block, only flags for notification
- RetryAfter only populated for cooldown blocks (quota blocks have no simple retry time)
- Empty AllowedReasonCodes = all reason codes allowed (wildcard)
- Empty Profiles = rule applies to all profiles (wildcard)
- MaxDuration 0 = no cap (use system default)

**v1.4 Bootstrap Schema decisions (Phase 35):**
- ResourceState includes 'exists' and 'skip' as separate states for clarity
- PlanSummary.ToSkip counts both skip and exists states
- SSM path validation uses regex for alphanumeric, /, -, _ characters
- Profile name validation matches AWS conventions (alphanumeric, -, _)

**v1.4 Bootstrap Planner decisions (Phase 36):**
- ssmAPI interface follows notification/sns.go pattern for testability
- Planner validates config before making any SSM calls
- IAM policy documents always show StateCreate (generated, not actual IAM resources)
- Format symbols: + (create), ~ (update), = (exists), - (skip)

**v1.4 SSM Parameter Creation decisions (Phase 37):**
- Use String type for parameters (not SecureString) since policy YAML is not sensitive
- Overwrite=false for create to detect race conditions
- Continue processing on individual failures (don't abort entire apply)
- Skip IAM policy resources (not SSM) and non-actionable states

**v1.4 Status Command decisions (Phase 41):**
- Separate ssmStatusAPI interface (GetParametersByPath) from planner's ssmAPI (GetParameter)
- Non-recursive query (Recursive=false) to get direct children only
- Human output includes profile name padding for alignment

**v1.5 CloudTrail Query Types decisions (Phase 46):**
- cloudtrailAPI interface follows notification/sns.go pattern for testability
- ParseSourceIdentity uses SplitN for handling colons in request-id
- PassRate returns 100% for zero sessions (no issues is success)
- Issues created as warnings for non-Sentinel sessions

**v1.5 Audit Verify Command decisions (Phase 47):**
- SessionVerifier interface enables CLI testing with mock verifiers
- Return non-zero exit code when issues found for scripting integration
- Human output shows time window, summary stats, pass rate, and detailed issues
- JSON output marshals VerificationResult directly for machine parsing

**v1.5 Require Sentinel Mode decisions (Phase 48):**
- DriftChecker uses existing Advisor for IAM analysis
- Drift checking is advisory only - credentials still issued despite warnings
- TestDriftChecker enables CLI testing with custom check functions
- DriftStatus mapped from existing EnforcementStatus (Full->OK, Partial->Partial, None->None)

**v1.5 Enforcement Documentation decisions (Phase 49):**
- CLI Commands section placed after How Enforcement Works for concept-to-command flow
- Drift Detection section placed before Troubleshooting for operational focus
- ASSURANCE.md structured around three verification levels: deployment, runtime, continuous

**v1.6 Mock Framework decisions (Phase 50-02):**
- Mocks use function fields (XxxFunc) for maximum flexibility over interface embedding
- Thread-safe call tracking with sync.Mutex for concurrent test support
- In-memory storage maps in store mocks for stateful test scenarios
- Interface verification tests ensure mocks stay in sync with interfaces
- Generic assertion helpers (AssertEqual) for any comparable type

**v1.6 SSM Loader Tests decisions (Phase 51-01):**
- Export SSMAPI interface for external test package compatibility
- Use testutil.MockSSMClient rather than internal mock for consistency
- NewLoaderWithClient constructor pattern for testable AWS-dependent types

**v1.6 Coverage Gap Tests decisions (Phase 51-02):**
- Double-check locking path is defensive code, tested via concurrent access patterns
- 98.6% coverage exceeds 95% target despite untested race condition guard
- Table-driven tests for exhaustive weekday/time edge cases

**v1.6 Security Gating Tests decisions (Phase 51-03):**
- Use policy_test package to avoid import cycle with breakglass/request packages
- Test finder functions directly with mock stores rather than via CLI integration
- External test package pattern for cross-domain testing in policy package

**v1.6 Rate Limiting Security Tests decisions (Phase 52-01):**
- Security-critical check order verified via call-tracking mock (orderTrackingStore)
- Boundary tests confirm >= comparison for quotas, < comparison for cooldown
- Rule matching tests verify first-match-wins and case sensitivity

**v1.6 Audit Trail Integrity Tests decisions (Phase 52-03):**
- Audit all events including invalid types (no audit bypass through malformed input)
- Expired events must NOT have ClosedBy/ClosedReason (system expired, not user closed)
- All event constants must have "breakglass." namespace prefix for filtering

**v1.6 Approval State Machine Tests decisions (Phase 53-01):**
- Coverage at 84.3% for request package - core validation/state machine at 100%
- Timestamp manipulation tests document behavior rather than enforce constraints
- Concurrent tests use mock store with first-writer-wins for deterministic testing

**v1.6 Notification Security Tests decisions (Phase 53-02):**
- Coverage at 89.9% for notification package - uncovered code is AWS constructors and pass-through methods
- Used httptest.Server for webhook tests, mockSNSClient for SNS tests
- Fire-and-forget semantics verified for context cancellation
- Goroutine leak detection uses runtime.NumGoroutine baseline/final comparison

### Deferred Issues

None — clean implementation across all milestones.

### Blockers/Concerns Carried Forward

None — clean start for v1.4.

## Session Continuity

Last session: 2026-01-17
Stopped at: Completed 54-01-PLAN.md (Plan 1 of 2 in Phase 54)
Resume file: None
Next: 54-02-PLAN.md (CloudTrail Query Tests)

## Roadmap Evolution

- Milestone v1.0 shipped: 2026-01-14 — MVP (Phases 1-8)
- Milestone v1.1 shipped: 2026-01-15 — Sentinel Fingerprint (Phases 9-17)
- Milestone v1.2 shipped: 2026-01-15 — Approval Workflows (Phases 18-26)
- Milestone v1.3 shipped: 2026-01-16 — Break-Glass (Phases 27-34)
- Milestone v1.4 shipped: 2026-01-16 — Sentinel Bootstrapping (Phases 35-42)
- Milestone v1.5 shipped: 2026-01-16 — Enforcement & Assurance (Phases 43-49)
- Milestone v1.6 created: 2026-01-16 — Testing & Hardening (Phases 50-59, 25 plans)
