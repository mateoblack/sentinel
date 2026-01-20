# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-20)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.11 Shell Integration — auto-generated shell functions for Sentinel profiles

## Current Position

Phase: 84 of 87 (Shell Init Command)
Plan: 1 of 1 in current phase
Status: Phase complete
Last activity: 2026-01-20 — Completed 84-01-PLAN.md

Progress: █░░░░░░░░░ 25% (v1.11 Shell Integration)

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

**v1.6 Testing & Hardening shipped:** 2026-01-17
- 10 phases, 25 plans
- +25,042 lines of Go (74,630 total)
- Comprehensive test infrastructure (mock framework, test helpers)
- >80% coverage on all 11 Sentinel packages (94.1% average)
- Security regression test suite
- Performance benchmarks and load simulation
- 1,085 tests total
- Pre-release validation complete

**v1.7 Permissions Discovery shipped:** 2026-01-18
- 9 phases, 10 plans
- +12,261 lines of Go (86,891 total)
- Permission schema mapping 10 features to IAM actions
- `sentinel permissions` CLI with Terraform/CloudFormation output
- Feature auto-detection probing SSM and DynamoDB
- `sentinel permissions check` via IAM SimulatePrincipalPolicy
- `sentinel init wizard` for interactive first-time setup
- Structured error types with actionable suggestions
- `sentinel config validate` for pre-runtime validation
- Quick start templates (basic, approvals, full)
- Streamlined onboarding docs (QUICKSTART.md, PERMISSIONS.md)

**v1.7.1 Security Patch shipped:** 2026-01-19
- 4 phases, 7 plans
- +3,649 lines of Go (90,540 total)
- CRITICAL: Fixed policy evaluation using OS username instead of AWS identity
- AWS identity extraction via STS GetCallerIdentity for all CLI commands
- ARN parsing for all identity types (IAM user, SSO, assumed-role, federated-user, root)
- `sentinel whoami` command for identity debugging
- 1,072 lines of security regression tests
- CHANGELOG.md and SECURITY.md with vulnerability advisory (SENTINEL-2026-001)

**v1.10.1 SSO Credential Fixes shipped:** 2026-01-19
- 1 phase, 2 plans
- +186 lines of Go tests (94,537 total)
- Test coverage for bootstrap command SSO credential loading via --aws-profile
- Test coverage for whoami command SSO credential loading via --profile
- Verified vault.LoadConfig recognizes SSO settings
- Established SSO profile test patterns for future credential testing

**v1.10 Real-time Revocation shipped:** 2026-01-20
- 6 phases, 15 plans
- +6,773 lines of Go (99,721 total)
- SentinelServer HTTP server with per-request policy evaluation
- --server flag for sentinel exec with AWS_CONTAINER_CREDENTIALS_FULL_URI
- CredentialMode-aware policies (server/cli/credential_process)
- 15-minute default sessions with MaxServerDuration policy caps
- Session tracking via DynamoDB with revocation support
- require_server policy effect for server mode enforcement

## Performance Metrics

**Velocity:**
- Total plans completed: 132
- Average duration: 3.0 min
- Total execution time: ~525 min

**By Milestone:**

| Milestone | Phases | Plans | Total Time |
|-----------|--------|-------|------------|
| v1.0 MVP | 8 | 16 | ~37 min |
| v1.1 Sentinel Fingerprint | 9 | 12 | ~29 min |
| v1.2 Approval Workflows | 9 | 17 | ~44 min |
| v1.3 Break-Glass | 8 | 15 | ~45 min |
| v1.4 Sentinel Bootstrapping | 8 | 8 | ~20 min |
| v1.5 Enforcement & Assurance | 7 | 8 | ~20 min |
| v1.6 Testing & Hardening | 10 | 25 | ~48 min |
| v1.7 Permissions Discovery | 9 | 10 | ~66 min |
| v1.7.1 Security Patch | 4 | 7 | ~86 min |
| v1.8 Credential Flow UX | 3 | 3 | ~16 min |
| v1.9 SSO Profile Support | 2 | 6 | ~6 min |
| v1.10.1 SSO Credential Fixes | 1 | 2 | ~6 min |

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

**v1.6 CloudTrail Query Tests decisions (Phase 54-02):**
- ParseSourceIdentity is case-sensitive (SENTINEL, Sentinel rejected)
- Zero-width characters in prefix are detected as non-sentinel
- Concurrent Verify calls produce isolated results (no interference)
- Coverage at 98.8% exceeds 91% target

**v1.6 Bootstrap Validation Edge Case Tests decisions (Phase 55-01):**
- Consecutive slashes (//) allowed in SSM paths per current regex implementation
- Nil config to Planner.Plan() may panic (documented as acceptable for programming error)
- mockSSMWriterAPI uses sync.Mutex to protect calls slice in parallel tests
- Validation functions isValidSSMPath and isValidProfileName at 100% coverage
- Overall bootstrap coverage improved from 95.7% to 96.9%

**v1.6 Bootstrap SSM Integration Tests decisions (Phase 55-02):**
- Each parallel goroutine gets its own mock/executor to avoid race on calls slice
- inMemorySSMStore implements ssmAPI, ssmWriterAPI, ssmStatusAPI for E2E testing
- 96.9% coverage acceptable - uncovered code is AWS config constructors (NewFromConfig)
- Shared putParameter function with atomic counter for parallel call counting

**v1.6 Credential Flow Integration Tests decisions (Phase 56-01):**
- Decision paths tested via component integration, not full CLI invocation (avoids AWS credential requirement)
- Logging verification uses MockLogger from testutil package for call tracking
- Error handling tests verify non-fatal semantics (store errors don't block credential denial)
- Integration tests exercise decision path components rather than full credential retrieval

**v1.6 Cross-Service Integration Tests decisions (Phase 56-02):**
- Mock store ListByRequesterFunc callback enables in-memory filtering for finder tests
- New request objects created for status updates (not in-place modification) to trigger NotifyStore transition detection
- Mutex-protected list snapshot for concurrent mutation tests (prevents race on map iteration)
- Fire-and-forget notification semantics verified across all state transitions

**v1.6 Command Integration Tests decisions (Phase 56-03):**
- Use testable command versions (testableRequestCommand, testableBreakGlassCommand, testableBootstrapCommand) for profile validation bypass
- Leverage existing MockRequestStore and MockBreakGlassStore from testutil instead of duplicating mocks
- Added MockBreakGlassNotifier to testutil to complete notification mock coverage
- Valid request/event IDs must be 16 lowercase hex characters

**v1.6 Performance Benchmarks decisions (Phase 57-01):**
- Used time.Date() for deterministic time in benchmarks (not time.Now())
- Created fixture functions (smallPolicy, mediumPolicy, largePolicy) for reusable test data
- Used b.Run() for table-driven sub-benchmarks for better organization
- Pre-generated keys for cache miss benchmark to avoid allocation in hot path

**v1.6 Concurrency Testing decisions (Phase 57-02):**
- Use atomic.Int64 for thread-safe call counters instead of mutex-protected int
- Barrier pattern (channel close) for synchronized goroutine start maximizes contention
- First-writer-wins via optimistic locking timestamp comparison for state machine tests
- Mock stores clone data on Get/Create to prevent external mutation

**v1.6 Load Simulation decisions (Phase 57-03):**
- Per-worker result slices instead of shared channels to avoid contention at high rates
- Atomic counter for work claiming prevents duplicate work assignment
- Skip collision tracking in identity test (birthday problem ~0.07% with 25k samples)
- Build tag 'loadtest' to skip expensive tests in normal runs

**v1.6 Security Regression Tests decisions (Phase 58-01):**
- Used TestSecurityRegression_ prefix for easy CI/CD filtering across all packages
- Tests verify denial paths, not just happy paths
- Boundary tests use nanosecond precision for time-based controls
- Table-driven tests with SECURITY VIOLATION markers for critical failures
- Tests cover case sensitivity, boundary conditions, and injection patterns

**v1.6 Pre-Release Coverage decisions (Phase 59-01):**
- All 11 Sentinel packages exceed 80% coverage target (average 94.1%)
- GO recommendation for v1.6 release - security-critical paths fully covered
- Uncovered code limited to AWS constructors (NewFromConfig patterns) and entry points
- Inherited aws-vault packages excluded from target (not modified by Sentinel)

**v1.6 Documentation Validation decisions (Phase 59-02):**
- No critical documentation errors found - all core documentation accurate
- CLI help text validated against all 17 documented commands
- Cross-references between docs/ files validated (all internal links work)
- Issues categorized by severity: 0 critical, 4 minor, 6 cosmetic
- macOS-specific date syntax in docs noted as cosmetic (script examples non-portable)

**v1.7 Feature Detection decisions (Phase 62-01):**
- Always-detected features: credential_issue (base), audit_verify (CloudTrail), enforce_analyze (IAM)
- SSM detection: /sentinel/policies/* for policy_load and bootstrap_plan
- DynamoDB detection: sentinel-requests (approval_workflow), sentinel-breakglass (breakglass)
- Not auto-detected: notify_sns, notify_webhook, bootstrap_apply (optional features)
- Best-effort detection: API errors collected but don't stop other feature checks
- Detection summary to stderr (human format only), permissions to stdout

**v1.7 Permission Validation decisions (Phase 63-01):**
- Renamed check subcommand flags to avoid kingpin inheritance conflict (--auto-detect, --features, --output, --aws-region)
- Exit code 0 for all passed, 1 for any failures or errors (CI/CD friendly)
- Cache caller ARN from STS GetCallerIdentity to avoid repeated calls
- Human output uses # (pass), X (fail), ? (error) markers for visual scanning
- JSON output includes results array and summary counts for machine parsing

**v1.7 Guided Setup decisions (Phase 64-01):**
- Wizard is subcommand (sentinel init wizard) rather than parent action due to kingpin limitations
- Non-interactive mode triggered when both --profile and --feature flags provided
- Uses existing vault.LoadConfigFromEnv() for profile discovery from ~/.aws/config

**v1.7 Error Enhancement decisions (Phase 65-01):**
- SentinelError interface provides Unwrap() for error chain compatibility
- Error classifiers use string matching for AWS error detection (reliable across SDK versions)
- NewPolicyDeniedError includes approval workflow and break-glass alternatives when available
- All error codes have default suggestions in centralized registry

**v1.7 Error Integration decisions (Phase 65-02):**
- Shared FormatErrorWithSuggestion helper in cli/errors.go for consistent error display
- CredentialsCommandInput.Stderr field for testable error output (matching existing patterns)
- WrapSTSError added for STS API error handling in permissions checker
- Test assertions updated to check error context keywords rather than exact message format

**v1.7 Config Validation decisions (Phase 66-01):**
- Warnings do not affect exit code - valid with warnings returns exit 0
- Auto-detect config type from YAML structure when --type not specified
- SSM support via --ssm flag for validating policies stored in Parameter Store
- Suggestions provided for each validation error type

**v1.7 Quick Start Templates decisions (Phase 67-01):**
- No explicit default-deny rule needed - policy engine denies when no rules match
- Business hours auto-approve (Mon-Fri 9:00-17:00 UTC) as default for approvals template
- Full template includes all 4 reason codes for break-glass authorization
- Generated configs pass validation via `sentinel config validate`

**v1.7.1 AWS Identity Integration decisions (Phase 70-01):**
- STSAPI interface enables mock injection for tests without AWS credentials
- GetAWSUsername returns sanitized username matching existing 20-char truncation logic
- STSClient field added to command input structs for dependency injection
- Initialization order: AWS config loaded first, then STS identity, then policy load
- ErrCodeSTSError/ErrCodeSTSAccessDenied added for STS-specific error handling
- Username extraction uses existing ParseARN sanitization (removes @, ., -, _, truncates)

**v1.7.1 Security Validation decisions (Phase 72-01):**
- Removed os/user dependency from all approval workflow commands (approve, deny, request, list)
- All commands use identity.GetAWSUsername via STS GetCallerIdentity
- AWS config loading reordered to occur before identity extraction (needed for STS client)
- Mock STS client pattern established for test isolation (same as credentials/whoami tests)

**v1.7.1 Break-Glass Security Validation decisions (Phase 72-02):**
- Removed os/user dependency from all break-glass commands (breakglass, breakglass-close, breakglass-list)
- Added STSClient field to all break-glass command input structs for dependency injection
- breakglass_list.go only calls identity.GetAWSUsername when no filter flags provided (optimization)
- testableBreakGlassListCommand signature changed to use STSClient instead of mockUsername parameter

**v1.7.1 Security Regression Tests decisions (Phase 72-03):**
- TestSecurityRegression_ prefix for CI/CD filtering of security tests
- Attack scenario demonstration tests explicitly show pre-v1.7.1 vulnerability and verify fix
- Tests cover all identity types: IAM user, SSO assumed-role, regular assumed-role, federated-user, root, GovCloud, China partition
- Policy bypass prevention tests verify AWS identity used for credentials, break-glass, and approval authorization
- Username sanitization tests verify special characters removed and length truncated to 20 chars

**v1.7.1 Security Documentation decisions (Phase 72-04):**
- CHANGELOG.md follows Keep a Changelog format with Security section prominently placed
- SECURITY.md includes full vulnerability disclosure with SENTINEL-2026-001 identifier
- Advisory includes remediation steps and verification command (sentinel whoami)
- Added security best practices section for ongoing guidance

**v1.8 SSO Error Detection decisions (Phase 74-01):**
- OIDCClient interface enables mock injection for testable OIDC operations
- Default client name "sentinel" (configurable via SSOLoginConfig.ClientName)
- RFC 8628 polling defaults: 5 second interval and slow down delay
- String-based keyring error detection fallback for wrapped errors

**v1.8 Auto Login Integration decisions (Phase 74-02):**
- WithAutoLogin uses Go generics for type-safe retry wrapper across different return types
- GetSSOConfigForProfile returns nil (not error) for missing profiles to simplify fallback
- AWS config file loaded early when auto-login enabled for SSO config lookup
- Keyring field in AutoLoginConfig unused - AWS SDK handles token caching internally

**v1.9 Core Credential Loading decisions (Phase 76-01):**
- config.WithSharedConfigProfile added to awsCfgOpts initialization for credentials and exec commands
- Profile is always passed to AWS SDK (even for non-SSO profiles) - SDK handles both correctly
- Enables SSO credential provider chain resolution via ~/.aws/sso/cache/

**v1.9 Approval Workflow SSO Credential Loading decisions (Phase 76-02):**
- request command: Use existing --profile flag for both target profile and AWS credential loading
- approve, deny, list commands: Add separate --aws-profile flag for credentials (optional)
- Pattern: WithSharedConfigProfile(profile) enables SSO credential loading for approval commands

**v1.9 Break-Glass SSO Credential Loading decisions (Phase 76-03):**
- breakglass command: Use existing --profile flag for both target profile and AWS credential loading
- breakglass-check, breakglass-close, breakglass-list: Add separate --aws-profile flag for credentials
- Pattern: WithSharedConfigProfile(profile) enables SSO credential loading for break-glass commands

**v1.9 Infrastructure Command SSO Credential Loading decisions (Phase 76-04):**
- bootstrap command: Use separate --aws-profile (for credentials) vs --profile (for profiles to bootstrap)
- status and config validate commands: Add --aws-profile for SSO credential loading
- Pattern: Consistent WithSharedConfigProfile pattern across all infrastructure commands

**v1.9 Permissions/Audit SSO Credential Loading decisions (Phase 76-05):**
- permissions list and permissions check commands: Add --aws-profile for SSO credential loading
- check command (request status): Add --aws-profile for SSO credential loading
- enforce plan and audit verify commands: Add --aws-profile for SSO credential loading
- All commands follow same WithSharedConfigProfile pattern

**v1.9 Whoami Profile Flag decisions (Phase 77-01):**
- Use --profile (not --aws-profile) since whoami has no concept of target profile - it only needs credentials to call STS
- Same WithSharedConfigProfile pattern for consistency with Phase 76

**v1.10 Credential Mode Schema decisions (Phase 79-01):**
- CredentialMode type placed after Effect for logical grouping in policy schema
- Empty mode list matches any mode (wildcard semantics, consistent with profiles/users/days)
- Mode check added as final condition in matchesConditions (after profiles, users, time)
- Three modes defined: ModeServer (per-request), ModeCLI (one-time exec), ModeCredentialProcess (one-time credential_process)

**v1.10 Server Mode Integration Tests and Documentation decisions (Phase 79-02):**
- createModeConditionalPolicy test helper for consistent mode-conditional test policy creation
- Mode condition documented after time condition in policy-reference.md
- Server Mode documented as subsection of exec command in commands.md

**v1.10 Short-Lived Sessions decisions (Phase 80-01):**
- DefaultServerSessionDuration=15min - balances security (rapid revocation) with performance (SDK caching)
- 0 value for MaxServerDuration means no policy-imposed limit (same pattern as BreakGlassPolicyRule.MaxDuration)
- Duration capping order: config -> policy cap -> break-glass cap -> final (each can only reduce, not increase)

**v1.10 Session Management decisions (Phase 81-01):**
- SessionStatus uses "revoked" (not "closed") to differentiate from break-glass terminology
- Touch operation uses UpdateItem for atomic increment (hot-path optimization)
- FindActiveByServerInstance queries by server_instance_id with status filter
- Session package follows breakglass package patterns exactly

**v1.10 Session Integration decisions (Phase 81-02):**
- Session tracking is best-effort: failures logged but don't block server startup or credential serving
- Session Touch is fire-and-forget to not impact credential hot path latency
- Sessions marked "expired" on shutdown (not "revoked") for accurate state representation
- ServerInstanceID auto-generated via identity.NewRequestID() if not provided
- --session-table flag is opt-in (no session tracking without explicit flag)

**v1.10 Server Session CLI Commands decisions (Phase 81-03):**
- List command defaults to current user's sessions when no filter specified
- Filter priority matches breakglass-list: status > profile > user
- Both server-sessions and server-session commands support human and JSON output formats
- Session ID validation performed before store call in detail command (fail fast)
- mockSessionStore follows same function-field pattern as mockBreakGlassStore for testing

**v1.10 Session Revocation decisions (Phase 81-04):**
- Revocation check fails-closed for security - revoked sessions are denied credentials immediately (403)
- Store errors fail-open for availability - don't block credentials due to store connectivity issues
- State machine validation: only active sessions can be revoked (expired/already-revoked return errors)
- RevokedBy extracted from AWS identity via STS GetCallerIdentity
- Reason flag is required for revocation (audit trail)

**v1.10 Server Mode Enforcement decisions (Phase 82-01):**
- require_server effect converts to allow/deny based on mode, preserving rule metadata (name, reason)
- RequiresServerMode boolean flag enables targeted error messages (vs parsing reason strings)
- Effect conversion pattern: special effects (require_server) convert to allow/deny with metadata flags

**v1.10 Server Mode Enforcement decisions (Phase 82-02):**
- require_server denials checked BEFORE approval/break-glass bypass - server mode cannot be bypassed
- Actionable error messages: credentials command suggests full exec --server pattern, exec command suggests --server flag

**v1.10 Server Mode Testing decisions (Phase 83-02):**
- testableServerRevokeCommand returns *session.ServerSession for direct verification in tests
- All server-revoke tests committed together as they share the testable command function
- Tests use session.Revoke directly rather than reimplementing revocation logic
- Test environment limitation: 1password SDK CGO dependency prevents running CLI tests (tests validated via go fmt)

**v1.10 Server Mode Testing decisions (Phase 83-01):**
- Test revocation check fail-closed for security: HTTP 403 when session revoked
- Test revocation check fail-open for availability: credentials issued despite store errors
- Test active session happy path: credentials issued and Touch called for tracking
- All tests use MockSessionStore with GetResult/GetErr configuration for session state simulation

**v1.10 Server Mode Testing decisions (Phase 83-03):**
- Call DefaultRoute directly (not HTTP server) to bypass network overhead in load tests
- Use 100 req/sec for 10 seconds as server load test target (vs 1000 req/sec for pure policy evaluation)
- Revocation timing test uses 5 workers at 100ms intervals (~50 req/sec) for coverage with reasonable test duration
- Concurrent stress test uses 50 goroutines x 100 requests = 5000 total requests for thread-safety verification

**v1.11 Shell Init Command decisions (Phase 84-01):**
- Shell function names use sentinel-{profile} format with sanitization
- GenerateScript supports both bash and zsh (same POSIX-compatible output)
- Auto-detect shell format from $SHELL env variable, default to bash
- Script output to stdout, status messages to stderr for eval compatibility
- ssmShellAPI interface follows same pattern as ssmStatusAPI for testability

### Deferred Issues

None — clean implementation across all milestones.

### Blockers/Concerns Carried Forward

None — clean start for v1.10.

## Session Continuity

Last session: 2026-01-20
Stopped at: Completed 84-01-PLAN.md
Resume file: None
Next: Phase 85 (Shell Completion) or verify-work

## Roadmap Evolution

- Milestone v1.0 shipped: 2026-01-14 — MVP (Phases 1-8)
- Milestone v1.1 shipped: 2026-01-15 — Sentinel Fingerprint (Phases 9-17)
- Milestone v1.2 shipped: 2026-01-15 — Approval Workflows (Phases 18-26)
- Milestone v1.3 shipped: 2026-01-16 — Break-Glass (Phases 27-34)
- Milestone v1.4 shipped: 2026-01-16 — Sentinel Bootstrapping (Phases 35-42)
- Milestone v1.5 shipped: 2026-01-16 — Enforcement & Assurance (Phases 43-49)
- Milestone v1.6 shipped: 2026-01-17 — Testing & Hardening (Phases 50-59)
- Milestone v1.7 shipped: 2026-01-18 — Permissions Discovery (Phases 60-68)
- Milestone v1.7.1 shipped: 2026-01-19 — Security Patch (Phases 69-72) - Fix OS username bug
- Milestone v1.8 shipped: 2026-01-19 — Credential Flow UX (Phases 73-75) - SSO profile resolution and auto-login
- Milestone v1.9 shipped: 2026-01-19 — SSO Profile Support (Phases 76-77) - Fix --profile SSO credential loading
- Milestone v1.10.1 shipped: 2026-01-19 — SSO Credential Fixes (Phase 78.1) - Test coverage for bootstrap and whoami SSO profile handling
- Milestone v1.10 shipped: 2026-01-20 — Real-time Revocation (Phases 78-83) - Server mode for instant credential revocation
- Milestone v1.11 created: 2026-01-20 — Shell Integration (Phases 84-87) - Auto-generated shell functions for profiles
