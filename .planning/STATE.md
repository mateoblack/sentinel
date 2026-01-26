# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-26)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.18 Critical Security Hardening

## Current Position

Phase: 126 of 135 (Policy Integrity)
Plan: Not started
Status: Ready to plan
Last activity: 2026-01-26 — Milestone v1.18 created

Progress: ░░░░░░░░░░ 0%

## Milestone Summary

**v1.18 Critical Security Hardening (IN PROGRESS):**
- 10 phases (126-135), TBD plans
- P0: Policy cache poisoning, break-glass bypass, audit log tampering, credential exposure
- High: Username spoofing, DynamoDB manipulation, keyring exposure, rate limit bypass, command injection
- STRIDE threat model findings implementation

**v1.17 Policy Developer Experience (SHIPPED 2026-01-26):**
- 5 phases (121-125), 5 plans
- Policy schema Version type with validation helpers
- Policy CLI commands: pull, push, diff, validate
- Complete workflow for editing SSM-backed policies locally

**v1.16 Security Hardening (SHIPPED 2026-01-26):**
- 8 phases (113-120), 9 plans
- Timing attack mitigation, Secrets Manager, rate limiting
- DynamoDB encryption, error sanitization
- Security integration tests

**v1.15 Device Posture (SHIPPED 2026-01-25):**
- 9 phases (104-112), 12 plans
- Server-verified device posture via MDM APIs in Lambda TVM
- MDM Provider interface with Jamf Pro implementation
- Policy device conditions for rule matching
- Session device binding for forensics
- Device audit commands with anomaly detection

**v1.14 Server-Side Credential Vending (SHIPPED):**
- 7 phases (97-103)
- 19 plans
- Goal: Lambda TVM for server-side credential vending
- Critical constraint: Lambda IS the trust boundary

**Previous milestones (18 shipped):**
- v1.0 MVP: 8 phases, 16 plans (shipped 2026-01-14)
- v1.1 Sentinel Fingerprint: 9 phases, 12 plans (shipped 2026-01-15)
- v1.2 Approval Workflows: 9 phases, 17 plans (shipped 2026-01-15)
- v1.3 Break-Glass: 8 phases, 15 plans (shipped 2026-01-16)
- v1.4 Sentinel Bootstrapping: 8 phases, 8 plans (shipped 2026-01-16)
- v1.5 Enforcement & Assurance: 7 phases, 8 plans (shipped 2026-01-16)
- v1.6 Testing & Hardening: 10 phases, 25 plans (shipped 2026-01-17)
- v1.7 Permissions Discovery: 9 phases, 10 plans (shipped 2026-01-18)
- v1.7.1 Security Patch: 4 phases, 7 plans (shipped 2026-01-19)
- v1.8 Credential Flow UX: 3 phases, 3 plans (shipped 2026-01-19)
- v1.9 SSO Profile Support: 2 phases, 6 plans (shipped 2026-01-19)
- v1.10.1 SSO Credential Fixes: 1 phase, 2 plans (shipped 2026-01-19)
- v1.10 Real-time Revocation: 6 phases, 15 plans (shipped 2026-01-20)
- v1.11 Shell Integration: 4 phases, 4 plans (shipped 2026-01-20)
- v1.12 Infrastructure Provisioning: 6 phases, 15 plans (shipped 2026-01-22)
- v1.13 Enforced Session Tracking: 3 phases, 10 plans (shipped 2026-01-24)
- v1.14 Server-Side Credential Vending: 7 phases, 19 plans (shipped 2026-01-25)
- v1.15 Device Posture: 9 phases, 12 plans (shipped 2026-01-25)
- v1.16 Security Hardening: 8 phases, 9 plans (shipped 2026-01-26)
- v1.17 Policy Developer Experience: 5 phases, 5 plans (shipped 2026-01-26)

## Performance Metrics

**Velocity:**
- Total plans completed: 228
- Average duration: ~3.5 min
- Total execution time: ~866 min

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
| v1.10 Real-time Revocation | 6 | 15 | ~102 min |
| v1.11 Shell Integration | 4 | 4 | ~14 min |
| v1.12 Infrastructure Provisioning | 6 | 15 | ~49 min |
| v1.13 Enforced Session Tracking | 3 | 10 | ~35 min |
| v1.14 Server-Side Credential Vending | 7 | 19 | ~49 min |
| v1.15 Device Posture | 9 | 12 | ~41 min |
| v1.16 Security Hardening | 8 | 9 | ~21 min |
| v1.17 Policy Developer Experience | 5 | 5 | ~25 min |

## Accumulated Context

### Decisions

Key decisions logged in PROJECT.md Key Decisions table. Recent decisions:

**v1.15 Device Posture decisions (Phases 104-107):**
- DeviceID uses 32-char hex (128 bits) vs SessionID 16-char for stronger fingerprint uniqueness
- Pointer bools distinguish not checked (nil) from checked and false
- Simple version comparison without external semver library
- All device log fields use omitempty for backward compatibility
- Collector interface returns (*DevicePosture, error) for partial results
- MultiCollector merges with first-non-nil-wins semantics
- StatusUnknown treated as empty/default for merge purposes
- machineid.ProtectedID() for HMAC-SHA256 hashed device ID (64 hex chars)
- AppID 'sentinel-device-posture' isolates device IDs from other apps
- MDMDeviceInfo uses non-pointer bools (enrollment/compliance always known from MDM)
- MultiProvider returns first success (unlike MultiCollector which merges)
- DeviceIDMapper placeholder for MVP direct passthrough mapping
- JamfProvider requires Extension Attribute 'SentinelDeviceID' for production
- Compliance = enrolled (managed) + remote management enabled
- Fail-open by default for MDM (RequireDevicePosture=false)
- Device ID passed as query parameter device_id (64-char lowercase hex)
- Unimplemented providers (intune, kandji) use NoopProvider with warning
- Device conditions affect RULE MATCHING (not effect) - if posture fails, rule doesn't match
- Nil posture fails non-empty device conditions (security: no posture = no match)
- Empty device conditions always match (backward compatible)
- DENY decision logs include device posture context for debugging
- CLI collects device ID via device.GetDeviceID() and passes to TVM as query param
- Fail-open on device ID collection failure (warning log, continue without)
- ServerSession.DeviceID uses omitempty for backward compatibility
- Log device_bound=true flag rather than actual device ID for privacy
- Fail-open on device ID collection for CLI decision logs (availability over blocking)
- Device ID collected once at server startup, cached in struct for efficiency
- Device audit commands: device-sessions queries by 64-char hex device ID, devices aggregates with anomaly detection
- Anomaly thresholds: MULTI_USER at >1 user, HIGH_PROFILE_COUNT at >5 profiles (configurable)

**v1.16 Security Hardening decisions (Phase 113):**
- Use crypto/subtle.ConstantTimeCompare for all bearer token comparisons
- Add inline security comments explaining vulnerability and mitigation
- Verify timing attack fixes via AST parsing in tests (not timing measurements)

**v1.16 Security Hardening decisions (Phase 114):**
- SecretsLoader interface for secrets abstraction (enables mocking and future extension)
- 1 hour default cache TTL optimized for Lambda cold start patterns
- Backward compatible env var fallback with deprecation warning logging

**v1.16 Security Hardening decisions (Phase 116):**
- AWS managed KMS as default encryption (simpler than customer CMK)
- EncryptionConfig is pointer for backward compatibility (nil = AWS owned)
- EncryptionDefault omits SSESpecification to maintain DynamoDB default behavior

**v1.16 Security Hardening decisions (Phase 117):**
- Sliding window log algorithm for rate limiting (simpler than token bucket for request-response)
- Rate limit by IAM user ARN, not IP (IAM auth identifies caller)
- Fail-open on rate limiter errors (availability preferred over blocking)
- Default 100 requests per 60 seconds (conservative but usable)
- Credential server rate limits by remote address (127.0.0.1 for localhost but provides burst protection)
- RFC 7231 compliant Retry-After header with 429 responses
- Rate limiter closed on shutdown if implements io.Closer

**v1.16 Security Hardening decisions (Phase 119):**
- Error sanitization pattern: log.Printf details internally, return generic message to client
- Rate limit and policy deny messages preserved (intentional user-facing information)
- ERROR: prefix for internal error logs for consistency

**v1.16 Security Hardening decisions (Phase 120):**
- Lambda TVM uses IAM auth from API Gateway, not local token comparison
- Security tests use AST parsing to verify constant-time comparison patterns
- Error sanitization tests verify both what IS exposed and what is NOT exposed
- Security test naming convention: TestSecurityIntegration_* for combined validation

**v1.17 Policy Developer Experience decisions (Phase 121):**
- Version as type alias (type Version string) for YAML compatibility
- SupportedVersions as slice for future schema extensibility
- ValidatePolicy distinguishes parse errors from validation errors for CLI UX

**v1.17 Policy Developer Experience decisions (Phase 123):**
- Extended existing SSMAPI interface with PutParameter (unified read/write)
- Use types.ParameterTypeString (not SecureString) matching bootstrap pattern
- Confirmation prompt with --force flag for automation bypass
- Cancel on confirmation exits with code 0 (not an error)

**v1.17 Policy Developer Experience decisions (Phase 124):**
- Exit code 0 = no changes, 1 = changes exist (scripting-friendly)
- Normalize policies via parse/marshal before comparison
- Use LCS algorithm for unified diff generation
- Color output enabled by default, --no-color flag to disable

**v1.17 Policy Developer Experience decisions (Phase 125):**
- Exit code 0 = valid, exit code 1 = invalid (scripting-friendly)
- No AWS credentials required - pure local YAML validation
- Success message to stderr (unless --quiet) to keep stdout clean

**v1.14 Server-Side Credential Vending decisions:**
- aws-lambda-go v1.47.0 for Lambda handler types
- AWS container credentials format for SDK compatibility
- Lambda handler returns (response, error) for all paths
- TVMConfig uses environment variable loading pattern
- Router with POST / for credentials, GET /profiles for discovery
- ARM64 architecture for Lambda cost optimization (Graviton2)
- Protected roles must use SentinelProtected- prefix for TVM policy match
- Trust policy requires both TVM principal and SourceIdentity condition
- Security tests use explicit "SECURITY VIOLATION" markers
- Gradual rollout strategy for enterprise adoption (4-phase migration)

### Pending Todos

None — ready to plan next milestone.

### Blockers/Concerns

None — fresh start for next milestone.

## Session Continuity

Last session: 2026-01-26
Stopped at: Milestone v1.18 initialization
Resume file: None
Next: Plan Phase 126 (Policy Integrity)

## Roadmap Evolution

- Milestone v1.0 shipped: 2026-01-14 — MVP (Phases 1-8)
- Milestone v1.1 shipped: 2026-01-15 — Sentinel Fingerprint (Phases 9-17)
- Milestone v1.2 shipped: 2026-01-15 — Approval Workflows (Phases 18-26)
- Milestone v1.3 shipped: 2026-01-16 — Break-Glass (Phases 27-34)
- Milestone v1.4 shipped: 2026-01-16 — Sentinel Bootstrapping (Phases 35-42)
- Milestone v1.5 shipped: 2026-01-16 — Enforcement & Assurance (Phases 43-49)
- Milestone v1.6 shipped: 2026-01-17 — Testing & Hardening (Phases 50-59)
- Milestone v1.7 shipped: 2026-01-18 — Permissions Discovery (Phases 60-68)
- Milestone v1.7.1 shipped: 2026-01-19 — Security Patch (Phases 69-72)
- Milestone v1.8 shipped: 2026-01-19 — Credential Flow UX (Phases 73-75)
- Milestone v1.9 shipped: 2026-01-19 — SSO Profile Support (Phases 76-77)
- Milestone v1.10.1 shipped: 2026-01-19 — SSO Credential Fixes (Phase 78.1)
- Milestone v1.10 shipped: 2026-01-20 — Real-time Revocation (Phases 78-83)
- Milestone v1.11 shipped: 2026-01-20 — Shell Integration (Phases 84-87)
- Milestone v1.12 shipped: 2026-01-22 — Infrastructure Provisioning (Phases 88-93)
- Milestone v1.13 shipped: 2026-01-24 — Enforced Session Tracking (Phases 94-96)
- Milestone v1.14 shipped: 2026-01-25 — Server-Side Credential Vending (Phases 97-103)
- Milestone v1.15 shipped: 2026-01-25 — Device Posture (Phases 104-112)
- Milestone v1.16 shipped: 2026-01-26 — Security Hardening (Phases 113-120)
- Milestone v1.17 shipped: 2026-01-26 — Policy Developer Experience (Phases 121-125)
- Milestone v1.18 created: 2026-01-26 — Critical Security Hardening (Phases 126-135)
