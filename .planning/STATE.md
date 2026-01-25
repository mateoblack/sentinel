# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-25)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** v1.15 Device Posture — verify device security before issuing credentials

## Current Position

Phase: 107 of 112 (MDM API Integration)
Plan: 1 of 1 in current phase
Status: Phase complete
Last activity: 2026-01-25 — Completed 107-01-PLAN.md

Progress: ████░░░░░░ 40%

## Milestone Summary

**v1.15 Device Posture (IN PROGRESS):**
- 9 phases (104-112)
- Plans: 2 completed (Phases 104, 105)
- Goal: Verify device security posture before issuing credentials
- Key feature: Device fingerprinting in decision logs and session metadata
- Phase 104 complete: Device posture schema types, policy conditions, log fields
- Phase 105 complete: Collector interface, MultiCollector, NoopCollector
- Phase 106 complete: Device identity module with machineid library
- Phase 107 complete: MDM Provider interface, MultiProvider, NoopProvider

**v1.14 Server-Side Credential Vending (SHIPPED):**
- 7 phases (97-103)
- 19 plans
- Goal: Lambda TVM for server-side credential vending
- Critical constraint: Lambda IS the trust boundary

**Previous milestones (17 shipped):**
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

## Performance Metrics

**Velocity:**
- Total plans completed: 195
- Average duration: ~3.5 min
- Total execution time: ~689 min

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

None — ready to plan v1.15.

### Blockers/Concerns

None — fresh milestone.

## Session Continuity

Last session: 2026-01-25
Stopped at: Phase 107 complete
Resume file: None
Next: `/gsd:plan-phase 108` to plan Jamf MDM Provider

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
- Milestone v1.15 created: 2026-01-25 — Device Posture, 9 phases (Phase 104-112)
