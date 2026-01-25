# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-01-24)

**Core value:** Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions.
**Current focus:** Milestone v1.14 Server-Side Credential Vending — COMPLETE

## Current Position

Phase: 103 of 103 (Testing & Documentation)
Plan: 1 of 2 in current phase
Status: Plan 103-01 complete
Last activity: 2026-01-25 — Completed 103-01-PLAN.md (security tests + testing docs)

Progress: ████████████████████ 100% (v1.14 Phase 103 Plan 01 complete)

## Milestone Summary

**v1.14 Server-Side Credential Vending:**
- 7 phases (97-103)
- Plan count: TBD (will be determined during planning)
- Goal: Lambda TVM for server-side credential vending
- Critical constraint: Lambda IS the trust boundary

**Phase structure:**
- Phase 97: Foundation (Lambda handler skeleton, build pipeline)
- Phase 98: Credential Vending (AssumeRole integration, SourceIdentity)
- Phase 99: Policy & Session Integration (policy evaluation, session tracking, approval/break-glass)
- Phase 100: API Gateway (HTTP API, IAM auth, profile discovery)
- Phase 101: Client Integration (--remote-server flag, SCP patterns)
- Phase 102: Infrastructure as Code (Terraform, CDK, role templates)
- Phase 103: Testing & Documentation (integration tests, load tests, deployment guide)

**Previous milestones (16 shipped):**
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

## Performance Metrics

**Velocity:**
- Total plans completed: 190
- Average duration: 3.5 min
- Total execution time: ~663 min

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

## Accumulated Context

### Decisions

Key decisions logged in PROJECT.md Key Decisions table. Recent decisions from v1.13:

**v1.13 Enforced Session Tracking decisions:**
- Dual-condition effect (require_server_session needs both --server AND --session-table flags)
- SENTINEL_SESSION_TABLE environment variable only applies in server mode
- Policy-level session_table field overrides CLI flag and environment variable
- Profile extraction tries session lookup first (Sentinel format), falls back to role name
- Non-zero exit code for compliance gaps (CI/CD integration)

**v1.14 Phase 101 decisions:**
- Use AWS_CONTAINER_CREDENTIALS_FULL_URI for SDK integration (automatic refresh)
- Skip local profile validation in remote mode (TVM has different profiles)
- --remote-server conflicts with both --server and --policy-parameter

**v1.14 Phase 102 decisions:**
- Use aws-cdk-lib ^2.170.0 for latest CDK features
- ARM64 architecture for Lambda cost optimization (Graviton2)
- Conditional DynamoDB policies only if tables specified
- Context + environment variable configuration pattern for CDK apps
- Use aws_apigatewayv2_* for HTTP APIs (not deprecated REST API resources)
- Count-based conditionals for optional DynamoDB table policies in Terraform
- Protected roles must use SentinelProtected- prefix for TVM policy match
- Trust policy requires both TVM principal and SourceIdentity condition

**v1.14 Phase 103 decisions:**
- Security tests use explicit "SECURITY VIOLATION" markers for critical failures
- Tests verify STS is NOT called when access should be denied
- Load testing docs cover both Artillery and k6 configurations

### Pending Todos

None yet for v1.14.

### Blockers/Concerns

None — clean start for v1.14.

**v1.14 Technical Notes:**
- Research suggests 95%+ code reuse from existing Sentinel packages
- Lambda handler will follow SentinelServer.DefaultRoute() pattern
- Integration points: policy.Evaluate, session.Store, request.FindApprovedRequest, breakglass.FindActiveBreakGlass, identity.GenerateSourceIdentity, logging.Logger
- Build target: cmd/lambda-tvm/ for Lambda binary
- New package: lambda/ for API Gateway handler logic

## Session Continuity

Last session: 2026-01-25
Stopped at: Completed 103-01-PLAN.md (security tests + testing docs)
Resume file: None
Next: `/gsd:execute-plan 103-02` or `/gsd:plan-phase 103` (if plan 02 needs creation)

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
- Milestone v1.14 planning: 2026-01-24 — Server-Side Credential Vending (Phases 97-103)
