# Roadmap: Sentinel

## Overview

Sentinel adds intent-aware access control to aws-vault, evaluating policy rules before issuing AWS credentials. The journey starts with CLI foundation and aws-vault integration, moves through policy schema design and SSM-based loading, implements the core decision engine, then exposes this through credential_process and exec commands with full logging and profile compatibility.

## Milestones

- ✅ **v1.0 MVP** - [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md) (Phases 1-8, shipped 2026-01-14)
- 🚧 **v1.1 Sentinel Fingerprint** - Phases 9-17 (in progress)

## Completed Milestones

<details>
<summary>v1.0 MVP (Phases 1-8) — SHIPPED 2026-01-14</summary>

- [x] Phase 1: Foundation (2/2 plans) — completed 2026-01-14
- [x] Phase 2: Policy Schema (2/2 plans) — completed 2026-01-14
- [x] Phase 3: Policy Loading (2/2 plans) — completed 2026-01-14
- [x] Phase 4: Policy Evaluation (2/2 plans) — completed 2026-01-14
- [x] Phase 5: Credential Process (2/2 plans) — completed 2026-01-14
- [x] Phase 6: Decision Logging (2/2 plans) — completed 2026-01-14
- [x] Phase 7: Exec Command (2/2 plans) — completed 2026-01-14
- [x] Phase 8: Profile Compatibility (2/2 plans) — completed 2026-01-14

</details>

## Domain Expertise

None

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Foundation | v1.0 | 2/2 | Complete | 2026-01-14 |
| 2. Policy Schema | v1.0 | 2/2 | Complete | 2026-01-14 |
| 3. Policy Loading | v1.0 | 2/2 | Complete | 2026-01-14 |
| 4. Policy Evaluation | v1.0 | 2/2 | Complete | 2026-01-14 |
| 5. Credential Process | v1.0 | 2/2 | Complete | 2026-01-14 |
| 6. Decision Logging | v1.0 | 2/2 | Complete | 2026-01-14 |
| 7. Exec Command | v1.0 | 2/2 | Complete | 2026-01-14 |
| 8. Profile Compatibility | v1.0 | 2/2 | Complete | 2026-01-14 |

### 🚧 v1.1 Sentinel Fingerprint (In Progress)

**Milestone Goal:** Make Sentinel enforceable and provable inside AWS by stamping all sessions with a Sentinel-controlled SourceIdentity.

#### Phase 9: Source Identity Schema (Complete)

**Goal**: Define SourceIdentity format (`sentinel:<user>:<request-id>`) and request-id generation
**Depends on**: v1.0 complete
**Research**: Unlikely (internal design)
**Plans**: 1/1 complete

Plans:
- [x] 09-01: Create SourceIdentity type and request-id generation

#### Phase 10: AssumeRole Provider (Complete)

**Goal**: Build AssumeRole wrapper that stamps SourceIdentity on all role assumptions
**Depends on**: Phase 9
**Research**: Unlikely (followed vault patterns)
**Plans**: 1/1 complete

Plans:
- [x] 10-01: Create SentinelAssumeRole function with SourceIdentity stamping

#### Phase 11: Two-Hop Orchestration (Complete)

**Goal**: Chain aws-vault base credentials → Sentinel AssumeRole with SourceIdentity
**Depends on**: Phase 10
**Research**: Not needed (followed vault patterns)
**Plans**: 1/1 complete

Plans:
- [x] 11-01: Create TwoHopCredentialProvider with SourceIdentity generation

#### Phase 12: Credential Process Update (Complete)

**Goal**: Update credential_process command to use two-hop pattern for SourceIdentity stamping
**Depends on**: Phase 11
**Research**: Unlikely (extending existing implementation)
**Plans**: 1/1 complete

Plans:
- [x] 12-01: Integrate GetCredentialsWithSourceIdentity into credentials command

#### Phase 13: Exec Command Update

**Goal**: Update exec command to use two-hop credential flow with SourceIdentity
**Depends on**: Phase 12
**Research**: Unlikely (parallel to credential_process changes)
**Plans**: TBD

Plans:
- [ ] 13-01: TBD

#### Phase 14: Enhanced Decision Logging

**Goal**: Add request-id, source-identity, role-arn, session-duration to decision logs
**Depends on**: Phase 13
**Research**: Unlikely (extending existing logging)
**Plans**: TBD

Plans:
- [ ] 14-01: TBD

#### Phase 15: CloudTrail Correlation

**Goal**: Documentation and tooling for correlating Sentinel logs with CloudTrail events
**Depends on**: Phase 14
**Research**: Unlikely (documentation focus)
**Plans**: TBD

Plans:
- [ ] 15-01: TBD

#### Phase 16: Enforcement Patterns

**Goal**: Document trust policy and SCP patterns for optional Sentinel enforcement
**Depends on**: Phase 15
**Research**: Unlikely (IAM patterns documentation)
**Plans**: TBD

Plans:
- [ ] 16-01: TBD

#### Phase 17: Integration Testing

**Goal**: End-to-end testing of fingerprint flow with real AWS resources
**Depends on**: Phase 16
**Research**: Unlikely (testing existing implementation)
**Plans**: TBD

Plans:
- [ ] 17-01: TBD

## Progress (v1.1)

| Phase | Milestone | Plans | Status | Completed |
|-------|-----------|-------|--------|-----------|
| 9. Source Identity Schema | v1.1 | 1/1 | Complete | 2026-01-14 |
| 10. AssumeRole Provider | v1.1 | 1/1 | Complete | 2026-01-14 |
| 11. Two-Hop Orchestration | v1.1 | 1/1 | Complete | 2026-01-14 |
| 12. Credential Process Update | v1.1 | 1/1 | Complete | 2026-01-15 |
| 13. Exec Command Update | v1.1 | 0/? | Not started | - |
| 14. Enhanced Decision Logging | v1.1 | 0/? | Not started | - |
| 15. CloudTrail Correlation | v1.1 | 0/? | Not started | - |
| 16. Enforcement Patterns | v1.1 | 0/? | Not started | - |
| 17. Integration Testing | v1.1 | 0/? | Not started | - |
