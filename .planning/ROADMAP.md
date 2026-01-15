# Roadmap: Sentinel

## Overview

Sentinel adds intent-aware access control to aws-vault, evaluating policy rules before issuing AWS credentials. The journey starts with CLI foundation and aws-vault integration, moves through policy schema design and SSM-based loading, implements the core decision engine, then exposes this through credential_process and exec commands with full logging and profile compatibility.

## Milestones

- ✅ **v1.0 MVP** - [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md) (Phases 1-8, shipped 2026-01-14)
- ✅ **v1.1 Sentinel Fingerprint** - [milestones/v1.1-ROADMAP.md](milestones/v1.1-ROADMAP.md) (Phases 9-17, shipped 2026-01-15)
- 🚧 **v1.2 Approval Workflows** - Phases 18-26 (in progress)
- 📋 **v1.3 Break-Glass** - Phases 27-34 (planned)

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

<details>
<summary>✅ v1.1 Sentinel Fingerprint (Phases 9-17) — SHIPPED 2026-01-15</summary>

- [x] Phase 9: Source Identity Schema (1/1 plans) — completed 2026-01-14
- [x] Phase 10: AssumeRole Provider (1/1 plans) — completed 2026-01-14
- [x] Phase 11: Two-Hop Orchestration (1/1 plans) — completed 2026-01-14
- [x] Phase 12: Credential Process Update (1/1 plans) — completed 2026-01-15
- [x] Phase 13: Exec Command Update (1/1 plans) — completed 2026-01-15
- [x] Phase 14: Enhanced Decision Logging (4/4 plans) — completed 2026-01-15
- [x] Phase 15: CloudTrail Correlation (1/1 plans) — completed 2026-01-15
- [x] Phase 16: Enforcement Patterns (1/1 plans) — completed 2026-01-15
- [x] Phase 17: Integration Testing (1/1 plans) — completed 2026-01-15

</details>

### 🚧 v1.2 Approval Workflows (In Progress)

**Milestone Goal:** Add request/approve flow for sensitive access with DynamoDB state, notification hooks, and approval policies.

#### Phase 18: Request Schema

**Goal**: Define approval request data model, state machine, and validation
**Depends on**: v1.1 complete
**Research**: Unlikely (internal design, extends existing types)
**Plans**: TBD

Plans:
- [x] 18-01: Request types with state machine and validation — completed 2026-01-15

#### Phase 19: DynamoDB Backend

**Goal**: Create request storage with TTL, indexes, and query patterns
**Depends on**: Phase 18
**Research**: Likely (new AWS service integration)
**Research topics**: DynamoDB table design, GSI patterns, TTL, aws-sdk-go-v2 dynamodb
**Plans**: 2

Plans:
- [x] 19-01: Store interface and DynamoDB CRUD operations — completed 2026-01-15
- [x] 19-02: GSI query methods (ListByRequester, ListByStatus, ListByProfile) — completed 2026-01-15

#### Phase 20: Request Command

**Goal**: CLI command to submit access requests with profile/duration/justification
**Depends on**: Phase 19
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: 1

Plans:
- [x] 20-01: Request command with CLI configuration and tests — completed 2026-01-14

#### Phase 21: List/Check Commands

**Goal**: Commands to view pending requests and check own request status
**Depends on**: Phase 20
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: 2

Plans:
- [x] 21-01: List command with CLI configuration and tests — completed 2026-01-15
- [x] 21-02: Check command with status lookup — completed 2026-01-15

#### Phase 22: Approve/Deny Commands

**Goal**: Approver actions with request validation and signature verification
**Depends on**: Phase 21
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: 1

Plans:
- [x] 22-01: Approve/deny commands with state transitions and tests — completed 2026-01-14

#### Phase 23: Request Integration

**Goal**: Wire approved requests into credential issuance flow
**Depends on**: Phase 22
**Research**: Unlikely (internal integration)
**Plans**: 2

Plans:
- [x] 23-01: Request checker function with FindApprovedRequest — completed 2026-01-15
- [x] 23-02: Credential issuance integration with Store field — completed 2026-01-15

#### Phase 24: Notification Hooks

**Goal**: Webhook/SNS integration for request lifecycle events
**Depends on**: Phase 23
**Research**: Likely (external service integration)
**Research topics**: SNS publish API, webhook patterns, retry semantics
**Plans**: 4

Plans:
- [x] 24-01: Notification types and Notifier interface — completed 2026-01-15
- [x] 24-02: SNS notifier implementation — completed 2026-01-15
- [x] 24-03: Webhook notifier implementation — completed 2026-01-15
- [x] 24-04: NotifyStore wrapper and CLI integration — completed 2026-01-15

#### Phase 25: Approval Policies

**Goal**: Policy rules for auto-approve conditions and approval routing
**Depends on**: Phase 24
**Research**: Unlikely (extends existing policy schema)
**Plans**: TBD

Plans:
- [x] 25-01: Approval policy schema — completed 2026-01-15
- [ ] 25-02: Approval policy validation
- [ ] 25-03: Approval policy matching

#### Phase 26: Approval Audit Trail

**Goal**: Enhanced logging for approval request lifecycle events
**Depends on**: Phase 25
**Research**: Unlikely (extends existing logging)
**Plans**: TBD

Plans:
- [ ] 26-01: TBD

### 📋 v1.3 Break-Glass (Planned)

**Milestone Goal:** Emergency access bypass with enhanced audit, time-bounded sessions, and immediate security notifications.

#### Phase 27: Break-Glass Schema

**Goal**: Define emergency access model with reason codes, expiry, and validation
**Depends on**: v1.2 complete
**Research**: Unlikely (extends existing types)
**Plans**: TBD

Plans:
- [ ] 27-01: TBD

#### Phase 28: Break-Glass Command

**Goal**: CLI command to invoke emergency access with mandatory justification
**Depends on**: Phase 27
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: TBD

Plans:
- [ ] 28-01: TBD

#### Phase 29: Elevated Audit

**Goal**: Enhanced logging with mandatory justification and incident correlation
**Depends on**: Phase 28
**Research**: Unlikely (extends existing logging)
**Plans**: TBD

Plans:
- [ ] 29-01: TBD

#### Phase 30: Time-Bounded Sessions

**Goal**: Automatic credential expiry and renewal limits for break-glass access
**Depends on**: Phase 29
**Research**: Unlikely (extends existing credential handling)
**Plans**: TBD

Plans:
- [ ] 30-01: TBD

#### Phase 31: Notification Blast

**Goal**: Immediate alerts to security team on break-glass invocation
**Depends on**: Phase 30
**Research**: Unlikely (reuses v1.2 notification infrastructure)
**Plans**: TBD

Plans:
- [ ] 31-01: TBD

#### Phase 32: Post-Incident Review

**Goal**: Commands to list, review, and close break-glass events
**Depends on**: Phase 31
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: TBD

Plans:
- [ ] 32-01: TBD

#### Phase 33: Rate Limiting

**Goal**: Prevent break-glass abuse with cooldowns, quotas, and escalation
**Depends on**: Phase 32
**Research**: Unlikely (internal design)
**Plans**: TBD

Plans:
- [ ] 33-01: TBD

#### Phase 34: Break-Glass Policies

**Goal**: Policy rules for who can invoke break-glass and under what conditions
**Depends on**: Phase 33
**Research**: Unlikely (extends existing policy schema)
**Plans**: TBD

Plans:
- [ ] 34-01: TBD

## Progress (All Milestones)

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1-8 | v1.0 | 16/16 | Complete | 2026-01-14 |
| 9-17 | v1.1 | 12/12 | Complete | 2026-01-15 |
| 18. Request Schema | v1.2 | 1/1 | Complete | 2026-01-15 |
| 19. DynamoDB Backend | v1.2 | 2/2 | Complete | 2026-01-15 |
| 20. Request Command | v1.2 | 1/1 | Complete | 2026-01-14 |
| 21. List/Check Commands | v1.2 | 2/2 | Complete | 2026-01-15 |
| 22. Approve/Deny Commands | v1.2 | 1/1 | Complete | 2026-01-14 |
| 23. Request Integration | v1.2 | 2/2 | Complete | 2026-01-15 |
| 24. Notification Hooks | v1.2 | 4/4 | Complete | 2026-01-15 |
| 25. Approval Policies | v1.2 | 1/3 | In progress | - |
| 26. Approval Audit Trail | v1.2 | 0/? | Not started | - |
| 27. Break-Glass Schema | v1.3 | 0/? | Not started | - |
| 28. Break-Glass Command | v1.3 | 0/? | Not started | - |
| 29. Elevated Audit | v1.3 | 0/? | Not started | - |
| 30. Time-Bounded Sessions | v1.3 | 0/? | Not started | - |
| 31. Notification Blast | v1.3 | 0/? | Not started | - |
| 32. Post-Incident Review | v1.3 | 0/? | Not started | - |
| 33. Rate Limiting | v1.3 | 0/? | Not started | - |
| 34. Break-Glass Policies | v1.3 | 0/? | Not started | - |
