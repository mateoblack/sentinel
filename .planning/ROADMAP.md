# Roadmap: Sentinel

## Overview

Sentinel adds intent-aware access control to aws-vault, evaluating policy rules before issuing AWS credentials. The journey starts with CLI foundation and aws-vault integration, moves through policy schema design and SSM-based loading, implements the core decision engine, then exposes this through credential_process and exec commands with full logging and profile compatibility.

## Milestones

- ✅ **v1.0 MVP** - [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md) (Phases 1-8, shipped 2026-01-14)
- ✅ **v1.1 Sentinel Fingerprint** - [milestones/v1.1-ROADMAP.md](milestones/v1.1-ROADMAP.md) (Phases 9-17, shipped 2026-01-15)
- ✅ **v1.2 Approval Workflows** - [milestones/v1.2-ROADMAP.md](milestones/v1.2-ROADMAP.md) (Phases 18-26, shipped 2026-01-15)
- ✅ **v1.3 Break-Glass** — [milestones/v1.3-ROADMAP.md](milestones/v1.3-ROADMAP.md) (Phases 27-34, shipped 2026-01-16)
- 🚧 **v1.4 Sentinel Bootstrapping** — Phases 35-42 (in progress)

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

<details>
<summary>✅ v1.2 Approval Workflows (Phases 18-26) — SHIPPED 2026-01-15</summary>

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
- [x] 25-02: Approval policy validation — completed 2026-01-15
- [x] 25-03: Approval policy matching — completed 2026-01-15

#### Phase 26: Approval Audit Trail

**Goal**: Enhanced logging for approval request lifecycle events
**Depends on**: Phase 25
**Research**: Unlikely (extends existing logging)
**Plans**: 2

Plans:
- [x] 26-01: Approval audit trail logging infrastructure — completed 2026-01-15
- [x] 26-02: CLI approval logging integration — completed 2026-01-15

</details>

<details>
<summary>✅ v1.3 Break-Glass (Phases 27-34) — SHIPPED 2026-01-16</summary>

- [x] Phase 27: Break-Glass Schema (1/1 plans) — completed 2026-01-15
- [x] Phase 28: Break-Glass Command (2/2 plans) — completed 2026-01-15
- [x] Phase 29: Elevated Audit (2/2 plans) — completed 2026-01-15
- [x] Phase 30: Time-Bounded Sessions (2/2 plans) — completed 2026-01-15
- [x] Phase 31: Notification Blast (2/2 plans) — completed 2026-01-15
- [x] Phase 32: Post-Incident Review (2/2 plans) — completed 2026-01-15
- [x] Phase 33: Rate Limiting (2/2 plans) — completed 2026-01-15
- [x] Phase 34: Break-Glass Policies (2/2 plans) — completed 2026-01-16

</details>

### 🚧 v1.4 Sentinel Bootstrapping (In Progress)

**Milestone Goal:** Prepare AWS to be a trustworthy policy source for Sentinel with deterministic, reversible CLI-driven setup.

#### Phase 35: Bootstrap Schema

**Goal**: Define bootstrap configuration types, resource specifications, and state tracking
**Depends on**: v1.3 complete
**Research**: Unlikely (internal design)
**Plans**: 1

Plans:
- [x] 35-01: Bootstrap config types with resource specs, state tracking, and validation — completed 2026-01-16

#### Phase 36: Bootstrap Planner

**Goal**: Dry-run logic to determine resources to create, existence checks, plan output formatting
**Depends on**: Phase 35
**Research**: Unlikely (internal logic)
**Plans**: 1

Plans:
- [x] 36-01: SSM existence checks and plan output formatting — completed 2026-01-15

#### Phase 37: SSM Parameter Creation

**Goal**: Create SSM policy parameters, handle existing parameters, versioning awareness
**Depends on**: Phase 36
**Research**: Unlikely (existing SSM patterns)
**Plans**: 1

Plans:
- [x] 37-01: Executor with Apply method for SSM parameter creation — completed 2026-01-16

#### Phase 38: Sample Policy Generation

**Goal**: Generate safe starter policy YAML per profile with validation
**Depends on**: Phase 37
**Research**: Unlikely (internal patterns)
**Plans**: 1

Plans:
- [x] 38-01: Sample policy generator with GenerateSamplePolicy function — completed 2026-01-16

#### Phase 39: IAM Policy Generation

**Goal**: Generate SentinelPolicyReader and SentinelPolicyAdmin IAM policy documents
**Depends on**: Phase 38
**Research**: Likely (IAM policy document structure, least-privilege patterns)
**Research topics**: IAM policy best practices, resource ARN patterns, condition keys
**Plans**: 1

Plans:
- [x] 39-01: IAM policy document types and generator functions — completed 2026-01-16

#### Phase 40: Bootstrap Command

**Goal**: `sentinel init bootstrap` command with --plan/--yes/--profile flags
**Depends on**: Phase 39
**Research**: Unlikely (existing CLI patterns)
**Plans**: 1

Plans:
- [x] 40-01: Bootstrap command with plan/apply workflow and CLI integration — completed 2026-01-16

#### Phase 41: Status Command

**Goal**: `sentinel init status` showing policy root, profiles with parameters, versions
**Depends on**: Phase 40
**Research**: Unlikely (existing CLI patterns)
**Plans**: TBD

Plans:
- [ ] 41-01: TBD

#### Phase 42: Bootstrap Documentation

**Goal**: Setup guide, security properties documentation, adoption guide
**Depends on**: Phase 41
**Research**: Unlikely (internal work)
**Plans**: TBD

Plans:
- [ ] 42-01: TBD

## Progress (All Milestones)

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1-8 | v1.0 | 16/16 | Complete | 2026-01-14 |
| 9-17 | v1.1 | 12/12 | Complete | 2026-01-15 |
| 18-26 | v1.2 | 17/17 | Complete | 2026-01-15 |
| 27-34 | v1.3 | 15/15 | Complete | 2026-01-16 |
| 35. Bootstrap Schema | v1.4 | 1/1 | Complete | 2026-01-16 |
| 36. Bootstrap Planner | v1.4 | 1/1 | Complete | 2026-01-15 |
| 37. SSM Parameter Creation | v1.4 | 1/1 | Complete | 2026-01-16 |
| 38. Sample Policy Generation | v1.4 | 1/1 | Complete | 2026-01-16 |
| 39. IAM Policy Generation | v1.4 | 1/1 | Complete | 2026-01-16 |
| 40. Bootstrap Command | v1.4 | 1/1 | Complete | 2026-01-16 |
| 41. Status Command | v1.4 | 0/? | Not started | - |
| 42. Bootstrap Documentation | v1.4 | 0/? | Not started | - |
