# Roadmap: Sentinel

## Overview

Sentinel adds intent-aware access control to aws-vault, evaluating policy rules before issuing AWS credentials. The journey starts with CLI foundation and aws-vault integration, moves through policy schema design and SSM-based loading, implements the core decision engine, then exposes this through credential_process and exec commands with full logging and profile compatibility.

## Milestones

- ✅ **v1.0 MVP** - [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md) (Phases 1-8, shipped 2026-01-14)
- ✅ **v1.1 Sentinel Fingerprint** - [milestones/v1.1-ROADMAP.md](milestones/v1.1-ROADMAP.md) (Phases 9-17, shipped 2026-01-15)
- ✅ **v1.2 Approval Workflows** - [milestones/v1.2-ROADMAP.md](milestones/v1.2-ROADMAP.md) (Phases 18-26, shipped 2026-01-15)
- ✅ **v1.3 Break-Glass** — [milestones/v1.3-ROADMAP.md](milestones/v1.3-ROADMAP.md) (Phases 27-34, shipped 2026-01-16)
- ✅ **v1.4 Sentinel Bootstrapping** — [milestones/v1.4-ROADMAP.md](milestones/v1.4-ROADMAP.md) (Phases 35-42, shipped 2026-01-16)
- ✅ **v1.5 Enforcement & Assurance** — [milestones/v1.5-ROADMAP.md](milestones/v1.5-ROADMAP.md) (Phases 43-49, shipped 2026-01-16)
- ✅ **v1.6 Testing & Hardening** — [milestones/v1.6-ROADMAP.md](milestones/v1.6-ROADMAP.md) (Phases 50-59, shipped 2026-01-17)
- 🚧 **v1.7 Permissions Discovery** — Phases 60-68 (in progress)

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

<details>
<summary>✅ v1.4 Sentinel Bootstrapping (Phases 35-42) — SHIPPED 2026-01-16</summary>

- [x] Phase 35: Bootstrap Schema (1/1 plans) — completed 2026-01-16
- [x] Phase 36: Bootstrap Planner (1/1 plans) — completed 2026-01-15
- [x] Phase 37: SSM Parameter Creation (1/1 plans) — completed 2026-01-16
- [x] Phase 38: Sample Policy Generation (1/1 plans) — completed 2026-01-16
- [x] Phase 39: IAM Policy Generation (1/1 plans) — completed 2026-01-16
- [x] Phase 40: Bootstrap Command (1/1 plans) — completed 2026-01-16
- [x] Phase 41: Status Command (1/1 plans) — completed 2026-01-16
- [x] Phase 42: Bootstrap Documentation (1/1 plans) — completed 2026-01-16

</details>

<details>
<summary>✅ v1.5 Enforcement & Assurance (Phases 43-49) — SHIPPED 2026-01-16</summary>

- [x] Phase 43: Enforcement Types (2/2 plans) — completed 2026-01-16
- [x] Phase 44: Enforcement Advisor (1/1 plans) — completed 2026-01-16
- [x] Phase 45: Trust Policy Templates (1/1 plans) — completed 2026-01-16
- [x] Phase 46: CloudTrail Query Types (1/1 plans) — completed 2026-01-16
- [x] Phase 47: Audit Verify Command (1/1 plans) — completed 2026-01-16
- [x] Phase 48: Require Sentinel Mode (1/1 plans) — completed 2026-01-16
- [x] Phase 49: Enforcement Documentation (1/1 plans) — completed 2026-01-16

</details>

<details>
<summary>✅ v1.6 Testing & Hardening (Phases 50-59) — SHIPPED 2026-01-17</summary>

**Milestone Goal:** Comprehensive test coverage and validation before production release (>80% coverage, security validation, performance benchmarks)

#### Phase 50: Test Infrastructure Setup

**Goal**: Set up coverage tooling and reusable test infrastructure
**Depends on**: v1.5 complete
**Research**: Unlikely (established Go testing patterns)
**Plans**: 2 plans

Plans:
- [x] 50-01: Coverage tooling & baseline metrics — completed 2026-01-16
- [x] 50-02: Mock framework & test helpers — completed 2026-01-16

#### Phase 51: Policy Engine Testing

**Goal**: Security-critical policy evaluation test coverage (>90%)
**Depends on**: Phase 50
**Research**: Unlikely (internal patterns)
**Plans**: 3 plans

Plans:
- [x] 51-01: SSM loader tests — completed 2026-01-16
- [x] 51-02: Policy authorization edge cases — completed 2026-01-17
- [x] 51-03: Credential gating validation — completed 2026-01-17

#### Phase 52: Break-Glass Security Testing

**Goal**: Rate limiting, state machine, and audit trail security tests
**Depends on**: Phase 51
**Research**: Unlikely (internal patterns)
**Plans**: 3 plans

Plans:
- [x] 52-01: Rate limiting logic tests — completed 2026-01-17
- [x] 52-02: State machine security tests — completed 2026-01-17
- [x] 52-03: Audit trail integrity tests — completed 2026-01-17

#### Phase 53: Approval Workflow Testing

**Goal**: Approval state machine and notification system tests
**Depends on**: Phase 52
**Research**: Unlikely (internal patterns)
**Plans**: 2 plans

Plans:
- [x] 53-01: Approval state machine tests — completed 2026-01-17
- [x] 53-02: Notification system tests — completed 2026-01-17

#### Phase 54: SourceIdentity & Fingerprinting Tests

**Goal**: Fingerprint generation and CloudTrail query tests (>90%)
**Depends on**: Phase 53
**Research**: Unlikely (internal patterns)
**Plans**: 2 plans

Plans:
- [x] 54-01: Fingerprint generation tests — completed 2026-01-17
- [x] 54-02: CloudTrail query tests — completed 2026-01-17

#### Phase 55: Bootstrap & Deployment Testing

**Goal**: Bootstrap planner and SSM integration tests
**Depends on**: Phase 54
**Research**: Unlikely (internal patterns)
**Plans**: 2 plans

Plans:
- [x] 55-01: Bootstrap planner tests — completed 2026-01-17
- [x] 55-02: SSM integration tests — completed 2026-01-17

#### Phase 56: Integration Testing

**Goal**: End-to-end credential flow and multi-service integration tests
**Depends on**: Phase 55
**Research**: Unlikely (internal patterns)
**Plans**: 3 plans

Plans:
- [x] 56-01: End-to-end credential flow tests — completed 2026-01-17
- [x] 56-02: Multi-service integration tests — completed 2026-01-17
- [x] 56-03: CLI command integration tests — completed 2026-01-17

#### Phase 57: Performance & Load Testing

**Goal**: Performance benchmarks, concurrency testing, and load simulation
**Depends on**: Phase 56
**Research**: Unlikely (established patterns)
**Plans**: 3 plans

Plans:
- [x] 57-01: Performance benchmarks — completed 2026-01-17
- [x] 57-02: Concurrency testing — completed 2026-01-17
- [x] 57-03: Load simulation — completed 2026-01-17

#### Phase 58: Security Regression Suite

**Goal**: Security test cases and threat model validation
**Depends on**: Phase 57
**Research**: Unlikely (internal patterns)
**Plans**: 2 plans

Plans:
- [x] 58-01: Security test cases — completed 2026-01-17
- [x] 58-02: Threat model validation — completed 2026-01-17

#### Phase 59: Pre-Release Validation

**Goal**: Coverage report, documentation validation, and release readiness
**Depends on**: Phase 58
**Research**: Unlikely (documentation review)
**Plans**: 3 plans

Plans:
- [x] 59-01: Coverage report & gaps — completed 2026-01-17
- [x] 59-02: Documentation validation — completed 2026-01-17
- [x] 59-03: Pre-release checklist — completed 2026-01-17

</details>

### 🚧 v1.7 Permissions Discovery (In Progress)

**Milestone Goal:** Help users understand and configure Sentinel permissions without trial-and-error. Commands to discover required IAM actions, validate current permissions, and streamline onboarding.

#### Phase 60: Permissions Schema

**Goal**: Define permission requirements per subsystem, map features to IAM actions
**Depends on**: v1.6 complete
**Research**: Unlikely (internal patterns)
**Plans**: 1 plan

Plans:
- [x] 60-01: Permission types and registry — completed 2026-01-18

#### Phase 61: Permissions Command

**Goal**: `sentinel permissions` CLI with JSON/Terraform/CloudFormation output formats
**Depends on**: Phase 60
**Research**: Unlikely (extends existing CLI patterns)
**Plans**: TBD

Plans:
- [ ] 61-01: TBD

#### Phase 62: Feature Detection

**Goal**: Auto-detect which subsystems are configured, suggest minimal permissions
**Depends on**: Phase 61
**Research**: Unlikely (internal patterns)
**Plans**: TBD

Plans:
- [ ] 62-01: TBD

#### Phase 63: Permission Validation

**Goal**: `sentinel permissions check` to verify current creds have required access
**Depends on**: Phase 62
**Research**: Likely (STS/IAM simulation APIs)
**Research topics**: sts:GetCallerIdentity, iam:SimulatePrincipalPolicy, dry-run patterns
**Plans**: TBD

Plans:
- [ ] 63-01: TBD

#### Phase 64: Guided Setup

**Goal**: `sentinel init` wizard for interactive first-time configuration
**Depends on**: Phase 63
**Research**: Unlikely (internal patterns)
**Plans**: TBD

Plans:
- [ ] 64-01: TBD

#### Phase 65: Error Enhancement

**Goal**: Better error messages for permission failures with specific fix suggestions
**Depends on**: Phase 64
**Research**: Unlikely (internal patterns)
**Plans**: TBD

Plans:
- [ ] 65-01: TBD

#### Phase 66: Config Validation

**Goal**: `sentinel config validate` to catch misconfigurations before runtime
**Depends on**: Phase 65
**Research**: Unlikely (internal patterns)
**Plans**: TBD

Plans:
- [ ] 66-01: TBD

#### Phase 67: Quick Start Templates

**Goal**: Pre-built configs for common use cases (`--template basic|approvals|full`)
**Depends on**: Phase 66
**Research**: Unlikely (internal patterns)
**Plans**: TBD

Plans:
- [ ] 67-01: TBD

#### Phase 68: Onboarding Docs

**Goal**: QUICKSTART.md, updated BOOTSTRAP.md, permission matrix documentation
**Depends on**: Phase 67
**Research**: Unlikely (documentation)
**Plans**: TBD

Plans:
- [ ] 68-01: TBD

## Progress (All Milestones)

| Milestone | Phases | Plans | Status | Shipped |
|-----------|--------|-------|--------|---------|
| v1.0 MVP | 1-8 | 16/16 | ✅ Complete | 2026-01-14 |
| v1.1 Sentinel Fingerprint | 9-17 | 12/12 | ✅ Complete | 2026-01-15 |
| v1.2 Approval Workflows | 18-26 | 17/17 | ✅ Complete | 2026-01-15 |
| v1.3 Break-Glass | 27-34 | 15/15 | ✅ Complete | 2026-01-16 |
| v1.4 Sentinel Bootstrapping | 35-42 | 8/8 | ✅ Complete | 2026-01-16 |
| v1.5 Enforcement & Assurance | 43-49 | 8/8 | ✅ Complete | 2026-01-16 |
| v1.6 Testing & Hardening | 50-59 | 25/25 | ✅ Complete | 2026-01-17 |
| v1.7 Permissions Discovery | 60-68 | 1/? | 🚧 In Progress | - |

**Totals:** 7 milestones shipped, 1 in progress (68 phases, 102+ plans)
