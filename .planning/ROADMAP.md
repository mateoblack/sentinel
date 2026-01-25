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
- ✅ **v1.7 Permissions Discovery** — [milestones/v1.7-ROADMAP.md](milestones/v1.7-ROADMAP.md) (Phases 60-68, shipped 2026-01-18)
- ✅ **v1.7.1 Security Patch** — [milestones/v1.7.1-ROADMAP.md](milestones/v1.7.1-ROADMAP.md) (Phases 69-72, shipped 2026-01-19)
- ✅ **v1.8 Credential Flow UX** — [milestones/v1.8-ROADMAP.md](milestones/v1.8-ROADMAP.md) (Phases 73-75, shipped 2026-01-19)
- ✅ **v1.9 SSO Profile Support** — [milestones/v1.9-ROADMAP.md](milestones/v1.9-ROADMAP.md) (Phases 76-77, shipped 2026-01-19)
- ✅ **v1.10.1 SSO Credential Fixes** — [milestones/v1.10.1-ROADMAP.md](milestones/v1.10.1-ROADMAP.md) (Phase 78.1, shipped 2026-01-19)
- ✅ **v1.10 Real-time Revocation** — [milestones/v1.10-ROADMAP.md](milestones/v1.10-ROADMAP.md) (Phases 78-83, shipped 2026-01-20)
- ✅ **v1.11 Shell Integration** — [milestones/v1.11-ROADMAP.md](milestones/v1.11-ROADMAP.md) (Phases 84-87, shipped 2026-01-20)
- ✅ **v1.12 Infrastructure Provisioning** — [milestones/v1.12-ROADMAP.md](milestones/v1.12-ROADMAP.md) (Phases 88-93, shipped 2026-01-22)
- ✅ **v1.13 Enforced Session Tracking** — [milestones/v1.13-ROADMAP.md](milestones/v1.13-ROADMAP.md) (Phases 94-96, shipped 2026-01-24)
- 🚧 **v1.14 Server-Side Credential Vending** — [milestones/v1.14-ROADMAP.md](milestones/v1.14-ROADMAP.md) (Phases 97-103, in progress)

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

<details>
<summary>✅ v1.7.1 Security Patch (Phases 69-72) — SHIPPED 2026-01-19</summary>

- [x] Phase 69: AWS Identity Core (1/1 plans) — completed 2026-01-19
- [x] Phase 70: Identity Integration (1/1 plans) — completed 2026-01-19
- [x] Phase 71: Whoami Command (1/1 plans) — completed 2026-01-19
- [x] Phase 72: Security Validation (4/4 plans) — completed 2026-01-19

</details>

## 🚧 v1.14 Server-Side Credential Vending (In Progress)

**Milestone Goal:** Move credential vending to server-side infrastructure (Lambda TVM) so clients cannot bypass policy enforcement. Lambda IS the trust boundary - protected roles trust ONLY the Lambda execution role.

### Phase 97: Foundation

**Goal**: Establish Lambda build pipeline and basic handler logic before AWS integration
**Depends on**: v1.13 complete
**Requirements**: LCORE-01
**Success Criteria** (what must be TRUE):
  1. Lambda binary builds for Linux architecture via make target
  2. Lambda handler parses API Gateway request and extracts caller identity
  3. Lambda handler returns credentials in AWS container credentials format
  4. Unit tests verify request parsing logic
**Plans**: 2 plans in 2 waves

Plans:
- [x] 97-01: Lambda infrastructure (build pipeline + types) — Wave 1 — completed 2026-01-24
- [x] 97-02: Handler implementation + tests — Wave 2 — completed 2026-01-24

### Phase 98: Credential Vending

**Goal**: Core TVM functionality - credential issuance via STS AssumeRole
**Depends on**: Phase 97
**Requirements**: LCORE-03, LCORE-04
**Success Criteria** (what must be TRUE):
  1. Lambda calls STS AssumeRole with SourceIdentity stamping
  2. Lambda returns temporary credentials in AWS container credentials format
  3. Returned credentials work for AWS service access (integration test)
  4. Lambda execution role IAM policy template exists for least-privilege AssumeRole
  5. Protected role trust policy template exists (trusts only Lambda execution role)
**Plans**: TBD

Plans:
- [x] 98-01: Credential vending function (VendCredentials, SourceIdentity stamping) — Wave 1 — completed 2026-01-25
- [x] 98-02: Handler integration (VendCredentials integration, duration parameter) — Wave 2 — completed 2026-01-25
- [x] 98-03: Lambda IAM role templates documentation — Wave 2 — completed 2026-01-25

### Phase 99: Policy & Session Integration

**Goal**: Reuse existing Sentinel policy evaluation, session tracking, approval, and break-glass logic with session tagging
**Depends on**: Phase 98
**Requirements**: LCORE-02, LCORE-05, LCORE-06, LCORE-07, LCORE-08, LCORE-09
**Success Criteria** (what must be TRUE):
  1. Lambda evaluates Sentinel policy before issuing credentials (policy deny blocks issuance)
  2. Lambda integrates with DynamoDB session tracking (sessions created/tracked via environment variable table name)
  3. Lambda stamps session ID as session tag on AssumeRole for downstream revocation checks
  4. Lambda checks for approved requests before credential issuance (approval flow works)
  5. Lambda checks for active break-glass before credential issuance (emergency access works)
  6. Lambda decision logging to CloudWatch in JSON Lines format (audit trail exists)
**Plans**: 4 plans in 3 waves

Plans:
- [x] 99-01: TVM configuration layer (TVMConfig + environment loading) — Wave 1 — completed 2026-01-25
- [x] 99-02: Policy evaluation integration — Wave 2 — completed 2026-01-25
- [x] 99-03: Session tracking with session tagging — Wave 2 — completed 2026-01-25
- [x] 99-04: Approval, break-glass, and logging integration — Wave 3 — completed 2026-01-25

### Phase 100: API Gateway

**Goal**: Expose Lambda via HTTP API with IAM authorization for caller identity extraction
**Depends on**: Phase 99
**Requirements**: APIGW-01, APIGW-02, APIGW-03, APIGW-04
**Success Criteria** (what must be TRUE):
  1. HTTP API endpoint serves credential vending at root path
  2. IAM authorization (SigV4) extracts caller identity from API Gateway request
  3. Profile discovery endpoint (GET /profiles) returns available profiles from SSM
  4. Resource policy restricts API Gateway access to VPC or IP ranges (deployment example)
  5. End-to-end test: API Gateway request returns credentials usable for AWS service access
**Plans**: 4 plans in 3 waves

Plans:
- [x] 100-01: Routing and profile discovery (Router, ProfileDiscovery) — Wave 1 — completed 2026-01-25
- [x] 100-02: Config integration (SSM client, policy root config) — Wave 2 — completed 2026-01-25
- [ ] 100-03: Main entry point (Lambda main.go with Router) — Wave 2
- [ ] 100-04: End-to-end test documentation — Wave 3

### Phase 101: Client Integration

**Goal**: Enable CLI and SDK clients to use remote TVM for credentials
**Depends on**: Phase 100
**Requirements**: CLIENT-01, CLIENT-02, CLIENT-03
**Success Criteria** (what must be TRUE):
  1. `sentinel exec --remote-server <url>` sets AWS_CONTAINER_CREDENTIALS_FULL_URI for SDK integration
  2. Documentation exists for manual credential URI setup without CLI changes (SDK-only clients)
  3. SCP example patterns exist to enforce TVM-only access (block direct AssumeRole calls)
  4. Integration test: sentinel exec --remote-server calls TVM endpoint and receives working credentials
**Plans**: TBD

Plans:
- [ ] 101-01: TBD

### Phase 102: Infrastructure as Code

**Goal**: Automate deployment once all components work end-to-end
**Depends on**: Phase 101
**Requirements**: INFRA-01, INFRA-02, INFRA-03, INFRA-04, INFRA-05
**Success Criteria** (what must be TRUE):
  1. Terraform module exists for Lambda + API Gateway deployment
  2. Lambda execution role template exists with least-privilege permissions
  3. Protected role trust policy template exists (trusts only Lambda execution role)
  4. CDK example exists for Lambda + API Gateway deployment
  5. Cost optimization documentation exists (low/medium/high volume patterns)
  6. Integration test: terraform apply deploys working TVM (credentials issued successfully)
**Plans**: TBD

Plans:
- [ ] 102-01: TBD

### Phase 103: Testing & Documentation

**Goal**: Comprehensive testing and deployment documentation for production readiness
**Depends on**: Phase 102
**Requirements**: TEST-01, TEST-02, TEST-03, DOC-01, DOC-02
**Success Criteria** (what must be TRUE):
  1. Integration tests cover full credential vending flow (API Gateway → Lambda → STS → working credentials)
  2. Security regression tests validate policy bypass prevention (cannot circumvent TVM)
  3. Load testing confirms <200ms p99 latency at target throughput
  4. LAMBDA_TVM.md deployment guide exists with setup instructions
  5. Migration guide exists comparing CLI server vs Lambda TVM (decision framework for users)
**Plans**: TBD

Plans:
- [ ] 103-01: TBD

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

<details>
<summary>✅ v1.7 Permissions Discovery (Phases 60-68) — SHIPPED 2026-01-18</summary>

- [x] Phase 60: Permissions Schema (1/1 plans) — completed 2026-01-18
- [x] Phase 61: Permissions Command (1/1 plans) — completed 2026-01-18
- [x] Phase 62: Feature Detection (1/1 plans) — completed 2026-01-18
- [x] Phase 63: Permission Validation (1/1 plans) — completed 2026-01-18
- [x] Phase 64: Guided Setup (1/1 plans) — completed 2026-01-18
- [x] Phase 65: Error Enhancement (2/2 plans) — completed 2026-01-18
- [x] Phase 66: Config Validation (1/1 plans) — completed 2026-01-18
- [x] Phase 67: Quick Start Templates (1/1 plans) — completed 2026-01-18
- [x] Phase 68: Onboarding Docs (1/1 plans) — completed 2026-01-18

</details>

<details>
<summary>✅ v1.8 Credential Flow UX (Phases 73-75) — SHIPPED 2026-01-19</summary>

**Milestone Goal:** Developer experience improvements for credential handling — automatic SSO profile resolution and login triggering.

- [x] Phase 73: SSO Profile Resolution (1/1 plans) — completed 2026-01-19
- [x] Phase 74: Auto SSO Login (2/2 plans) — completed 2026-01-19
- [x] Phase 75: AWS Auth Error Enhancement (deferred to v1.9)

</details>

<details>
<summary>✅ v1.9 SSO Profile Support (Phases 76-77) — SHIPPED 2026-01-19</summary>

**Milestone Goal:** Fix systemic bug where --profile flag doesn't load SSO credentials, ensuring all Sentinel commands work seamlessly with SSO profiles like AWS CLI does.

- [x] Phase 76: SSO Credential Loading (5/5 plans) — completed 2026-01-19
- [x] Phase 77: Whoami Profile Flag (1/1 plan) — completed 2026-01-19

</details>

<details>
<summary>✅ v1.10 Real-time Revocation (Phases 78-83) — SHIPPED 2026-01-20</summary>

- [x] Phase 78: Server Infrastructure (2/2 plans) — completed 2026-01-19
- [x] Phase 79: Server Policy Integration (2/2 plans) — completed 2026-01-20
- [x] Phase 80: Short-Lived Sessions (1/1 plans) — completed 2026-01-20
- [x] Phase 81: Session Management (4/4 plans) — completed 2026-01-20
- [x] Phase 82: Server Mode Enforcement (3/3 plans) — completed 2026-01-20
- [x] Phase 83: Server Mode Testing (3/3 plans) — completed 2026-01-20

See [milestones/v1.10-ROADMAP.md](milestones/v1.10-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.11 Shell Integration (Phases 84-87) — SHIPPED 2026-01-20</summary>

- [x] Phase 84: Shell Init Command (1/1 plans) — completed 2026-01-20
- [x] Phase 85: Server Mode Variants (1/1 plans) — completed 2026-01-20
- [x] Phase 86: Shell Completions (1/1 plans) — completed 2026-01-20
- [x] Phase 87: Documentation & Testing (1/1 plans) — completed 2026-01-20

See [milestones/v1.11-ROADMAP.md](milestones/v1.11-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.12 Infrastructure Provisioning (Phases 88-93) — SHIPPED 2026-01-22</summary>

- [x] Phase 88: Approval Table Provisioning (3/3 plans + 1 fix plan) — completed 2026-01-22
- [x] Phase 89: Breakglass Table Provisioning (2/2 plans) — completed 2026-01-22
- [x] Phase 90: Session Table Provisioning (2/2 plans) — completed 2026-01-22
- [x] Phase 91: Unified Bootstrap Extension (2/2 plans) — completed 2026-01-22
- [x] Phase 92: Enhanced Init Status (2/2 plans) — completed 2026-01-22
- [x] Phase 93: Documentation Validation (3/3 plans) — completed 2026-01-22

See [milestones/v1.12-ROADMAP.md](milestones/v1.12-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.13 Enforced Session Tracking (Phases 94-96) — SHIPPED 2026-01-24</summary>

- [x] Phase 94: Policy Effect - require_server_session (3/3 plans) — completed 2026-01-24
- [x] Phase 95: Default Session Table Configuration (4/4 plans) — completed 2026-01-24
- [x] Phase 96: Session Tracking Audit & Compliance (3/3 plans) — completed 2026-01-24

See [milestones/v1.13-ROADMAP.md](milestones/v1.13-ROADMAP.md) for full details.

</details>

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
| v1.7 Permissions Discovery | 60-68 | 10/10 | ✅ Complete | 2026-01-18 |
| v1.7.1 Security Patch | 69-72 | 7/7 | ✅ Complete | 2026-01-19 |
| v1.8 Credential Flow UX | 73-75 | 3/3 | ✅ Complete | 2026-01-19 |
| v1.9 SSO Profile Support | 76-77 | 6/6 | ✅ Complete | 2026-01-19 |
| v1.10.1 SSO Credential Fixes | 78.1 | 2/2 | ✅ Complete | 2026-01-19 |
| v1.10 Real-time Revocation | 78-83 | 15/15 | ✅ Complete | 2026-01-20 |
| v1.11 Shell Integration | 84-87 | 4/4 | ✅ Complete | 2026-01-20 |
| v1.12 Infrastructure Provisioning | 88-93 | 15/15 | ✅ Complete | 2026-01-22 |
| v1.13 Enforced Session Tracking | 94-96 | 10/10 | ✅ Complete | 2026-01-24 |
| v1.14 Server-Side Credential Vending | 97-103 | 10/TBD | 🚧 In progress | - |

**Totals:** 16 milestones shipped, 1 in progress (96 phases, 196 plans shipped)
