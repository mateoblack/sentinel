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
- ✅ **v1.14 Server-Side Credential Vending** — [milestones/v1.14-ROADMAP.md](milestones/v1.14-ROADMAP.md) (Phases 97-103, shipped 2026-01-25)
- ✅ **v1.15 Device Posture** — [milestones/v1.15-ROADMAP.md](milestones/v1.15-ROADMAP.md) (Phases 104-112, shipped 2026-01-25)
- ✅ **v1.16 Security Hardening** — [milestones/v1.16-ROADMAP.md](milestones/v1.16-ROADMAP.md) (Phases 113-120, shipped 2026-01-26)
- ✅ **v1.17 Policy Developer Experience** — [milestones/v1.17-ROADMAP.md](milestones/v1.17-ROADMAP.md) (Phases 121-125, shipped 2026-01-26)
- 🚧 **v1.18 Critical Security Hardening** — [milestones/v1.18-ROADMAP.md](milestones/v1.18-ROADMAP.md) (Phases 126-135, in progress)

- ⏳ **v1.19 Documentation & Completeness Audit** — [milestones/v1.19-ROADMAP.md](milestones/v1.19-ROADMAP.md) (Phases 136-142, pending v1.18)
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

<details>
<summary>✅ v1.14 Server-Side Credential Vending (Phases 97-103) — SHIPPED 2026-01-25</summary>

- [x] Phase 97: Foundation (2/2 plans) — completed 2026-01-24
- [x] Phase 98: Credential Vending (3/3 plans) — completed 2026-01-25
- [x] Phase 99: Policy & Session Integration (4/4 plans) — completed 2026-01-25
- [x] Phase 100: API Gateway (4/4 plans) — completed 2026-01-25
- [x] Phase 101: Client Integration (2/2 plans) — completed 2026-01-25
- [x] Phase 102: Infrastructure as Code (3/3 plans) — completed 2026-01-25
- [x] Phase 103: Testing & Documentation (2/2 plans) — completed 2026-01-25

See [milestones/v1.14-ROADMAP.md](milestones/v1.14-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.15 Device Posture (Phases 104-112) — SHIPPED 2026-01-25</summary>

- [x] Phase 104: Device Fingerprint Schema (1/1 plans) — completed 2026-01-25
- [x] Phase 105: Device Collector Interface (1/1 plans) — completed 2026-01-25
- [x] Phase 106: Device Identification (1/1 plans) — completed 2026-01-25
- [x] Phase 107: MDM API Integration (3/3 plans) — completed 2026-01-25
- [x] Phase 108: Policy Device Conditions (1/1 plans) — completed 2026-01-25
- [x] Phase 109: Device Attestation Flow (1/1 plans) — completed 2026-01-25
- [x] Phase 110: Session Device Binding (1/1 plans) — completed 2026-01-25
- [x] Phase 111: Decision Logging Enhancement (1/1 plans) — completed 2026-01-25
- [x] Phase 112: Device Audit Commands (1/1 plans) — completed 2026-01-25

See [milestones/v1.15-ROADMAP.md](milestones/v1.15-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.16 Security Hardening (Phases 113-120) — SHIPPED 2026-01-26</summary>

- [x] Phase 113: Timing Attack Remediation (1/1 plans) — completed 2026-01-25
- [x] Phase 114: Secrets Manager Migration (2/2 plans) — completed 2026-01-25
- [x] Phase 115: CI/CD Security Scanning (1/1 plans) — completed 2026-01-25
- [x] Phase 116: DynamoDB Encryption (1/1 plans) — completed 2026-01-25
- [x] Phase 117: API Rate Limiting (2/2 plans) — completed 2026-01-25
- [x] Phase 118: Dependency Security Audit (1/1 plans) — completed 2026-01-25
- [x] Phase 119: Error Sanitization (1/1 plans) — completed 2026-01-26
- [x] Phase 120: Security Validation (1/1 plans) — completed 2026-01-26

See [milestones/v1.16-ROADMAP.md](milestones/v1.16-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.17 Policy Developer Experience (Phases 121-125) — SHIPPED 2026-01-26</summary>

- [x] Phase 121: Policy Schema Enhancements (1/1 plans) — completed 2026-01-26
- [x] Phase 122: Policy Pull Command (1/1 plans) — completed 2026-01-26
- [x] Phase 123: Policy Push Command (1/1 plans) — completed 2026-01-26
- [x] Phase 124: Policy Diff Command (1/1 plans) — completed 2026-01-26
- [x] Phase 125: Policy Validate Command (1/1 plans) — completed 2026-01-26

See [milestones/v1.17-ROADMAP.md](milestones/v1.17-ROADMAP.md) for full details.

</details>

### 🚧 v1.18 Critical Security Hardening (In Progress)

**Milestone Goal:** Address P0 security threats and high-risk vulnerabilities identified in STRIDE threat model analysis, including policy cache poisoning, break-glass bypass, audit log tampering, and credential exposure.

#### Phase 126: Policy Integrity ✅

**Goal**: KMS-signed policy validation to prevent cache poisoning attacks
**Depends on**: v1.17 complete
**Completed**: 2026-01-26
**Plans**: 3/3

Plans:
- [x] 126-01: KMS signing infrastructure (KMSAPI interface, PolicySigner, signature types) — completed 2026-01-26
- [x] 126-02: Verifying loader & CLI commands (VerifyingLoader, policy sign/verify, push --sign) — completed 2026-01-26
- [x] 126-03: Lambda TVM integration & security tests (config, handler integration, security tests) — completed 2026-01-26

#### Phase 127: Break-Glass MFA ✅

**Goal**: Secondary verification (SMS/push) for emergency access to prevent abuse
**Depends on**: Phase 126
**Completed**: 2026-01-26
**Plans**: 3/3

Plans:
- [x] 127-01: MFA infrastructure (types, TOTP verifier, SMS verifier via SNS) — completed 2026-01-26
- [x] 127-02: Break-glass MFA integration (policy MFA requirements, CLI flow, logging) — completed 2026-01-26
- [x] 127-03: Security tests & CLI config (regression tests, SSM-based MFA configuration) — completed 2026-01-26

#### Phase 128: Audit Log Integrity ✅

**Goal**: CloudWatch forwarding with HMAC signatures for tamper-evident logging
**Depends on**: Phase 127
**Completed**: 2026-01-26
**Plans**: 3/3

Plans:
- [x] 128-01: HMAC signature types and SignedLogger wrapper — completed 2026-01-26
- [x] 128-02: CloudWatch Logs forwarder and Lambda TVM integration — completed 2026-01-26
- [x] 128-03: verify-logs CLI command and security regression tests — completed 2026-01-26

#### Phase 129: Local Server Security ✅

**Goal**: Process-based authentication for credential servers to prevent local access
**Depends on**: Phase 128
**Completed**: 2026-01-26
**Plans**: 4/4

Plans:
- [x] 129-01: Peer credential infrastructure (PeerCredentials types, GetPeerCredentials, Linux/macOS/fallback) — completed 2026-01-26
- [x] 129-02: Unix server with process auth (ProcessAuthenticator, UnixServer, WithProcessAuth middleware) — completed 2026-01-26
- [x] 129-03: Credential server integration (SentinelServer Unix mode, CLI flags, integration tests) — completed 2026-01-26
- [x] 129-04: ECS/EC2 Unix mode & security tests (EcsServer Unix mode, EC2 security docs, regression tests) — completed 2026-01-26

#### Phase 130: Identity Hardening

**Goal**: Strengthen AWS STS identity validation, remove OS username dependency
**Depends on**: Phase 129
**Research**: Unlikely (extends v1.7.1 STS identity work)
**Plans**: TBD

Plans:
- [ ] 130-01: TBD (run /gsd:plan-phase 130 to break down)

#### Phase 131: DynamoDB Security ✅

**Goal**: State integrity validation with conditional writes to prevent manipulation
**Depends on**: Phase 130
**Completed**: 2026-01-26
**Plans**: 2/2

Plans:
- [x] 131-01: Fix optimistic locking bug + state transition validation (session/dynamodb.go Update fix, request/breakglass state validation) — completed 2026-01-26
- [x] 131-02: Security regression tests (TestSecurityRegression_ tests for all three DynamoDB stores) — completed 2026-01-26

#### Phase 132: Keyring Protection ✅

**Goal**: Secure credential storage with access controls and encryption
**Depends on**: Phase 131
**Completed**: 2026-01-26
**Plans**: 2/2

Plans:
- [x] 132-01: Keyring security hardening (macOS Keychain ACLs, Linux keyctl permissions, iCloud sync prevention) — completed 2026-01-26
- [x] 132-02: Security regression tests (TestSecurityRegression_* tests for keyring item properties) — completed 2026-01-26

#### Phase 133: Rate Limit Hardening

**Goal**: Distributed rate limiting with DynamoDB to prevent bypass attacks
**Depends on**: Phase 132
**Research**: Unlikely (extends v1.16 rate limiting)
**Plans**: TBD

Plans:
- [ ] 133-01: TBD (run /gsd:plan-phase 133 to break down)

#### Phase 134: Input Sanitization

**Goal**: Command injection prevention in MFA process and all user inputs
**Depends on**: Phase 133
**Research**: Unlikely (input validation patterns, shell escaping)
**Plans**: TBD

Plans:
- [ ] 134-01: TBD (run /gsd:plan-phase 134 to break down)

#### Phase 135: Security Validation

**Goal**: Comprehensive security regression testing for all P0 and high-risk findings
**Depends on**: Phase 134
**Research**: Unlikely (extends existing test framework)
**Plans**: TBD

Plans:
- [ ] 135-01: TBD (run /gsd:plan-phase 135 to break down)

### ⏳ v1.19 Documentation & Completeness Audit (Pending v1.18)

**Milestone Goal:** Close documentation gaps for v1.13-v1.18 features, ensuring all capabilities shipped in recent milestones are properly documented for users and operators.

**Status:** Waiting for v1.18 Critical Security Hardening to complete (phases 129-135 remaining).

#### Phase 136: CHANGELOG Completion

**Goal**: Update CHANGELOG with all shipped v1.13-v1.18 releases
**Depends on**: v1.18 complete (Phase 135)
**Requirements**: CHLOG-01, CHLOG-02, CHLOG-03, CHLOG-04, CHLOG-05, CHLOG-06
**Success Criteria** (what must be TRUE):
  1. CHANGELOG shows v1.13-v1.18 as released with ship dates (not "Unreleased")
  2. Each version entry lists all major features shipped
  3. Ship dates match actual milestone completion dates from git history
  4. CHANGELOG follows consistent format with previous entries
**Plans**: TBD

Plans:
- [ ] 136-01: TBD (run /gsd:plan-phase 136 to break down)

#### Phase 137: Command Documentation

**Goal**: Document all policy commands in commands.md with syntax and examples
**Depends on**: Phase 136
**Requirements**: CMD-01, CMD-02, CMD-03, CMD-04, CMD-05, CMD-06
**Success Criteria** (what must be TRUE):
  1. User can find all 6 policy commands documented in commands.md
  2. Each command shows syntax, flags, and practical examples
  3. Policy workflow is clear (pull → edit → validate → diff → push)
  4. Examples demonstrate both basic and advanced usage
**Plans**: TBD

Plans:
- [ ] 137-01: TBD (run /gsd:plan-phase 137 to break down)

#### Phase 138: Policy Signing Guide

**Goal**: Create POLICY_SIGNING.md explaining KMS-based policy integrity
**Depends on**: Phase 137
**Requirements**: PSIGN-01, PSIGN-02, PSIGN-03, PSIGN-04, PSIGN-05, PSIGN-06
**Success Criteria** (what must be TRUE):
  1. User understands why policy signing prevents attacks (threat model documented)
  2. User can create KMS signing key following documented steps
  3. User can sign and verify policies locally
  4. Operator can configure Lambda TVM signature verification
  5. Troubleshooting section addresses common signature errors
**Plans**: TBD

Plans:
- [ ] 138-01: TBD (run /gsd:plan-phase 138 to break down)

#### Phase 139: Device Posture Guide

**Goal**: Create DEVICE_POSTURE.md explaining MDM integration and device verification
**Depends on**: Phase 138
**Requirements**: DPOST-01, DPOST-02, DPOST-03, DPOST-04, DPOST-05
**Success Criteria** (what must be TRUE):
  1. User understands device posture threat model and use cases
  2. Operator can configure Jamf Pro MDM provider following documented steps
  3. User can write policy rules with device conditions (require_mdm, require_encryption)
  4. Operator can audit device compliance using device-sessions and devices commands
  5. Troubleshooting section addresses common device verification failures
**Plans**: TBD

Plans:
- [ ] 139-01: TBD (run /gsd:plan-phase 139 to break down)

#### Phase 140: Security Hardening Guide

**Goal**: Create SECURITY_HARDENING.md documenting v1.16 hardening features
**Depends on**: Phase 139
**Requirements**: HARD-01, HARD-02, HARD-03, HARD-04, HARD-05, HARD-06
**Success Criteria** (what must be TRUE):
  1. Security team understands all v1.16 hardening features and their purpose
  2. Timing attack mitigation is explained with crypto/subtle.ConstantTimeCompare example
  3. Secrets Manager integration is documented with configuration examples
  4. Rate limiting configuration is documented for Lambda TVM and credential servers
  5. Error sanitization pattern is explained (log details, return generic messages)
  6. DynamoDB KMS encryption is documented with deployment examples
**Plans**: TBD

Plans:
- [ ] 140-01: TBD (run /gsd:plan-phase 140 to break down)

#### Phase 141: README & Examples Update

**Goal**: Update README feature list and add examples for new features
**Depends on**: Phase 140
**Requirements**: README-01, README-02, README-03, README-04, EX-01, EX-02, EX-03, EX-04
**Success Criteria** (what must be TRUE):
  1. README mentions Lambda TVM, device posture, and policy signing in feature list
  2. README feature list is complete through v1.18
  3. Example policy demonstrates policy signing workflow
  4. Example policy demonstrates device posture conditions
  5. Terraform example shows KMS signing key creation
  6. Lambda TVM deployment example includes signature verification configuration
**Plans**: TBD

Plans:
- [ ] 141-01: TBD (run /gsd:plan-phase 141 to break down)

#### Phase 142: Deployment Guide Review

**Goal**: Review and update deployment.md for accuracy with v1.18
**Depends on**: Phase 141
**Requirements**: DEPLOY-01, DEPLOY-02, DEPLOY-03
**Success Criteria** (what must be TRUE):
  1. Deployment.md examples are accurate for v1.18
  2. DynamoDB encryption examples are verified (already added in Phase 126)
  3. All Terraform examples use current syntax
  4. No outdated commands or deprecated flags in examples
**Plans**: TBD

Plans:
- [ ] 142-01: TBD (run /gsd:plan-phase 142 to break down)

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
| v1.14 Server-Side Credential Vending | 97-103 | 19/19 | ✅ Complete | 2026-01-25 |
| v1.15 Device Posture | 104-112 | 12/12 | ✅ Complete | 2026-01-25 |
| v1.16 Security Hardening | 113-120 | 9/9 | ✅ Complete | 2026-01-26 |
| v1.17 Policy Developer Experience | 121-125 | 5/5 | ✅ Complete | 2026-01-26 |
| v1.18 Critical Security Hardening | 126-135 | 16/? | 🚧 In Progress | - |
| v1.19 Documentation & Completeness Audit | 136-142 | 0/? | ⏳ Pending | - |

**Totals:** 21 milestones shipped (125 phases, 230 plans shipped), 1 milestone in progress (10 phases), 1 milestone pending (7 phases)
