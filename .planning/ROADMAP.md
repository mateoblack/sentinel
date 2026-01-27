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
- ✅ **v1.18 Critical Security Hardening** — [milestones/v1.18-ROADMAP.md](milestones/v1.18-ROADMAP.md) (Phases 126-135, shipped 2026-01-26)
- ✅ **v1.19 Documentation & Completeness Audit** — [milestones/v1.19-ROADMAP.md](milestones/v1.19-ROADMAP.md) (Phases 136-142, shipped 2026-01-26)
- ✅ **v1.20 CLI Security & Deployment Helpers** — [milestones/v1.20-ROADMAP.md](milestones/v1.20-ROADMAP.md) (Phases 143-149, shipped 2026-01-27)

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

<details>
<summary>✅ v1.18 Critical Security Hardening (Phases 126-135) — SHIPPED 2026-01-26</summary>

- [x] Phase 126: Policy Integrity (3/3 plans) — completed 2026-01-26
- [x] Phase 127: Break-Glass MFA (3/3 plans) — completed 2026-01-26
- [x] Phase 128: Audit Log Integrity (3/3 plans) — completed 2026-01-26
- [x] Phase 129: Local Server Security (4/4 plans) — completed 2026-01-26
- [x] Phase 130: Identity Hardening (1/1 plans) — completed 2026-01-26
- [x] Phase 131: DynamoDB Security (2/2 plans) — completed 2026-01-26
- [x] Phase 132: Keyring Protection (2/2 plans) — completed 2026-01-26
- [x] Phase 133: Rate Limit Hardening (2/2 plans) — completed 2026-01-26
- [x] Phase 134: Input Sanitization (2/2 plans) — completed 2026-01-26
- [x] Phase 135: Security Validation (2/2 plans) — completed 2026-01-26

See [milestones/v1.18-ROADMAP.md](milestones/v1.18-ROADMAP.md) for full details.

</details>

<details>
<summary>✅ v1.19 Documentation & Completeness Audit (Phases 136-142) — SHIPPED 2026-01-26</summary>

- [x] Phase 136: CHANGELOG Completion (1/1 plans) — completed 2026-01-26
- [x] Phase 137: Command Documentation (1/1 plans) — completed 2026-01-26
- [x] Phase 138: Policy Signing Guide (1/1 plans) — completed 2026-01-26
- [x] Phase 139: Device Posture Guide (1/1 plans) — completed 2026-01-26
- [x] Phase 140: Security Hardening Guide (1/1 plans) — completed 2026-01-26
- [x] Phase 141: README & Examples Update (1/1 plans) — completed 2026-01-26
- [x] Phase 142: Deployment Guide Review (1/1 plans) — completed 2026-01-26

See [milestones/v1.19-ROADMAP.md](milestones/v1.19-ROADMAP.md) for full details.

</details>

## Domain Expertise

None

<details>
<summary>✅ v1.20 CLI Security & Deployment Helpers (Phases 143-149) — SHIPPED 2026-01-27</summary>

- [x] Phase 143: Policy Linting (1/1 plans) — completed 2026-01-26
- [x] Phase 144: Trust Policy Validation (1/1 plans) — completed 2026-01-27
- [x] Phase 145: Deployment Validation (1/1 plans) — completed 2026-01-27
- [x] Phase 146: SCP Deployment (1/1 plans) — completed 2026-01-27
- [x] Phase 147: DynamoDB Hardening (1/1 plans) — completed 2026-01-27
- [x] Phase 148: SSM Hardening (1/1 plans) — completed 2026-01-27
- [x] Phase 149: CloudTrail Monitoring (1/1 plans) — completed 2026-01-27

See [milestones/v1.20-ROADMAP.md](milestones/v1.20-ROADMAP.md) for full details.

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
| v1.18 Critical Security Hardening | 126-135 | 24/24 | ✅ Complete | 2026-01-26 |
| v1.19 Documentation & Completeness Audit | 136-142 | 7/7 | ✅ Complete | 2026-01-26 |
| v1.20 CLI Security & Deployment Helpers | 143-149 | 7/7 | ✅ Complete | 2026-01-27 |

**Totals:** 23 milestones (23 shipped) - 149 phases complete
