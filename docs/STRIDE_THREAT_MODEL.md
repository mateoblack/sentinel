# STRIDE Threat Model: Sentinel AWS Credential Management System

**Version:** 2.0
**Date:** 2026-01-27
**Status:** v2.0 Release
**Coverage:** Sentinel v2.0

## Executive Summary

This document presents a comprehensive STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat model for the Sentinel AWS credential management system. The analysis covers the complete architecture including the CLI tool, Lambda TVM (Token Vending Machine), ECS credential server, DynamoDB state stores, SSM Parameter Store, KMS signing infrastructure, and MDM integration.

**Key Findings:**
- **153 security regression tests** across 13 packages validate security controls
- **v1.15-v1.18 hardening** addressed major vulnerabilities (timing attacks, policy signing, MFA, audit log integrity)
- **Remaining high-priority gaps** identified in cross-account scenarios, session hijacking, and supply chain security
- **30+ specific threats** analyzed with impact/likelihood scoring

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [STRIDE Analysis by Category](#2-stride-analysis-by-category)
3. [Trust Boundary Analysis](#3-trust-boundary-analysis)
4. [Attack Scenarios](#4-attack-scenarios)
5. [Risk Prioritization](#5-risk-prioritization)
6. [Verification Against Existing Controls](#6-verification-against-existing-controls)
7. [Recommendations](#7-recommendations)

---

## 1. System Overview

### 1.1 Architecture Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INTERNET BOUNDARY                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS (IAM Auth)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    AWS Lambda TVM (Trust Boundary)                      │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ • IAM authorization via API Gateway v2                         │    │
│  │ • Policy evaluation (VerifyingLoader → CachedLoader)          │    │
│  │ • KMS signature verification (RSASSA_PSS_SHA_256)             │    │
│  │ • MDM device posture verification (Jamf Pro API)              │    │
│  │ • MFA verification (TOTP, SMS via SNS)                        │    │
│  │ • Rate limiting (DynamoDB distributed counters)               │    │
│  │ • HMAC-signed audit logging (CloudWatch Logs)                 │    │
│  │ • STS AssumeRole with SourceIdentity stamping                 │    │
│  └────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌──────────┐        ┌──────────┐        ┌──────────────┐
    │ DynamoDB │        │   SSM    │        │ AWS Secrets  │
    │ (KMS     │        │Parameter │        │  Manager     │
    │ encrypt) │        │  Store   │        │ (MDM tokens) │
    └──────────┘        └──────────┘        └──────────────┘
    • Approval          • Policies           • API credentials
    • Breakglass        • Signatures         • 1-hour cache
    • Sessions          • KMS signed
    • Rate limits

┌─────────────────────────────────────────────────────────────────────────┐
│                         WORKSTATION BOUNDARY                            │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │  Sentinel CLI                                                  │    │
│  │  • Policy evaluation (local mode)                              │    │
│  │  • Device ID generation (HMAC-SHA256 of machine UUID)          │    │
│  │  • AWS STS GetCallerIdentity for identity extraction           │    │
│  │  • SSM policy loading                                          │    │
│  │  • Keychain/Keyring credential storage (ACLs, no iCloud sync) │    │
│  │  • Unix socket server (process authentication via SO_PEERCRED) │    │
│  └────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐
    │ Keychain │        │ aws-vault│        │ AWS STS  │
    │  (macOS) │        │credential│        │          │
    │ Keyring  │        │  cache   │        │          │
    │ (Linux)  │        │          │        │          │
    └──────────┘        └──────────┘        └──────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    CONTAINER/ECS BOUNDARY                               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │  ECS Credential Server                                         │    │
│  │  • Bearer token authentication (timing-safe comparison)        │    │
│  │  • Rate limiting (in-memory sliding window)                    │    │
│  │  • Unix socket mode with process authentication               │    │
│  │  • ECS task metadata proxy                                     │    │
│  └────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Trust Boundaries

| Boundary | Trust Model | Controls |
|----------|-------------|----------|
| **Internet → Lambda TVM** | Zero trust - all requests authenticated | API Gateway IAM authorization, rate limiting, KMS-signed policies |
| **User Workstation → Sentinel CLI** | User controls local system | Keyring ACLs, process authentication for Unix sockets, no iCloud sync |
| **CLI → AWS STS** | AWS STS trusted for identity verification | TLS, AWS SigV4, STS GetCallerIdentity for username extraction |
| **Application → DynamoDB/SSM** | AWS service trust with encryption | DynamoDB KMS encryption at rest, SSM parameter encryption, IAM policies |
| **Policy Author → SSM** | KMS signing key controls write access | KMS asymmetric signing (kms:Sign), separate from SSM write permissions |
| **Lambda → MDM Provider** | MDM API trusted for device posture | API token in Secrets Manager, TLS, fail-closed on MDM errors |
| **Container → ECS Server** | Bearer token or process-based auth | Timing-safe token comparison, Unix socket process credential extraction |

### 1.3 Key Assets and Sensitivity

| Asset | Sensitivity | Why It Matters |
|-------|-------------|----------------|
| **AWS STS Credentials** | CRITICAL | Full AWS access within IAM role permissions |
| **Bearer Tokens** (ECS/Sentinel server) | HIGH | Session hijacking enables credential theft |
| **Policy Files** (SSM) | HIGH | Policy bypass grants unauthorized access |
| **KMS Signing Key** | HIGH | Policy integrity depends on signing key |
| **DynamoDB Records** | MEDIUM | Approval/break-glass state can be manipulated |
| **Keychain Credentials** | CRITICAL | Long-lived SSO credentials |
| **MDM API Tokens** | MEDIUM | Device posture bypass if compromised |
| **Audit Logs** | MEDIUM | Tampering enables evidence destruction |
| **Session State** | MEDIUM | Session state manipulation for bypass |

### 1.4 Data Flow Diagram

**Standard Credential Issuance Flow:**

```
1. User → Sentinel CLI: sentinel exec --profile prod -- aws s3 ls
2. CLI → AWS STS: GetCallerIdentity() [extract IAM username]
3. CLI → SSM: GetParameter(/sentinel/policies/default + /sentinel/signatures/default)
4. CLI → KMS: Verify(policy signature) [RSASSA_PSS_SHA_256]
5. CLI → Policy Engine: Evaluate(user=alice, profile=prod, time=now)
6. Policy Engine → CLI: Effect=allow, Reason="Production access"
7. CLI → Device ID: HMAC-SHA256(IOPlatformUUID, "sentinel-device-v1")
8. CLI → AWS STS: AssumeRole(role=prod, SourceIdentity=sentinel:alice:direct:a1b2c3d4)
9. AWS STS → CLI: Credentials (AccessKey, SecretKey, SessionToken, Expiration)
10. CLI → Keychain: Store credentials with ACLs
11. CLI: Export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
12. CLI: exec("aws", "s3", "ls")
```

**Lambda TVM Flow (Server-Side):**

```
1. Client → API Gateway: GET /credentials?profile=prod (IAM auth via SigV4)
2. API Gateway → Lambda: APIGatewayV2HTTPRequest with IAM context
3. Lambda → Authorizer: ExtractCallerIdentity(req)
4. Lambda → Rate Limiter: Allow(userARN) [DynamoDB atomic counters]
5. Lambda → Input Validator: ValidateProfileName(profile)
6. Lambda → MDM Provider: QueryDevice(deviceID) [Jamf Pro API]
7. MDM → Lambda: {enrolled: true, compliant: true, encrypted: true}
8. Lambda → SSM: GetParameter(/sentinel/policies/X + /sentinel/signatures/X)
9. Lambda → KMS: Verify(policy, signature)
10. Lambda → Policy Engine: Evaluate(user, profile, device_posture, time)
11. Policy Engine: require_approval → Query DynamoDB approvals table
12. Policy Engine → Lambda: Effect=allow
13. Lambda → Break-Glass Policy: MFA verification (if required)
14. Lambda → TOTP/SMS: Verify(code)
15. Lambda → AWS STS: AssumeRole(role, SourceIdentity=sentinel:alice:abcd1234:xyz)
16. Lambda → Session Store: CreateSession(deviceID, profile) [DynamoDB]
17. Lambda → Audit Logger: LogDecision(effect, user, profile, device_posture) [HMAC-signed]
18. Lambda → CloudWatch: ForwardLog(signed_entry)
19. Lambda → Client: {AccessKeyId, SecretAccessKey, Token, Expiration}
```

---

## 2. STRIDE Analysis by Category

### 2.1 Spoofing (Identity Verification)

**Threat S-01: OS Username Spoofing (FIXED - v1.7.1)**

- **Description:** Attacker runs Sentinel as a different local user to bypass user-based policy restrictions.
- **Affected Asset:** Policy evaluation username
- **Attack Vector:** `sudo -u victim sentinel credentials --profile prod`
- **Impact:** CRITICAL - Complete policy bypass, unauthorized credential access
- **Likelihood:** LOW (post-fix)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.7.1 replaced `os/user.Current()` with `identity.GetAWSUsername()` (STS GetCallerIdentity)
  - ✅ Username extracted from AWS-authenticated ARN, not OS user
  - ✅ Covers all commands: credentials, exec, breakglass, approve, request
- **Verification:** `sentinel whoami` shows AWS identity, not OS username
- **Residual Risk:** None - AWS STS is authoritative source

---

**Threat S-02: IAM Identity Spoofing (Lambda TVM)**

- **Description:** Attacker bypasses API Gateway IAM authorization to impersonate another user.
- **Affected Asset:** Lambda TVM caller identity
- **Attack Vector:** Craft malicious API Gateway request with forged IAM context
- **Impact:** CRITICAL - Credential vending as arbitrary user
- **Likelihood:** VERY LOW
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ API Gateway v2 HTTP API with IAM authorization (AWS-managed)
  - ✅ CallerIdentity extracted from `req.RequestContext.Authorizer.IAM`
  - ✅ AWS SigV4 request signing required
  - ✅ No custom authorization code (AWS controls IAM auth)
- **Gaps:**
  - ⚠️ No validation that IAM context matches request signature (AWS responsibility)
- **Recommendation:** Trust AWS API Gateway IAM authorizer (industry standard)

---

**Threat S-03: SourceIdentity Spoofing**

- **Description:** User directly calls STS AssumeRole with spoofed `sentinel:*` SourceIdentity.
- **Affected Asset:** SourceIdentity in CloudTrail
- **Attack Vector:** `aws sts assume-role --role-arn X --source-identity sentinel:admin:direct:fake`
- **Impact:** MEDIUM - CloudTrail audit trail pollution
- **Likelihood:** HIGH (if user has direct IAM credentials)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ Trust policies can require Sentinel-specific SourceIdentity patterns
  - ✅ SCPs can deny AssumeRole without Sentinel SourceIdentity
  - ✅ Enforcement documented in ENFORCEMENT.md
- **Gaps:**
  - ❌ Enforcement is optional (opt-in via trust policies/SCPs)
  - ❌ Users with IAM access keys can bypass Sentinel entirely
- **Recommendation:**
  - Deploy SCP: `Deny sts:AssumeRole where sts:SourceIdentity NOT LIKE sentinel:*`
  - Revoke IAM user access keys, require SSO
  - Document enforcement levels (advisory → trust policy → SCP)

---

**Threat S-04: Device ID Spoofing**

- **Description:** Attacker computes valid device ID for a different managed device to bypass device posture checks.
- **Affected Asset:** Device ID in MDM lookup
- **Attack Vector:**
  1. Obtain IOPlatformUUID of victim's device
  2. Compute `HMAC-SHA256(victimUUID, "sentinel-device-v1")`
  3. Submit credentials request with spoofed device ID
- **Impact:** MEDIUM - Bypass device posture requirements (MDM enrollment, encryption)
- **Likelihood:** LOW (requires knowledge of victim's machine UUID)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Device ID is HMAC-SHA256 hash (not reversible to find source UUID)
  - ✅ MDM enrollment is real security boundary (spoofed ID must still map to enrolled device)
  - ✅ MDM lookup returns actual device posture (can't spoof compliance status)
  - ✅ Fail-closed on MDM errors
- **Gaps:**
  - ⚠️ HMAC key is public ("sentinel-device-v1") - not cryptographically secure binding
  - ⚠️ If attacker knows victim UUID, can request credentials as victim's device
- **Recommendation:**
  - Device binding prevents cross-device session use (session revocation)
  - MDM compliance check is authoritative (spoofed ID doesn't grant compliance)
  - Consider adding nonce to device ID computation for request-specific binding

---

**Threat S-05: Bearer Token Spoofing (Credential Servers)**

- **Description:** Attacker forges bearer token to authenticate to ECS/Sentinel credential server.
- **Affected Asset:** Bearer token authentication
- **Attack Vector:** Guess or brute-force bearer token value
- **Impact:** HIGH - Unauthorized credential access from server
- **Likelihood:** VERY LOW (cryptographically random tokens)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.16 Phase 113: Timing-safe token comparison (`crypto/subtle.ConstantTimeCompare`)
  - ✅ Tokens are 32-byte random values (256 bits entropy)
  - ✅ AST verification tests ensure timing-safe comparison is used
- **Gaps:**
  - ⚠️ Token transmitted via `Authorization: Bearer` header (sniffable on local network if not HTTPS)
  - ⚠️ Unix socket mode available but not enforced
- **Recommendation:**
  - Enforce Unix socket mode with process authentication for local servers
  - Document network bearer tokens only for container/ECS scenarios with TLS

---

### 2.2 Tampering (Data Integrity)

**Threat T-01: Policy Cache Poisoning (FIXED - v1.18)**

- **Description:** Attacker with SSM write access modifies policy to grant unauthorized permissions.
- **Affected Asset:** Policy files in SSM Parameter Store
- **Attack Vector:**
  1. Compromise IAM credentials with `ssm:PutParameter`
  2. Modify `/sentinel/policies/production` to add permissive rule
  3. Lambda TVM loads poisoned policy from SSM
- **Impact:** CRITICAL - Complete policy bypass, privilege escalation
- **Likelihood:** MEDIUM (requires IAM credential compromise)
- **Risk Score:** HIGH
- **Current Mitigation:**
  - ✅ v1.18 Phase 126: KMS-based policy signing (RSASSA_PSS_SHA_256)
  - ✅ VerifyingLoader enforces signature verification before policy use
  - ✅ Fail-closed: unsigned/invalid signature = credentials denied
  - ✅ Signing requires separate `kms:Sign` permission (defense in depth)
  - ✅ Lambda TVM: SSM → VerifyingLoader → CachedLoader pipeline
- **Verification:**
  - `sentinel policy verify policy.yaml --key-id alias/sentinel-policy-signing -s policy.sig`
  - Lambda logs: "Policy signature verification enabled"
- **Residual Risk:** VERY LOW - requires compromise of both SSM write AND KMS signing key

---

**Threat T-02: DynamoDB State Manipulation (FIXED - v1.18)**

- **Description:** Attacker modifies DynamoDB approval/break-glass/session records to bypass controls.
- **Affected Asset:** DynamoDB tables (approvals, break-glass events, sessions)
- **Attack Vector:**
  1. Compromise IAM credentials with DynamoDB write access
  2. Modify approval record: `status: pending → approved`
  3. Policy engine uses tampered state to grant credentials
- **Impact:** HIGH - Approval workflow bypass, session hijacking
- **Likelihood:** MEDIUM (requires DynamoDB write access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 131: Optimistic locking with `updated_at` version field
  - ✅ State transition validation (`ValidTransition()` method)
  - ✅ Conditional writes prevent concurrent modification races
  - ✅ v1.16 Phase 116: DynamoDB KMS encryption at rest
- **Gaps:**
  - ⚠️ IAM with DynamoDB write can still modify records (encryption doesn't prevent authorized writes)
  - ⚠️ No cryptographic integrity (HMAC) on DynamoDB items themselves
- **Recommendation:**
  - Restrict DynamoDB write access to Lambda execution role only
  - Audit DynamoDB writes via CloudTrail
  - Consider item-level HMAC for approval/break-glass critical state

---

**Threat T-03: Audit Log Tampering (FIXED - v1.18)**

- **Description:** Attacker modifies or deletes local audit logs to hide unauthorized access.
- **Affected Asset:** Sentinel decision logs (`/var/log/sentinel/decisions.log`)
- **Attack Vector:**
  1. Gain root/admin access to workstation
  2. Edit or delete `/var/log/sentinel/decisions.log`
  3. Remove evidence of policy denials or suspicious access patterns
- **Impact:** MEDIUM - Evidence destruction, compliance violation
- **Likelihood:** MEDIUM (requires local admin access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 128: HMAC-SHA256 signed audit logs
  - ✅ CloudWatch Logs forwarding for tamper-evident storage
  - ✅ `sentinel audit verify-logs` command validates HMAC signatures
  - ✅ Fail-open on CloudWatch errors (availability preferred)
  - ✅ Minimum 32-byte HMAC key length enforced
- **Verification:**
  - `sentinel audit verify-logs --log-file /var/log/sentinel/decisions.log --hmac-key-file key.txt`
- **Gaps:**
  - ⚠️ Local logs still deletable (HMAC prevents modification, not deletion)
  - ⚠️ CloudWatch forwarding is fail-open (errors don't block credentials)
- **Recommendation:**
  - Ship logs to centralized SIEM immediately
  - Alert on log deletion or HMAC verification failures
  - Enforce immutable log retention in CloudWatch

---

**Threat T-04: Keychain/Keyring Credential Tampering**

- **Description:** Attacker modifies stored credentials in macOS Keychain or Linux keyring.
- **Affected Asset:** Cached STS credentials, SSO tokens
- **Attack Vector:**
  1. Gain access to keychain (malware, physical access)
  2. Modify credential expiration time to extend validity
  3. Use expired-but-modified credentials
- **Impact:** MEDIUM - Credential lifetime extension
- **Likelihood:** LOW (keychain protections)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.18 Phase 132: Keychain security hardening
  - ✅ macOS: `KeychainAccessibleWhenUnlocked: false`, `KeychainSynchronizable: false`
  - ✅ Linux: Possessor-only permissions (0x3f000000)
  - ✅ macOS: `KeychainNotTrustApplication: true` (requires user consent)
- **Gaps:**
  - ⚠️ Root/admin can still access keychain
  - ⚠️ Credential integrity not cryptographically protected (no HMAC)
- **Recommendation:**
  - Document: keychain access = full credential access (trust boundary)
  - Recommend short credential lifetimes (1 hour)
  - Consider secure enclave for credential storage (macOS T2/M1+)

---

**Threat T-05: Session Token Injection (Server Mode)**

- **Description:** Attacker injects crafted session token to hijack active server-mode session.
- **Affected Asset:** Server-mode bearer tokens
- **Attack Vector:**
  1. Intercept bearer token from server start (local network sniffing, process inspection)
  2. Use token to issue credential requests as victim
- **Impact:** HIGH - Session hijacking, credential theft
- **Likelihood:** MEDIUM (local network/process access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 129: Unix socket mode with process authentication
  - ✅ Process credentials (PID, UID) verified via SO_PEERCRED (Linux) or LOCAL_PEERCRED (macOS)
  - ✅ ProcessToken binds token to specific PID + UID
  - ✅ Token validation fails if caller PID/UID mismatch
- **Gaps:**
  - ⚠️ Network mode (HTTP over TCP) still vulnerable to token interception
  - ⚠️ Process authentication only available in Unix socket mode
- **Recommendation:**
  - Deprecate network mode for local servers
  - Require `--unix-socket` flag for server mode
  - Document: network mode only for containerized environments with mutual TLS

---

**Threat T-06: Break-Glass Event Manipulation**

- **Description:** Attacker modifies break-glass DynamoDB records to hide unauthorized emergency access.
- **Affected Asset:** Break-glass events table
- **Attack Vector:**
  1. Invoke break-glass: `sentinel breakglass --profile prod --justification "Emergency"`
  2. Compromise DynamoDB write access
  3. Delete break-glass event record
- **Impact:** HIGH - Evidence destruction for emergency access abuse
- **Likelihood:** LOW (requires DynamoDB write + break-glass use)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ Break-glass events logged to DynamoDB with timestamp, user, justification
  - ✅ SNS notifications for break-glass (real-time alerting)
  - ✅ v1.18 Phase 127: Break-glass MFA (secondary verification)
  - ✅ DynamoDB optimistic locking prevents concurrent modification
  - ✅ KMS encryption at rest
- **Gaps:**
  - ❌ No cryptographic integrity on break-glass records (deletable)
  - ❌ SNS notifications not cryptographically signed
- **Recommendation:**
  - Forward break-glass events to immutable log store (CloudWatch, S3 with object lock)
  - Implement item-level HMAC for break-glass records
  - Alert on DynamoDB record deletions (CloudTrail)

---

### 2.3 Repudiation (Non-Repudiation)

**Threat R-01: Policy Decision Repudiation**

- **Description:** User denies making credential request after unauthorized access is discovered.
- **Affected Asset:** Decision logs, CloudTrail
- **Attack Vector:**
  - "I never requested those production credentials"
  - "My account was compromised, not me"
- **Impact:** MEDIUM - Accountability gap, compliance violation
- **Likelihood:** MEDIUM
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 128: HMAC-signed audit logs (tamper-evident)
  - ✅ SourceIdentity stamping in CloudTrail (immutable AWS record)
  - ✅ AWS STS GetCallerIdentity for authoritative username
  - ✅ Device ID binding in session records (forensic correlation)
  - ✅ CloudWatch Logs forwarding (centralized, AWS-managed)
- **Verification:**
  - Decision log: `{user: alice, profile: prod, effect: allow, timestamp, rule_matched, device_id}`
  - CloudTrail: `userIdentity.sourceIdentity: sentinel:alice:direct:xyz`
  - Correlation: Request ID in both logs
- **Gaps:**
  - ⚠️ MFA verification (TOTP/SMS) not logged in decision record
  - ⚠️ IP address not logged (privacy trade-off)
- **Recommendation:**
  - Log MFA verification result in decision records
  - Consider optional IP address logging for high-security environments
  - Implement approval audit trail with approver identity

---

**Threat R-02: Approval Workflow Repudiation**

- **Description:** Approver denies approving a request after compromise is discovered.
- **Affected Asset:** Approval records in DynamoDB
- **Attack Vector:**
  - "I never approved that production access request"
  - Approver account compromised, attacker approved malicious request
- **Impact:** MEDIUM - Accountability gap, approval workflow bypass
- **Likelihood:** LOW (requires approver credential compromise)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Approval records include: approver username (AWS STS identity), timestamp, request ID
  - ✅ Approver extracted via `identity.GetAWSUsername()` (not OS user)
  - ✅ DynamoDB state transition validation (pending → approved)
  - ✅ Approval ID in SourceIdentity (correlation to CloudTrail)
- **Gaps:**
  - ❌ No cryptographic signature from approver (HMAC, digital signature)
  - ❌ No MFA enforcement for approval action
- **Recommendation:**
  - Require MFA for approval action (not just credential issuance)
  - Implement approval signature: HMAC(approver_identity + request_id + timestamp, approver_secret)
  - Forward approval events to immutable audit log

---

**Threat R-03: Break-Glass Justification Repudiation**

- **Description:** User claims break-glass justification was altered after the fact.
- **Affected Asset:** Break-glass event records
- **Attack Vector:**
  - User: "I wrote 'Test', not 'Production incident #1234'"
  - Attacker modifies justification text in DynamoDB
- **Impact:** LOW - Justification integrity, compliance
- **Likelihood:** LOW (requires DynamoDB write access)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Break-glass events immutable once created (no Update operation)
  - ✅ DynamoDB optimistic locking
  - ✅ SNS notifications sent at creation time (external record)
- **Gaps:**
  - ⚠️ DynamoDB write access can still delete entire record
  - ❌ No cryptographic signature on justification text
- **Recommendation:**
  - Forward break-glass events to append-only log (S3 with object lock)
  - Implement HMAC signature on break-glass event: HMAC(user + justification + timestamp, secret)

---

### 2.4 Information Disclosure (Confidentiality)

**Threat I-01: Credential Exposure in Environment Variables**

- **Description:** AWS credentials exposed via environment variables (`AWS_ACCESS_KEY_ID`, etc.) visible to other processes.
- **Affected Asset:** STS credentials
- **Attack Vector:**
  1. `sentinel exec --profile prod -- long-running-app`
  2. Attacker reads `/proc/$PID/environ` (Linux) or process memory
  3. Extract credentials from environment
- **Impact:** CRITICAL - Full credential theft
- **Likelihood:** MEDIUM (requires local access)
- **Risk Score:** HIGH
- **Current Mitigation:**
  - ✅ Server mode (`--server`) uses credential server instead of environment variables
  - ✅ Credentials served over HTTPS/Unix socket, not exported to env
  - ✅ Policy engine can enforce `require_server` effect for sensitive profiles
- **Gaps:**
  - ❌ Standard `exec` mode exports to environment (documented behavior)
  - ❌ No process isolation for credentials
- **Recommendation:**
  - Document: Use `--server` mode for long-running processes
  - Enforce `require_server` policy effect for production profiles
  - Consider mandatory server mode with deprecation of env var export

---

**Threat I-02: Keychain Credential Exposure**

- **Description:** Malware or attacker extracts credentials from macOS Keychain or Linux keyring.
- **Affected Asset:** Cached STS credentials, SSO refresh tokens
- **Attack Vector:**
  1. Malware gains keychain access (user consent dialog, root access)
  2. Extract all Sentinel credentials
  3. Use credentials until expiration
- **Impact:** CRITICAL - Credential theft, persistent access
- **Likelihood:** MEDIUM (malware, physical access)
- **Risk Score:** HIGH
- **Current Mitigation:**
  - ✅ v1.18 Phase 132: Keychain hardening
  - ✅ macOS: Accessible only when unlocked, no iCloud sync, requires user approval
  - ✅ Linux: Possessor-only permissions
  - ✅ Short credential lifetimes (1-12 hours)
- **Gaps:**
  - ⚠️ Root/admin can bypass keychain protections
  - ⚠️ User approval for keychain access is one-time (not per-access)
  - ⚠️ No encryption of credential values beyond keychain default
- **Recommendation:**
  - Document: Keychain access = full credential compromise (trust boundary)
  - Recommend short credential lifetimes (1 hour)
  - Investigate macOS Secure Enclave for credential storage (hardware-backed)

---

**Threat I-03: Error Message Information Leakage (FIXED - v1.16)**

- **Description:** Detailed error messages leak internal system information to attackers.
- **Affected Asset:** Lambda TVM error responses
- **Attack Vector:**
  - Trigger error conditions, observe error messages
  - Extract SSM paths, ARN formats, MDM provider details
  - Use information for targeted attacks
- **Impact:** LOW - Information gathering for reconnaissance
- **Likelihood:** HIGH
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.16 Phase 119: Error sanitization across Lambda TVM, Sentinel server, ECS server
  - ✅ Pattern: Log detailed errors internally, return generic messages to clients
  - ✅ Sanitized: SSM paths, ARN parsing errors, MDM failures, credential retrieval errors
  - ✅ Preserved: Rate limit retry-after, policy deny reasons (intentional user-facing)
- **Verification:**
  - Lambda returns: "Failed to load configuration" (not "SSM parameter /sentinel/policies/X not found")
- **Residual Risk:** VERY LOW

---

**Threat I-04: MDM API Token Exposure (FIXED - v1.16)**

- **Description:** MDM API token exposed in environment variables or logs.
- **Affected Asset:** Jamf Pro API token
- **Attack Vector:**
  1. Lambda environment variables visible to IAM with `lambda:GetFunctionConfiguration`
  2. Extract MDM token
  3. Query MDM API for device inventory
- **Impact:** MEDIUM - Device inventory disclosure, MDM data access
- **Likelihood:** LOW (requires Lambda read access)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.16 Phase 114: MDM tokens migrated to AWS Secrets Manager
  - ✅ CachedSecretsLoader with 1-hour TTL (Lambda cold start optimization)
  - ✅ Backward-compatible env var fallback with deprecation warning
  - ✅ Lambda execution role requires `secretsmanager:GetSecretValue`
- **Gaps:**
  - ⚠️ Secrets Manager secrets readable by anyone with `secretsmanager:GetSecretValue`
  - ⚠️ Environment variable fallback still supported (deprecated)
- **Recommendation:**
  - Remove environment variable fallback in v2.0 (breaking change)
  - Restrict Secrets Manager access to Lambda execution role only
  - Rotate MDM tokens quarterly

---

**Threat I-05: CloudWatch Log Exposure**

- **Description:** Sensitive information leaked in CloudWatch Logs (usernames, profiles, device IDs).
- **Affected Asset:** CloudWatch Logs streams
- **Attack Vector:**
  1. Compromise IAM credentials with `logs:FilterLogEvents`
  2. Query logs for usernames, device IDs, access patterns
  3. Use for reconnaissance or privilege escalation planning
- **Impact:** MEDIUM - Privacy violation, reconnaissance
- **Likelihood:** MEDIUM (CloudWatch access common)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ Decision logs include user, profile, device_bound (not full device ID)
  - ✅ Verbose logging disabled by default
  - ✅ Error sanitization prevents internal details in logs
- **Gaps:**
  - ⚠️ Device IDs logged in session records (forensic requirement vs privacy)
  - ⚠️ No log encryption beyond CloudWatch default
  - ⚠️ No automatic PII redaction
- **Recommendation:**
  - Implement CloudWatch Logs encryption with KMS
  - Restrict log access via IAM policies
  - Consider PII redaction for device IDs (hash before logging)

---

**Threat I-06: Session Token Interception (Network Mode)**

- **Description:** Bearer token intercepted over unencrypted local network connection.
- **Affected Asset:** Credential server bearer tokens
- **Attack Vector:**
  1. `sentinel server --address :8080` (HTTP, not HTTPS)
  2. Local network sniffing (ARP poisoning, WiFi monitoring)
  3. Extract `Authorization: Bearer <token>` header
  4. Use token to request credentials
- **Impact:** HIGH - Session hijacking, credential theft
- **Likelihood:** LOW (requires local network access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 129: Unix socket mode with process authentication
  - ✅ Process credentials (PID/UID) prevent cross-process token use
  - ✅ Timing-safe token comparison
- **Gaps:**
  - ❌ Network mode (HTTP over TCP) still vulnerable
  - ❌ No TLS enforcement for network mode
  - ❌ Unix socket mode not enforced by default
- **Recommendation:**
  - Deprecate network mode for local use (Unix socket only)
  - Require mutual TLS for network mode in containers
  - Document: Network mode only for ECS with proper network isolation

---

**Threat I-07: Policy Content Disclosure**

- **Description:** Attacker reads policy files to understand access control logic and find bypass opportunities.
- **Affected Asset:** Policy YAML in SSM
- **Attack Vector:**
  1. Gain `ssm:GetParameter` access
  2. Read `/sentinel/policies/production`
  3. Analyze rules to identify permissive patterns or loopholes
- **Impact:** LOW - Reconnaissance, policy analysis
- **Likelihood:** HIGH (SSM read access common)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Policy read access required for legitimate Sentinel use
  - ✅ Policy signing prevents tampering (disclosure is acceptable)
  - ✅ Defense in depth: policy + IAM + trust policies
- **Gaps:**
  - N/A - Policy disclosure is inherent to the system design
- **Recommendation:**
  - Accept: Policy confidentiality is not a security requirement
  - Focus on policy integrity (signing) and enforcement (IAM, SCPs)

---

### 2.5 Denial of Service (Availability)

**Threat D-01: Rate Limit Bypass (Lambda TVM) (FIXED - v1.18)**

- **Description:** Attacker bypasses rate limiting to overwhelm Lambda TVM with credential requests.
- **Affected Asset:** Lambda TVM, KMS, MDM API
- **Attack Vector:**
  1. Distribute requests across multiple Lambda instances
  2. Bypass in-memory rate limiter (each Lambda has separate state)
  3. Exhaust KMS API quota, MDM API quota
- **Impact:** MEDIUM - Service degradation, cost increase
- **Likelihood:** MEDIUM (Lambda auto-scaling)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ v1.18 Phase 133: DynamoDB distributed rate limiter
  - ✅ Atomic UpdateItem operations for rate limit counters
  - ✅ Rate limit by IAM ARN (per-user, not per-IP)
  - ✅ Default: 100 requests per 60 seconds
  - ✅ Fail-open on DynamoDB errors (availability preferred)
  - ✅ RFC 7231 compliant Retry-After header
- **Verification:**
  - Lambda logs: "RATE_LIMITED: user=alice retry_after=45s"
- **Gaps:**
  - ⚠️ Fail-open policy allows bypass if DynamoDB unavailable
  - ⚠️ No cascading rate limit (global across all users)
- **Recommendation:**
  - Monitor DynamoDB rate limit table for anomalies
  - Implement API Gateway throttling (backup rate limit)
  - Consider fail-closed for critical production deployments

---

**Threat D-02: Break-Glass Rate Limit Abuse**

- **Description:** Attacker repeatedly invokes break-glass to exhaust rate limits or flood notifications.
- **Affected Asset:** Break-glass SNS notifications, rate limiter
- **Attack Vector:**
  1. `sentinel breakglass --profile prod --justification "test"`
  2. Repeat 100 times to trigger rate limit
  3. SNS notification flood
- **Impact:** MEDIUM - Alert fatigue, rate limit exhaustion
- **Likelihood:** LOW (break-glass MFA required in v1.18)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.18 Phase 127: Break-glass MFA (TOTP/SMS secondary verification)
  - ✅ Rate limiting on break-glass invocation (policy configurable)
  - ✅ SNS notification throttling (AWS-managed)
- **Gaps:**
  - ⚠️ No CAPTCHA or similar bot protection
  - ⚠️ MFA code can be automated (TOTP is deterministic)
- **Recommendation:**
  - Log break-glass failures for anomaly detection
  - Implement exponential backoff for repeated failures
  - Consider hardware token requirement for break-glass (U2F, WebAuthn)

---

**Threat D-03: DynamoDB Table Deletion**

- **Description:** Attacker with DynamoDB admin access deletes approval/session/break-glass tables.
- **Affected Asset:** DynamoDB tables
- **Attack Vector:**
  1. Compromise IAM with `dynamodb:DeleteTable`
  2. Delete `sentinel-approvals`, `sentinel-sessions`, `sentinel-breakglass`
  3. Approval workflow, session tracking, break-glass logging all fail
- **Impact:** HIGH - Service outage, audit trail loss
- **Likelihood:** LOW (requires DynamoDB admin access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ IAM least privilege (Lambda execution role has no DeleteTable)
  - ✅ Terraform/CloudFormation resource protection
- **Gaps:**
  - ❌ No DynamoDB deletion protection enabled by default
  - ❌ No automated table backup
- **Recommendation:**
  - Enable DynamoDB deletion protection (`deletion_protection_enabled: true`)
  - Configure point-in-time recovery (PITR)
  - Monitor CloudTrail for DeleteTable API calls
  - Implement SCP to deny DeleteTable on Sentinel tables

---

**Threat D-04: SSM Parameter Deletion**

- **Description:** Attacker deletes policy or signature parameters to cause credential denial.
- **Affected Asset:** SSM Parameter Store
- **Attack Vector:**
  1. Compromise IAM with `ssm:DeleteParameter`
  2. Delete `/sentinel/policies/production`
  3. Lambda TVM fails to load policy, denies all requests
- **Impact:** HIGH - Service outage for affected profiles
- **Likelihood:** LOW (requires SSM admin access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ IAM least privilege (Lambda has GetParameter only)
  - ✅ Policy caching reduces SSM dependency
- **Gaps:**
  - ❌ No SSM parameter versioning enabled by default
  - ❌ No parameter deletion protection
- **Recommendation:**
  - Enable SSM parameter versioning (rollback capability)
  - Monitor CloudTrail for DeleteParameter API calls
  - Implement backup/restore for critical parameters
  - SCP to deny DeleteParameter on `/sentinel/*` parameters

---

**Threat D-05: KMS Key Deletion/Disablement**

- **Description:** Attacker disables or schedules deletion of KMS signing key.
- **Affected Asset:** KMS signing key
- **Attack Vector:**
  1. Compromise IAM with `kms:DisableKey` or `kms:ScheduleKeyDeletion`
  2. Disable policy signing key
  3. Lambda TVM signature verification fails, denies all credentials
- **Impact:** CRITICAL - Complete service outage (policy signing required)
- **Likelihood:** VERY LOW (requires KMS admin access)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ IAM least privilege (Lambda has kms:Verify only)
  - ✅ KMS key policy separate from IAM
  - ✅ AWS enforces 7-30 day waiting period for key deletion
- **Gaps:**
  - ❌ No KMS key backup (asymmetric keys cannot be exported)
  - ❌ DisableKey takes immediate effect
- **Recommendation:**
  - Enable CloudTrail alerting for KMS key state changes
  - Implement SCP to deny KMS key deletion/disable for critical keys
  - Document disaster recovery: create new key, re-sign all policies
  - Maintain offline record of key ARN for recovery

---

**Threat D-06: MDM API Quota Exhaustion**

- **Description:** Attacker exhausts MDM API quota to prevent device posture verification.
- **Affected Asset:** Jamf Pro API rate limits
- **Attack Vector:**
  1. Issue many credential requests with different device IDs
  2. Each request triggers MDM API lookup
  3. Exhaust Jamf Pro API quota (60 req/min typical)
  4. Legitimate requests fail device verification
- **Impact:** MEDIUM - Service degradation for device-bound profiles
- **Likelihood:** LOW (rate limiting protects)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.16 Phase 114: MDM result caching (5-minute TTL default)
  - ✅ Lambda rate limiting (100 req/min per user)
  - ✅ Fail-open MDM policy configurable (availability vs security trade-off)
- **Gaps:**
  - ⚠️ Cache is per-Lambda instance (no global cache)
  - ⚠️ Device ID uniqueness not validated (can generate fake IDs)
- **Recommendation:**
  - Increase MDM cache TTL (15 minutes) for high-traffic environments
  - Implement API Gateway throttling (defense in depth)
  - Monitor MDM API usage for anomalies

---

### 2.6 Elevation of Privilege (Authorization)

**Threat E-01: Policy Rule Order Bypass**

- **Description:** Attacker exploits policy evaluation order to match permissive rule before restrictive deny.
- **Affected Asset:** Policy evaluation engine
- **Attack Vector:**
  1. Policy has: Rule 1 (allow, profiles: [prod]), Rule 2 (deny, profiles: [prod], time: business hours)
  2. Request outside business hours
  3. Matches Rule 1 (allow) before Rule 2 (deny)
  4. Credentials granted outside allowed time
- **Impact:** HIGH - Time-based access control bypass
- **Likelihood:** MEDIUM (policy misconfiguration)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ Policy evaluation: first matching rule wins (documented behavior)
  - ✅ `sentinel config validate` checks for rule conflicts
  - ✅ Policy signing prevents post-deploy tampering
- **Gaps:**
  - ❌ No automatic rule ordering or conflict detection
  - ❌ Deny rules not automatically prioritized
- **Recommendation:**
  - Document best practice: Specific rules first, general rules last
  - Implement policy linter: warn on allow-then-deny for same profile
  - Consider explicit rule priority field in policy schema

---

**Threat E-02: Approval Workflow Bypass (Session Reuse)**

- **Description:** User obtains approved credentials, then reuses keychain-cached credentials without approval.
- **Affected Asset:** Cached credentials in keychain
- **Attack Vector:**
  1. User requests access: `require_approval` policy → approval granted
  2. Credentials cached in keychain
  3. User requests again: keychain returns cached credentials (no new approval)
  4. Bypass approval requirement
- **Impact:** MEDIUM - Approval workflow bypass for cached credentials
- **Likelihood:** HIGH (credential caching is default)
- **Risk Score:** MEDIUM
- **Current Mitigation:**
  - ✅ Credential expiration (max 12 hours)
  - ✅ Server mode (`require_server` policy effect) re-evaluates policy per request
  - ✅ Session revocation capability
- **Gaps:**
  - ❌ Standard mode caches credentials until expiration
  - ❌ No approval timeout enforcement (approved credentials valid until STS expiration)
- **Recommendation:**
  - Document: Use `require_server` effect for approval-based profiles
  - Implement approval-specific expiration (shorter than STS session)
  - Consider approval-to-credential binding (approval ID in cached credential metadata)

---

**Threat E-03: Break-Glass Policy Bypass (No MFA)**

- **Description:** Attacker uses break-glass to bypass all policy restrictions without secondary verification.
- **Affected Asset:** Break-glass bypass mechanism
- **Attack Vector:**
  1. `sentinel breakglass --profile prod --justification "Emergency"`
  2. No MFA required (before v1.18)
  3. Credentials granted, bypassing time restrictions, approval requirements
- **Impact:** HIGH - Complete policy bypass
- **Likelihood:** LOW (post-v1.18 MFA enforcement)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.18 Phase 127: Break-glass MFA enforcement
  - ✅ TOTP or SMS verification required
  - ✅ MFA requirements in break-glass policy rules
  - ✅ SNS notifications for all break-glass events
  - ✅ Rate limiting on break-glass invocation
- **Verification:**
  - Policy: `mfa: {type: totp, secret_env: BREAKGLASS_TOTP_SECRET}`
  - Logs: "Break-glass MFA verification succeeded"
- **Residual Risk:** VERY LOW

---

**Threat E-04: Cross-Account Privilege Escalation**

- **Description:** User in Account A obtains credentials for privileged role in Account B.
- **Affected Asset:** Cross-account IAM trust relationships
- **Attack Vector:**
  1. User has access to low-privilege role in Account A
  2. Account B has role with trust policy: `Principal: arn:aws:iam::AccountA:root`
  3. Sentinel policy allows cross-account profile
  4. User escalates from AccountA read-only to AccountB admin
- **Impact:** CRITICAL - Cross-account privilege escalation
- **Likelihood:** MEDIUM (misconfigured trust policies)
- **Risk Score:** HIGH
- **Current Mitigation:**
  - ✅ Sentinel policy can restrict profiles per user
  - ✅ IAM trust policies require explicit cross-account configuration
  - ✅ SourceIdentity propagates across account boundaries (audit trail)
- **Gaps:**
  - ❌ Sentinel doesn't validate IAM trust policy constraints
  - ❌ No cross-account policy enforcement in Sentinel
  - ❌ Trust policies can allow overly broad principals (`root`)
- **Recommendation:**
  - Document: Cross-account access requires defense-in-depth (Sentinel policy + IAM trust + SCP)
  - Implement trust policy linter: warn on `Principal: root` patterns
  - Require `sts:SourceIdentity` condition in all cross-account trust policies
  - Use `sts:ExternalId` for additional cross-account protection

---

**Threat E-05: IAM Permission Boundary Bypass**

- **Description:** Sentinel-issued credentials bypass IAM permission boundaries.
- **Affected Asset:** IAM permission boundaries
- **Attack Vector:**
  1. User has IAM user with permission boundary: `Deny s3:DeleteBucket`
  2. Sentinel issues STS credentials for role without permission boundary
  3. User deletes S3 buckets with STS credentials
- **Impact:** HIGH - Permission boundary bypass
- **Likelihood:** LOW (permission boundaries apply to roles too)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Permission boundaries apply to IAM roles (not just users)
  - ✅ STS AssumeRole respects role permission boundary
  - ✅ Sentinel doesn't modify IAM permissions
- **Gaps:**
  - ❌ Sentinel doesn't enforce permission boundaries (AWS IAM responsibility)
  - ❌ No validation that target roles have appropriate boundaries
- **Recommendation:**
  - Document: Permission boundaries are IAM concern, not Sentinel
  - Recommend: Apply permission boundaries to all assumable roles
  - Consider policy validation: warn if target role lacks permission boundary

---

**Threat E-06: Device Posture Bypass (MDM Unenrollment)**

- **Description:** User unenrolls device from MDM after obtaining credentials to bypass future posture checks.
- **Affected Asset:** MDM enrollment status
- **Attack Vector:**
  1. Device enrolled, passes MDM posture check
  2. Credentials issued with 12-hour expiration
  3. User unenrolls device from MDM
  4. Credentials still valid for remaining session duration
- **Impact:** MEDIUM - Device posture bypass for credential lifetime
- **Likelihood:** LOW (unenrollment is auditable)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Credential expiration (max 12 hours)
  - ✅ Server mode re-checks policy (can include MDM lookup) per request
  - ✅ Session binding to device ID (revocation on enrollment change)
- **Gaps:**
  - ❌ Standard mode doesn't re-verify posture until credential expiration
  - ❌ No real-time MDM enrollment change notification
- **Recommendation:**
  - Document: Use `require_server` for device-posture-protected profiles
  - Implement MDM webhook: trigger session revocation on unenrollment
  - Recommend shorter credential lifetimes for device-bound access (1 hour)

---

**Threat E-07: Command Injection via Profile Name**

- **Description:** Attacker injects shell commands via malicious profile name.
- **Affected Asset:** Profile parameter input
- **Attack Vector:**
  1. Request: `GET /credentials?profile=prod; rm -rf /`
  2. Profile name used in shell command construction (if vulnerable)
  3. Command injection
- **Impact:** CRITICAL - Remote code execution
- **Likelihood:** VERY LOW (post-v1.18 input validation)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ v1.18 Phase 134: Input sanitization for all user inputs
  - ✅ ValidateProfileName: alphanumeric, hyphen, underscore, forward slash, colon only
  - ✅ ASCII-only enforcement (prevents homoglyph attacks)
  - ✅ Path traversal pattern rejection (.., //, etc.)
  - ✅ Max length: 256 characters
  - ✅ Applied BEFORE any use of profile value
- **Verification:**
  - Profile `prod; rm -rf /` → "Invalid profile name format"
  - Profile `../../etc/passwd` → "Invalid profile name format"
- **Residual Risk:** VERY LOW

---

**Threat E-08: Session Hijacking via SessionID Prediction**

- **Description:** Attacker predicts session ID to hijack active server-mode session.
- **Affected Asset:** Server-mode session IDs
- **Attack Vector:**
  1. Observe session ID pattern: `sess-abc123def456`
  2. Guess next session ID: `sess-abc123def457`
  3. Revoke victim's session using guessed ID
- **Impact:** MEDIUM - Session disruption, denial of service
- **Likelihood:** VERY LOW (cryptographically random session IDs)
- **Risk Score:** LOW
- **Current Mitigation:**
  - ✅ Session IDs are cryptographically random (not sequential)
  - ✅ Session revocation requires authentication (not just session ID knowledge)
- **Gaps:**
  - ⚠️ Session ID format not documented (could aid prediction if format leaks)
- **Recommendation:**
  - Use UUID v4 or similar for session IDs (128 bits entropy)
  - Document session ID format for security review

---

## 3. Trust Boundary Analysis

### 3.1 Internet → Lambda TVM Boundary

**Assets Crossing Boundary:**
- IAM-signed requests (AWS SigV4)
- Profile name (query parameter)
- Session duration (query parameter)
- Device ID (custom header)

**Threats:**
- IAM credential compromise → unauthorized credential requests
- Request forgery → policy bypass attempts
- Input injection → command injection, path traversal

**Controls:**
- ✅ API Gateway v2 HTTP API with IAM authorizer (AWS-managed)
- ✅ Input validation (`ValidateProfileName`)
- ✅ Rate limiting (DynamoDB distributed limiter)
- ✅ Error sanitization (generic error messages)
- ✅ Fail-closed policy signature verification

**Gaps:**
- ⚠️ No DDoS protection beyond rate limiting (consider AWS WAF, Shield)
- ⚠️ No IP-based access control (IAM only)

**Recommendations:**
- Deploy AWS WAF with rate-based rules
- Implement API Gateway resource policies for IP restrictions (if needed)
- Monitor CloudWatch metrics for anomalies

---

### 3.2 User Workstation → Sentinel CLI Boundary

**Assets Crossing Boundary:**
- Policy files (SSM → CLI)
- Credentials (AWS STS → Keychain)
- User input (command line arguments)

**Threats:**
- Local malware → credential theft from keychain
- Process inspection → bearer token extraction
- Credential export → environment variable exposure

**Controls:**
- ✅ Keychain ACLs (macOS: no iCloud sync, requires unlock, application approval)
- ✅ Linux keyring permissions (possessor-only)
- ✅ Unix socket mode with process authentication
- ✅ Short credential lifetimes (1-12 hours)

**Gaps:**
- ❌ Root/admin can bypass keychain protections
- ❌ Environment variable export in standard mode (proc filesystem visible)
- ❌ No malware detection integration

**Recommendations:**
- Document: Local admin access = full credential compromise (trust boundary)
- Enforce server mode for production profiles (`require_server` policy effect)
- Integrate with EDR/AV for malware detection

---

### 3.3 CLI → AWS STS Boundary

**Assets Crossing Boundary:**
- AssumeRole requests (with SourceIdentity)
- GetCallerIdentity requests (for username extraction)

**Threats:**
- STS API compromise → credential interception (AWS responsibility)
- SourceIdentity spoofing → audit trail pollution

**Controls:**
- ✅ TLS for all AWS API calls
- ✅ AWS SigV4 request signing
- ✅ SourceIdentity validated by trust policies (defense in depth)

**Gaps:**
- N/A - STS security is AWS responsibility

**Recommendations:**
- Trust AWS STS (industry standard)
- Enforce trust policy SourceIdentity requirements (defense in depth)

---

### 3.4 Application → DynamoDB/SSM Boundary

**Assets Crossing Boundary:**
- Policy files (SSM Parameter Store)
- Approval records, break-glass events, sessions (DynamoDB)

**Threats:**
- IAM credential compromise → state tampering
- Parameter deletion → service outage
- State manipulation → approval bypass

**Controls:**
- ✅ KMS encryption at rest (DynamoDB, SSM)
- ✅ IAM least privilege (Lambda has read-only SSM, read-write DynamoDB for specific tables)
- ✅ DynamoDB optimistic locking
- ✅ Policy signing (KMS-based integrity)

**Gaps:**
- ❌ No parameter/item-level HMAC for integrity
- ❌ No deletion protection enabled by default

**Recommendations:**
- Enable DynamoDB deletion protection
- Implement item-level HMAC for critical state (approvals, break-glass)
- Enable SSM parameter versioning

---

### 3.5 Policy Author → SSM Parameter Store Boundary

**Assets Crossing Boundary:**
- Policy YAML files
- KMS signatures

**Threats:**
- Malicious policy injection → privilege escalation
- Unsigned policy upload → policy tampering

**Controls:**
- ✅ KMS signing key separation (kms:Sign permission separate from SSM write)
- ✅ VerifyingLoader enforces signature verification
- ✅ Fail-closed enforcement (unsigned policies rejected)

**Gaps:**
- ⚠️ Signature enforcement optional (can be disabled for migration)
- ⚠️ No policy version rollback by default

**Recommendations:**
- Enforce signature verification in production (SENTINEL_ENFORCE_POLICY_SIGNING=true)
- Enable SSM parameter versioning for rollback capability
- Implement CI/CD approval gates for policy changes

---

## 4. Attack Scenarios

### Scenario 1: Policy Cache Poisoning Attack

**Attacker Goal:** Gain unauthorized production access by modifying policy.

**Attack Steps:**
1. **Reconnaissance:** Identify SSM parameter path (`/sentinel/policies/production`)
2. **Credential Compromise:** Phish developer with SSM write access
3. **Policy Tampering:** Modify policy to add permissive rule:
   ```yaml
   - name: backdoor
     users: [attacker]
     profiles: [production]
     effect: allow
   ```
4. **Cache Poisoning:** Wait for Lambda TVM to reload policy (cache expiration)
5. **Credential Request:** Request production credentials as `attacker`
6. **Access:** Use credentials for unauthorized production access

**Mitigations (v1.18):**
- ✅ **Policy Signing (Phase 126):** Unsigned policy rejected by VerifyingLoader
- ✅ **Fail-Closed Enforcement:** Invalid signature = credentials denied
- ✅ **KMS Separation:** Attacker needs both SSM write AND kms:Sign

**Result:** Attack FAILS - policy tampering detected, credentials denied.

**Remaining Risk:** If attacker compromises both SSM write AND KMS signing key → attack succeeds (VERY LOW likelihood).

---

### Scenario 2: Session Hijacking Attack (Local Network)

**Attacker Goal:** Steal active credentials from developer's server-mode session.

**Attack Steps:**
1. **Reconnaissance:** Developer runs `sentinel server --address :8080` (HTTP, not Unix socket)
2. **Network Position:** Attacker on same WiFi network (coffee shop, office)
3. **Traffic Sniffing:** ARP poisoning, capture HTTP traffic
4. **Token Extraction:** Extract `Authorization: Bearer 1234abcd...` from request
5. **Credential Request:** Use stolen bearer token to request credentials
6. **Access:** Obtain AWS credentials, access developer's profiles

**Mitigations (v1.18):**
- ✅ **Unix Socket Mode (Phase 129):** Process authentication prevents cross-process token use
- ✅ **Process Credentials:** Token bound to PID + UID
- ✅ **Timing-Safe Comparison:** Token comparison resistant to timing attacks

**Result (Network Mode):** Attack SUCCEEDS - bearer token valid until session ends.

**Result (Unix Socket Mode):** Attack FAILS - process credential mismatch.

**Remaining Risk:** Network mode still vulnerable to token interception (documented limitation).

**Recommendation:** Deprecate network mode for local use, enforce Unix socket mode.

---

### Scenario 3: Break-Glass Abuse

**Attacker Goal:** Use break-glass to bypass all policy restrictions for production access.

**Attack Steps:**
1. **Policy Review:** Identify break-glass enabled for production profile
2. **Invocation:** `sentinel breakglass --profile prod --justification "Testing"`
3. **Bypass:** Bypass time restrictions, approval requirements
4. **Access:** Obtain production credentials
5. **Cover Tracks:** Delete break-glass event from DynamoDB (if possible)

**Mitigations (v1.18):**
- ✅ **MFA Enforcement (Phase 127):** TOTP/SMS verification required
- ✅ **SNS Notifications:** Immediate alert on break-glass invocation
- ✅ **Rate Limiting:** Prevent repeated break-glass attempts
- ✅ **CloudWatch Forwarding:** Immutable audit log (tamper-evident)

**Result:** Attack FAILS - MFA verification required, alerts triggered.

**Remaining Risk:** If attacker has MFA access → attack succeeds but logged.

**Recommendation:** Monitor break-glass SNS notifications, investigate all break-glass events.

---

### Scenario 4: Cross-Account Privilege Escalation

**Attacker Goal:** Escalate from read-only Account A to admin Account B.

**Attack Steps:**
1. **Reconnaissance:** Account B has role with trust policy: `Principal: arn:aws:iam::AccountA:root`
2. **Policy Analysis:** Sentinel policy allows cross-account profile `accountb-admin`
3. **Credential Request:** `sentinel credentials --profile accountb-admin`
4. **Escalation:** AssumeRole succeeds (trust policy allows Account A root)
5. **Access:** Full admin access in Account B

**Mitigations:**
- ✅ **Sentinel Policy:** Can restrict cross-account profiles per user
- ✅ **SourceIdentity Propagation:** Cross-account access auditable in CloudTrail
- ⚠️ **Trust Policy:** Account B trust policy is overly permissive (`root`)

**Result:** Attack SUCCEEDS if Sentinel policy allows and trust policy is misconfigured.

**Recommendation:**
- Use specific IAM principals in trust policies (not `root`)
- Require `sts:SourceIdentity` condition in cross-account trust policies
- Implement cross-account access review process
- SCP to enforce SourceIdentity requirement

---

### Scenario 5: Supply Chain Attack (Dependency Compromise)

**Attacker Goal:** Inject malicious code via compromised Go dependency.

**Attack Steps:**
1. **Reconnaissance:** Identify Sentinel dependencies (go.mod)
2. **Compromise:** Compromise popular dependency (e.g., aws-sdk-go-v2)
3. **Backdoor Injection:** Inject credential exfiltration code
4. **Distribution:** Sentinel users pull compromised dependency
5. **Credential Theft:** Backdoor sends credentials to attacker

**Mitigations:**
- ✅ **Dependency Scanning (Phase 115):** govulncheck, gosec, Trivy in CI/CD
- ✅ **Weekly Scans:** Automated vulnerability detection
- ✅ **Trusted Sources:** All dependencies from official AWS, vetted community
- ✅ **Active Maintenance:** Dependencies updated within 12 months

**Gaps:**
- ❌ No cryptographic verification of dependencies (go.sum is integrity, not authenticity)
- ❌ No dependency pinning enforcement
- ❌ No runtime integrity monitoring

**Result:** Attack could SUCCEED if dependency compromise goes undetected.

**Recommendation:**
- Enable Go module checksum database (sum.golang.org)
- Pin dependency versions (require explicit updates)
- Implement SBOM (Software Bill of Materials) generation
- Runtime monitoring for unusual network activity

---

## 5. Risk Prioritization

### 5.1 Risk Matrix

**Risk Scoring:** Impact × Likelihood

| Impact Level | Multiplier |
|--------------|------------|
| CRITICAL | 4 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 1 |

| Likelihood Level | Multiplier |
|------------------|------------|
| VERY HIGH | 4 |
| HIGH | 3 |
| MEDIUM | 2 |
| LOW | 1 |
| VERY LOW | 0.5 |

**Risk Score = Impact × Likelihood**

### 5.2 Top 10 Highest Risk Threats

| Rank | Threat ID | Threat | Impact | Likelihood | Risk Score | Status |
|------|-----------|--------|--------|------------|------------|--------|
| 1 | **I-02** | Keychain Credential Exposure | CRITICAL (4) | MEDIUM (2) | **8** | Open |
| 2 | **I-01** | Credential Exposure in Environment Variables | CRITICAL (4) | MEDIUM (2) | **8** | Mitigable |
| 3 | **E-04** | Cross-Account Privilege Escalation | CRITICAL (4) | MEDIUM (2) | **8** | Open |
| 4 | **T-01** | Policy Cache Poisoning | CRITICAL (4) | MEDIUM (2) | **8** | ✅ FIXED (v1.18) |
| 5 | **T-02** | DynamoDB State Manipulation | HIGH (3) | MEDIUM (2) | **6** | ✅ MITIGATED (v1.18) |
| 6 | **T-03** | Audit Log Tampering | MEDIUM (2) | MEDIUM (2) | **4** | ✅ MITIGATED (v1.18) |
| 7 | **T-05** | Session Token Injection | HIGH (3) | MEDIUM (2) | **6** | ✅ MITIGATED (v1.18) |
| 8 | **E-01** | Policy Rule Order Bypass | HIGH (3) | MEDIUM (2) | **6** | Open |
| 9 | **E-02** | Approval Workflow Bypass (Session Reuse) | MEDIUM (2) | HIGH (3) | **6** | Open |
| 10 | **D-01** | Rate Limit Bypass | MEDIUM (2) | MEDIUM (2) | **4** | ✅ MITIGATED (v1.18) |

### 5.3 Priority Recommendations

#### P0 (Immediate - High Risk, Not Fully Mitigated)

1. **[I-02] Keychain Credential Exposure Mitigation**
   - **Action:** Document keychain access = full compromise, recommend 1-hour credential lifetimes
   - **Effort:** Low (documentation)
   - **Impact:** Risk awareness, user behavior change

2. **[I-01] Enforce Server Mode for Production**
   - **Action:** Implement `require_server` policy effect for all production profiles
   - **Effort:** Low (policy update)
   - **Impact:** Eliminate environment variable exposure for sensitive profiles

3. **[E-04] Cross-Account Trust Policy Hardening**
   - **Action:** SCP to require SourceIdentity for cross-account AssumeRole
   - **Effort:** Medium (SCP deployment, testing)
   - **Impact:** Prevent cross-account bypass

#### P1 (High Priority - Medium Risk)

4. **[E-01] Policy Rule Order Validation**
   - **Action:** Implement policy linter to detect allow-before-deny conflicts
   - **Effort:** Medium (new linter rules)
   - **Impact:** Prevent policy misconfiguration

5. **[E-02] Approval-Specific Expiration**
   - **Action:** Implement shorter expiration for approved credentials (separate from STS session)
   - **Effort:** High (architecture change)
   - **Impact:** Reduce approval bypass window

6. **[T-02] DynamoDB Item-Level HMAC**
   - **Action:** Add HMAC signatures to approval/break-glass records
   - **Effort:** High (schema change, migration)
   - **Impact:** Tamper-evident state

#### P2 (Medium Priority - Defense in Depth)

7. **[D-03] DynamoDB Deletion Protection**
   - **Action:** Enable deletion protection on all Sentinel tables
   - **Effort:** Low (Terraform update)
   - **Impact:** Prevent accidental/malicious table deletion

8. **[D-04] SSM Parameter Versioning**
   - **Action:** Enable SSM parameter versioning for rollback capability
   - **Effort:** Low (Terraform update)
   - **Impact:** Policy rollback capability

9. **[Supply Chain] Dependency Verification**
   - **Action:** Implement SBOM generation, dependency pinning enforcement
   - **Effort:** Medium (CI/CD integration)
   - **Impact:** Supply chain attack detection

#### P3 (Low Priority - Long-Term Hardening)

10. **[I-02] Secure Enclave Integration**
    - **Action:** Use macOS Secure Enclave for credential storage (T2/M1+ chips)
    - **Effort:** Very High (architecture change)
    - **Impact:** Hardware-backed credential protection

11. **[Network Mode Deprecation]**
    - **Action:** Remove network mode for local servers (Unix socket only)
    - **Effort:** Medium (breaking change, migration path)
    - **Impact:** Eliminate token interception risk

---

## 6. Verification Against Existing Controls

### 6.1 v1.15-v1.18 Security Hardening Coverage

| Threat Category | v1.15-v1.18 Mitigations | Threats Addressed | Gaps Remaining |
|-----------------|-------------------------|-------------------|----------------|
| **Spoofing** | Identity extraction (v1.7), IAM auth | S-01 (✅ FIXED), S-02 (✅ MITIGATED) | S-03 (enforcement optional), S-04 (device ID binding) |
| **Tampering** | Policy signing (v1.18 Phase 126), DynamoDB locking (Phase 131), Audit HMAC (Phase 128) | T-01 (✅ FIXED), T-02 (✅ MITIGATED), T-03 (✅ MITIGATED) | T-02 (item-level HMAC), T-06 (immutable logs) |
| **Repudiation** | HMAC-signed logs (v1.18 Phase 128), SourceIdentity | R-01 (✅ MITIGATED), R-02 (✅ MITIGATED) | R-01 (MFA logging), R-03 (break-glass HMAC) |
| **Information Disclosure** | Error sanitization (v1.16 Phase 119), Secrets Manager (Phase 114), Keychain ACLs (v1.18 Phase 132) | I-03 (✅ FIXED), I-04 (✅ FIXED), I-02 (✅ MITIGATED) | I-01 (env var export), I-05 (log encryption), I-06 (network mode) |
| **Denial of Service** | Distributed rate limiting (v1.18 Phase 133), MDM caching (v1.16 Phase 114) | D-01 (✅ MITIGATED), D-06 (✅ MITIGATED) | D-03 (deletion protection), D-04 (parameter versioning), D-05 (KMS backup) |
| **Elevation of Privilege** | Input validation (v1.18 Phase 134), Break-glass MFA (Phase 127), Process auth (Phase 129) | E-07 (✅ FIXED), E-03 (✅ FIXED), T-05 (✅ MITIGATED) | E-01 (policy linting), E-02 (approval expiration), E-04 (cross-account), E-06 (MDM webhook) |

### 6.2 Security Control Effectiveness

| Control | Implementation | Effectiveness | Coverage |
|---------|----------------|---------------|----------|
| **KMS Policy Signing** | RSASSA_PSS_SHA_256, VerifyingLoader, fail-closed | ✅ EXCELLENT | Policy integrity (T-01) |
| **Timing Attack Mitigation** | crypto/subtle.ConstantTimeCompare, AST verification | ✅ EXCELLENT | Bearer token comparison (S-05) |
| **Rate Limiting** | DynamoDB atomic counters, per-user ARN, Retry-After | ✅ GOOD | DoS protection (D-01), fail-open limitation |
| **Error Sanitization** | Generic client messages, detailed internal logs | ✅ EXCELLENT | Information leakage (I-03) |
| **DynamoDB Encryption** | KMS at rest, optimistic locking, state validation | ✅ GOOD | Data confidentiality, partial integrity (T-02) |
| **Audit Log HMAC** | HMAC-SHA256, CloudWatch forwarding, verify-logs command | ✅ GOOD | Tamper evidence (R-01, T-03), deletion still possible |
| **Break-Glass MFA** | TOTP/SMS, timing-safe verification, SNS alerts | ✅ EXCELLENT | Break-glass abuse (E-03) |
| **Process Authentication** | Unix socket, SO_PEERCRED, PID+UID binding | ✅ EXCELLENT | Local session hijacking (T-05) |
| **Input Validation** | ASCII-only, path traversal rejection, length limits | ✅ EXCELLENT | Command injection (E-07) |
| **Keychain Hardening** | No iCloud sync, unlock required, app approval, possessor-only | ✅ GOOD | Credential theft (I-02), admin bypass possible |
| **Secrets Manager** | API token caching, 1-hour TTL, deprecation warnings | ✅ EXCELLENT | Token exposure (I-04) |
| **MDM Integration** | Fail-closed posture verification, 5-min caching | ✅ GOOD | Device posture bypass (S-04, E-06) |

### 6.3 Security Test Coverage

**v1.18 Security Regression Tests: 153 tests across 13 packages**

| Package | Test Count | Coverage Area |
|---------|------------|---------------|
| `policy` | 24 | Policy signing, verification, caching |
| `lambda` | 18 | TVM handler, rate limiting, error sanitization |
| `sentinel` | 15 | Server security, timing attacks, process auth |
| `breakglass` | 12 | MFA verification, rate limiting |
| `audit` | 10 | HMAC signatures, log verification |
| `ratelimit` | 14 | DynamoDB limiter, concurrent access |
| `validate` | 18 | Input validation, shell escaping |
| `keyring` | 12 | Keychain ACLs, permissions |
| `session` | 10 | DynamoDB locking, state transitions |
| `request` | 8 | Approval state validation |
| `mdm` | 6 | Device posture verification |
| `identity` | 4 | ARN parsing, partition validation |
| `server` | 2 | Unix socket authentication |

**Test Categories:**
- AST verification (timing-safe comparison enforcement)
- Concurrent access tests (race conditions, DynamoDB locking)
- Fuzzing (input validation, shell escaping)
- Error message validation (information leakage)
- Cryptographic verification (HMAC, KMS signatures)

---

## 7. Recommendations

### 7.1 Immediate Actions (Next Sprint)

1. **Deploy SCP for SourceIdentity Enforcement**
   - **Action:** Implement organization-wide SCP requiring `sts:SourceIdentity` like `sentinel:*`
   - **Scope:** Production and admin roles initially, expand to all roles
   - **Effort:** Medium (1-2 weeks for testing and rollout)
   - **Impact:** Prevents policy bypass via direct AWS CLI/SDK

2. **Enable DynamoDB Deletion Protection**
   - **Action:** Update Terraform to set `deletion_protection_enabled: true` on all Sentinel tables
   - **Scope:** Approval, break-glass, session, rate limit tables
   - **Effort:** Low (1 day)
   - **Impact:** Prevents accidental/malicious table deletion

3. **Document Keychain Trust Boundary**
   - **Action:** Add SECURITY.md section: "Keychain access = full credential compromise"
   - **Scope:** User documentation, threat model
   - **Effort:** Low (1 day)
   - **Impact:** User awareness, realistic security expectations

4. **Enforce Server Mode for Production**
   - **Action:** Update production policies with `require_server` effect
   - **Scope:** All production and admin profiles
   - **Effort:** Low (policy update)
   - **Impact:** Eliminate environment variable exposure

### 7.2 Short-Term (Next Quarter)

5. **Implement Policy Linter**
   - **Action:** Build `sentinel policy lint` command to detect rule ordering issues
   - **Detection:** Allow-before-deny conflicts, overlapping conditions, unreachable rules
   - **Effort:** Medium (2-3 weeks)
   - **Impact:** Prevent policy misconfiguration

6. **Add Item-Level HMAC to DynamoDB**
   - **Action:** Implement HMAC signatures on approval and break-glass records
   - **Schema:** Add `hmac` field, verify on read, fail-closed on mismatch
   - **Effort:** High (4-6 weeks with migration)
   - **Impact:** Tamper-evident state, detect unauthorized modifications

7. **Enable SSM Parameter Versioning**
   - **Action:** Update SSM parameters to use versioning, implement rollback CLI
   - **Command:** `sentinel policy rollback production --version 3`
   - **Effort:** Medium (2-3 weeks)
   - **Impact:** Policy rollback capability, accidental change recovery

8. **Implement Cross-Account Policy Validator**
   - **Action:** Add `sentinel validate-trust-policy` to check role trust policies
   - **Detection:** Overly broad principals, missing SourceIdentity conditions
   - **Effort:** Medium (3-4 weeks)
   - **Impact:** Prevent cross-account privilege escalation

### 7.3 Long-Term (Next 6-12 Months)

9. **Deprecate Network Mode for Local Servers**
   - **Action:** Phase out `--address` flag, enforce `--unix-socket` for local use
   - **Migration:** Document mutual TLS requirement for container network mode
   - **Effort:** Medium (breaking change, migration path needed)
   - **Impact:** Eliminate bearer token interception risk

10. **Implement SBOM and Dependency Verification**
    - **Action:** Generate Software Bill of Materials, enforce dependency pinning
    - **Tools:** cyclonedx-gomod, dependabot, go.sum verification
    - **Effort:** Medium (CI/CD integration)
    - **Impact:** Supply chain attack detection

11. **Explore Secure Enclave Integration (macOS)**
    - **Action:** Investigate using macOS Secure Enclave for credential storage
    - **Scope:** T2/M1+ Macs with hardware-backed security
    - **Effort:** High (architecture research, implementation)
    - **Impact:** Hardware-backed credential protection, malware resistance

12. **Implement Approval-Specific Expiration**
    - **Action:** Separate approval timeout from STS session duration
    - **Schema:** Approval records include `expires_at`, enforce on credential issuance
    - **Effort:** High (architecture change)
    - **Impact:** Reduce approval bypass window

### 7.4 Monitoring and Detection

13. **CloudTrail Alerting**
    - **Alerts:**
      - AssumeRole without SourceIdentity (policy bypass detection)
      - DynamoDB DeleteTable on Sentinel tables
      - KMS key state changes (DisableKey, ScheduleKeyDeletion)
      - SSM DeleteParameter on `/sentinel/*`
    - **Tools:** CloudWatch Alarms, AWS Security Hub, GuardDuty
    - **Effort:** Medium (alert configuration)

14. **Anomaly Detection**
    - **Metrics:**
      - Break-glass invocation spike
      - Unusual device count per user
      - Cross-account access patterns
      - Rate limit violations
    - **Tools:** CloudWatch Insights, custom dashboards
    - **Effort:** Medium (query development)

15. **Regular Security Reviews**
    - **Cadence:** Quarterly threat model review, annual penetration test
    - **Scope:** New features, architecture changes, threat landscape updates
    - **Effort:** Ongoing

---

## Appendix A: Threat Summary Table

| ID | Category | Threat | Impact | Likelihood | Risk | Status |
|----|----------|--------|--------|------------|------|--------|
| S-01 | Spoofing | OS Username Spoofing | CRITICAL | LOW | LOW | ✅ FIXED (v1.7.1) |
| S-02 | Spoofing | IAM Identity Spoofing (Lambda) | CRITICAL | VERY LOW | LOW | ✅ MITIGATED |
| S-03 | Spoofing | SourceIdentity Spoofing | MEDIUM | HIGH | MEDIUM | ⚠️ Enforcement Optional |
| S-04 | Spoofing | Device ID Spoofing | MEDIUM | LOW | LOW | ✅ MITIGATED |
| S-05 | Spoofing | Bearer Token Spoofing | HIGH | VERY LOW | LOW | ✅ MITIGATED (v1.16) |
| T-01 | Tampering | Policy Cache Poisoning | CRITICAL | MEDIUM | HIGH | ✅ FIXED (v1.18) |
| T-02 | Tampering | DynamoDB State Manipulation | HIGH | MEDIUM | MEDIUM | ✅ MITIGATED (v1.18) |
| T-03 | Tampering | Audit Log Tampering | MEDIUM | MEDIUM | MEDIUM | ✅ MITIGATED (v1.18) |
| T-04 | Tampering | Keychain Credential Tampering | MEDIUM | LOW | LOW | ✅ MITIGATED (v1.18) |
| T-05 | Tampering | Session Token Injection | HIGH | MEDIUM | MEDIUM | ✅ MITIGATED (v1.18) |
| T-06 | Tampering | Break-Glass Event Manipulation | HIGH | LOW | MEDIUM | ⚠️ Partial |
| R-01 | Repudiation | Policy Decision Repudiation | MEDIUM | MEDIUM | MEDIUM | ✅ MITIGATED (v1.18) |
| R-02 | Repudiation | Approval Workflow Repudiation | MEDIUM | LOW | LOW | ✅ MITIGATED |
| R-03 | Repudiation | Break-Glass Justification Repudiation | LOW | LOW | LOW | ⚠️ Partial |
| I-01 | Information Disclosure | Credential Exposure (Env Vars) | CRITICAL | MEDIUM | HIGH | ⚠️ Mitigable |
| I-02 | Information Disclosure | Keychain Credential Exposure | CRITICAL | MEDIUM | HIGH | ⚠️ Open |
| I-03 | Information Disclosure | Error Message Leakage | LOW | HIGH | MEDIUM | ✅ FIXED (v1.16) |
| I-04 | Information Disclosure | MDM API Token Exposure | MEDIUM | LOW | LOW | ✅ FIXED (v1.16) |
| I-05 | Information Disclosure | CloudWatch Log Exposure | MEDIUM | MEDIUM | MEDIUM | ⚠️ Partial |
| I-06 | Information Disclosure | Session Token Interception (Network) | HIGH | LOW | MEDIUM | ⚠️ Open |
| I-07 | Information Disclosure | Policy Content Disclosure | LOW | HIGH | LOW | ✅ Acceptable |
| D-01 | Denial of Service | Rate Limit Bypass (Lambda) | MEDIUM | MEDIUM | MEDIUM | ✅ MITIGATED (v1.18) |
| D-02 | Denial of Service | Break-Glass Rate Limit Abuse | MEDIUM | LOW | LOW | ✅ MITIGATED (v1.18) |
| D-03 | Denial of Service | DynamoDB Table Deletion | HIGH | LOW | MEDIUM | ⚠️ Open |
| D-04 | Denial of Service | SSM Parameter Deletion | HIGH | LOW | MEDIUM | ⚠️ Open |
| D-05 | Denial of Service | KMS Key Deletion/Disable | CRITICAL | VERY LOW | MEDIUM | ⚠️ Partial |
| D-06 | Denial of Service | MDM API Quota Exhaustion | MEDIUM | LOW | LOW | ✅ MITIGATED (v1.16) |
| E-01 | Elevation of Privilege | Policy Rule Order Bypass | HIGH | MEDIUM | MEDIUM | ⚠️ Open |
| E-02 | Elevation of Privilege | Approval Workflow Bypass (Cache) | MEDIUM | HIGH | MEDIUM | ⚠️ Open |
| E-03 | Elevation of Privilege | Break-Glass Bypass (No MFA) | HIGH | LOW | LOW | ✅ FIXED (v1.18) |
| E-04 | Elevation of Privilege | Cross-Account Privilege Escalation | CRITICAL | MEDIUM | HIGH | ⚠️ Open |
| E-05 | Elevation of Privilege | IAM Permission Boundary Bypass | HIGH | LOW | LOW | ✅ Acceptable |
| E-06 | Elevation of Privilege | Device Posture Bypass (Unenrollment) | MEDIUM | LOW | LOW | ⚠️ Partial |
| E-07 | Elevation of Privilege | Command Injection (Profile Name) | CRITICAL | VERY LOW | LOW | ✅ FIXED (v1.18) |
| E-08 | Elevation of Privilege | Session Hijacking (ID Prediction) | MEDIUM | VERY LOW | LOW | ✅ MITIGATED |

---

## Appendix B: Security Hardening Timeline

| Version | Phase | Feature | Threat(s) Addressed |
|---------|-------|---------|---------------------|
| **v1.7.1** | - | AWS identity extraction (not OS user) | S-01 |
| **v1.15** | 110-112 | Device posture verification, OIDC integration | S-04, E-06 |
| **v1.16** | 113 | Timing attack remediation | S-05 |
| | 114 | Secrets Manager migration | I-04 |
| | 115 | CI/CD security scanning | Supply Chain |
| | 116 | DynamoDB encryption at rest | I-05 |
| | 117 | API rate limiting | D-01 |
| | 119 | Error sanitization | I-03 |
| **v1.18** | 126 | KMS policy signing | T-01 |
| | 127 | Break-glass MFA | E-03 |
| | 128 | HMAC audit logging | T-03, R-01 |
| | 129 | Process-based authentication | T-05, I-06 |
| | 130 | Identity hardening (partition support) | S-01 |
| | 131 | DynamoDB state validation | T-02 |
| | 132 | Keyring protection | T-04, I-02 |
| | 133 | Distributed rate limiting | D-01 |
| | 134 | Input sanitization | E-07 |
| | 135 | Security validation (153 tests) | All |

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-26 | Claude Sonnet 4.5 | Initial comprehensive STRIDE threat model |
| 2.0 | 2026-01-27 | Claude Opus 4.5 | Updated for v2.0 stable release, incorporated Phase 150-152 security hardening |

**Review Schedule:** Quarterly or when significant architecture changes occur

**Distribution:** Security team, engineering leads, compliance stakeholders

**Next Review:** 2026-04-27

---

**END OF STRIDE THREAT MODEL**
