# STRIDE Threat Model Findings - Categorized by Responsibility

**Date:** 2026-01-26
**Purpose:** Clarify which findings require Sentinel code changes vs. customer AWS account hardening

---

## Category 1: Sentinel Implementation Issues
*Require code changes, new commands, or feature additions to Sentinel itself*

### High Priority

| ID | Finding | Action Required | Effort | Impact |
|----|---------|-----------------|--------|--------|
| **E-01** | Policy Rule Order Bypass | Build `sentinel policy lint` command to detect allow-before-deny conflicts | Medium (2-3 weeks) | Prevent policy misconfiguration |
| **E-02** | Approval Bypass via Session Reuse | Implement approval-specific expiration (shorter than STS session) | High (4-6 weeks) | Reduce approval bypass window |
| **T-02** | DynamoDB State Manipulation | Add item-level HMAC signatures to approval/break-glass records | High (4-6 weeks) | Tamper-evident state |

### Medium Priority

| ID | Finding | Action Required | Effort | Impact |
|----|---------|-----------------|--------|--------|
| **E-04** | Cross-Account Escalation Detection | Build `sentinel validate-trust-policy` to check role trust policies | Medium (3-4 weeks) | Warn on overly broad principals |
| **Supply Chain** | Dependency Verification | Generate SBOM, enforce dependency pinning in CI/CD | Medium (2-3 weeks) | Supply chain attack detection |

### Low Priority (Long-Term)

| ID | Finding | Action Required | Effort | Impact |
|----|---------|-----------------|--------|--------|
| **I-06** | Network Mode Token Interception | Deprecate network mode for local use (enforce Unix socket) | Medium (breaking change) | Eliminate token interception |
| **I-02** | Keychain Credential Exposure | Investigate macOS Secure Enclave integration (T2/M1+ chips) | Very High | Hardware-backed credential protection |

---

## Category 2: Customer Deployment Concerns
*AWS account configurations that customers should apply (not Sentinel bugs)*

### Critical (Should Be Default/Guided)

| ID | Finding | Customer Action | Why Important | Helper Command Idea |
|----|---------|-----------------|---------------|---------------------|
| **S-03** | SourceIdentity Enforcement | Deploy SCP: `Deny sts:AssumeRole where sts:SourceIdentity NOT LIKE sentinel:*` | Prevents bypassing Sentinel via direct AWS CLI/SDK | `sentinel init scp --management-account` ✨ |
| **D-03** | DynamoDB Table Deletion | Enable `deletion_protection_enabled: true` on all Sentinel tables | Prevents accidental/malicious table deletion | `sentinel init dynamodb --enable-deletion-protection` |
| **D-04** | SSM Parameter Deletion | Enable SSM parameter versioning, create backup | Policy rollback capability | `sentinel init ssm --enable-versioning` |
| **D-05** | KMS Key Deletion | Create CloudTrail alert for KMS key state changes | Detect key disablement | `sentinel init monitoring --cloudtrail-alerts` |

### Important (Best Practices)

| ID | Finding | Customer Action | Why Important |
|----|---------|-----------------|---------------|
| **E-04** | Cross-Account Trust Policy | Require `sts:SourceIdentity` condition in cross-account trust policies | Prevent cross-account privilege escalation |
| **I-01** | Environment Variable Exposure | Use `require_server` policy effect for production profiles | Eliminate environment variable exposure |
| **I-05** | CloudWatch Log Encryption | Enable CloudWatch Logs KMS encryption | Protect sensitive logs |

---

## Category 3: Documentation Gaps
*Just need better documentation, no code or deployment changes*

| ID | Finding | Documentation Needed | Location |
|----|---------|---------------------|----------|
| **I-02** | Keychain Access = Full Compromise | Document trust boundary: keychain access = full credential access | `docs/SECURITY.md` (Trust Model section) ✅ DONE |
| **I-01** | Server Mode Benefits | Document: Use `--server` mode for long-running processes | `docs/guide/commands.md` |
| **E-01** | Policy Rule Ordering | Best practice: Specific rules first, general rules last | `docs/POLICY_DESIGN.md` (new guide) |
| **E-04** | Cross-Account Hardening | Document: Defense-in-depth (Sentinel policy + IAM trust + SCP) | `docs/SECURITY.md` |
| **E-06** | Device Posture Re-checking | Document: Use `require_server` for device-posture-protected profiles | `docs/DEVICE_POSTURE.md` |

---

## Category 4: Already Fixed ✅
*Addressed in v1.15-v1.18 security hardening*

| ID | Threat | Fixed In | Mitigation |
|----|--------|----------|------------|
| **S-01** | OS Username Spoofing | v1.7.1 | AWS STS GetCallerIdentity for authoritative username |
| **T-01** | Policy Cache Poisoning | v1.18 Phase 126 | KMS policy signing (RSASSA_PSS_SHA_256) |
| **T-03** | Audit Log Tampering | v1.18 Phase 128 | HMAC-SHA256 signed audit logs |
| **T-05** | Session Token Injection | v1.18 Phase 129 | Unix socket mode with process authentication |
| **I-03** | Error Message Leakage | v1.16 Phase 119 | Error sanitization (generic client messages) |
| **I-04** | MDM Token Exposure | v1.16 Phase 114 | Secrets Manager integration |
| **E-03** | Break-Glass Bypass | v1.18 Phase 127 | MFA enforcement (TOTP/SMS) |
| **E-07** | Command Injection | v1.18 Phase 134 | Input sanitization (ValidateProfileName) |
| **D-01** | Rate Limit Bypass | v1.18 Phase 133 | DynamoDB distributed rate limiter |

---

## Brilliant Idea: Helper Commands for Customer Deployment

Your suggestion to add helper commands for deploying SCPs and other AWS configurations is excellent! Here's a proposed design:

### `sentinel init` Subcommands

```bash
# Deploy SCP to management account (prevents Sentinel bypass)
sentinel init scp \
  --management-account 123456789012 \
  --ou-id ou-xxxx-yyyyyyyy \
  --require-source-identity \
  --dry-run

# Enable DynamoDB deletion protection
sentinel init dynamodb \
  --table-prefix sentinel \
  --enable-deletion-protection \
  --enable-pitr

# Enable SSM parameter versioning
sentinel init ssm \
  --parameter-prefix /sentinel \
  --enable-versioning \
  --enable-backup

# Create CloudTrail alerts for security events
sentinel init monitoring \
  --cloudtrail-alerts \
  --sns-topic arn:aws:sns:us-east-1:123456789012:sentinel-security \
  --alert-on kms-key-change,dynamodb-delete,ssm-delete

# Validate existing deployment against best practices
sentinel init validate \
  --check scp,dynamodb,ssm,kms,cloudtrail \
  --report findings.json
```

### What These Commands Would Do

1. **`sentinel init scp`**
   - Read recommended SCP policy from embedded template
   - Apply to specified management account or OU
   - Support dry-run mode (show what would be applied)
   - Validate existing SCP doesn't conflict

2. **`sentinel init dynamodb`**
   - Discover Sentinel DynamoDB tables (by prefix)
   - Enable deletion protection on each
   - Enable point-in-time recovery (PITR)
   - Report current state

3. **`sentinel init ssm`**
   - Discover Sentinel SSM parameters (by prefix)
   - Enable versioning
   - Create backup (export to S3 or local)
   - Report current state

4. **`sentinel init monitoring`**
   - Create CloudWatch alarms for security events
   - Configure SNS topic for alerts
   - Deploy EventBridge rules for CloudTrail events
   - Report monitoring coverage

5. **`sentinel init validate`**
   - Audit existing deployment
   - Check for missing protections (deletion protection, versioning, etc.)
   - Scan IAM trust policies for overly broad principals
   - Generate report of findings

---

## Priority Implementation Plan

### Phase 1: Documentation (1 week)
- ✅ Trust Model section (DONE)
- Policy design best practices guide
- Server mode vs standard mode guidance
- Cross-account hardening guide

### Phase 2: Sentinel Commands (4-6 weeks)
1. `sentinel policy lint` - policy rule conflict detection
2. `sentinel validate-trust-policy` - cross-account trust policy auditing
3. `sentinel init validate` - deployment best practices checker

### Phase 3: Deployment Helpers (4-6 weeks)
4. `sentinel init scp` - SCP deployment helper
5. `sentinel init dynamodb` - DynamoDB hardening
6. `sentinel init ssm` - SSM parameter protection
7. `sentinel init monitoring` - CloudTrail alerting

### Phase 4: Advanced Features (8-12 weeks)
8. Item-level HMAC for DynamoDB records
9. Approval-specific expiration
10. SBOM generation in CI/CD

---

## Summary

**The user is 100% correct:**

❌ **NOT Sentinel bugs:**
- SCP enforcement (customer AWS account hardening)
- DynamoDB deletion protection (customer deployment setting)
- SSM parameter versioning (customer deployment setting)
- CloudWatch encryption (customer deployment setting)

✅ **ARE Sentinel implementation needs:**
- Policy linter (`sentinel policy lint`)
- Trust policy validator (`sentinel validate-trust-policy`)
- Item-level HMAC for critical state
- Approval-specific expiration
- Network mode deprecation

💡 **BRILLIANT idea:**
- Helper commands (`sentinel init ...`) to guide customers through proper AWS account hardening
- Makes best practices easily discoverable and executable
- Reduces friction for security hardening

**Next Steps:**
1. Implement documentation updates (Phase 1)
2. Build `sentinel init validate` to audit deployment (useful immediately)
3. Build `sentinel init scp` to help with SCP deployment (high-value, low-effort)
4. Continue with policy linter and other Sentinel features

Would you like to proceed with implementing any of these helper commands?
