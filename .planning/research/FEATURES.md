# Features Research: Server-Side Credential Vending

**Domain:** Token Vending Machine (TVM) / Credential Vending Service
**Researched:** 2026-01-24
**Confidence:** HIGH (AWS official documentation + established patterns)

## Executive Summary

Token Vending Machines provide server-side temporary credential issuance, typically for multi-tenant SaaS applications or IoT device provisioning. The core pattern uses AWS Lambda + STS to generate tenant-scoped or device-scoped temporary credentials that cannot be bypassed. Sentinel's TVM implementation adds unique value by integrating policy enforcement, session tracking, and approval workflows at the credential boundary.

**Key Finding:** TVMs are fundamentally about **policy enforcement at credential issuance time**. The server has the only path to credentials, making bypass impossible. This aligns perfectly with Sentinel's core value proposition: "Credentials are issued only when policy explicitly allows it — no credentials, no access, no exceptions."

## Table Stakes

Features users expect from any credential vending service. Missing these = incomplete TVM.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Temporary Credentials** | STS credentials with configurable TTL | Low | AWS STS provides this; 15min-12hr range standard |
| **Authentication** | Verify client identity before vending | Medium | Sentinel has AWS identity via GetCallerIdentity |
| **Dynamic Policy Scoping** | Credentials scoped to specific resources | High | Core TVM pattern; tenant/user/resource isolation |
| **Session Duration Control** | Configurable credential lifetime | Low | STS session duration parameter; policy-enforced caps |
| **Audit Logging** | Who got what credentials, when | Medium | CloudTrail integration + application logging |
| **Fail-Safe Defaults** | Deny when policy evaluation fails | Low | Fail-closed for security (existing Sentinel pattern) |
| **Idempotency** | Repeated requests don't cause issues | Medium | Session caching or deterministic responses |
| **Rate Limiting** | Prevent credential enumeration/abuse | Medium | Per-user or per-profile request throttling |
| **Credential Revocation** | Ability to invalidate active sessions | High | Requires session tracking (Sentinel v1.10 has this) |
| **Trust Boundary Enforcement** | Only authorized systems can vend credentials | Low | IAM role trust policies + network controls |

## Differentiators

Features that set Sentinel TVM apart from basic credential vending. Not expected, but highly valued.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Policy-Gated Vending** | Sentinel policies apply BEFORE credentials issued | Low | Reuse existing policy engine; TVM mode condition |
| **Approval Workflow Integration** | Sensitive credentials require human approval | Low | Existing v1.2 approval system works server-side |
| **Break-Glass Override** | Emergency access with mandatory justification | Low | Existing v1.3 break-glass applies to TVM requests |
| **Session Tracking & Compliance** | All vended sessions tracked for audit | Low | Existing v1.10/v1.13 session tracking |
| **SourceIdentity Propagation** | CloudTrail correlation for all vended credentials | Low | Existing v1.1 SourceIdentity stamping |
| **Real-Time Revocation** | Revoke active sessions immediately | Low | v1.10 session revocation via DynamoDB |
| **Credential Mode Awareness** | Policies differentiate TVM vs CLI vs credential_process | Low | Existing v1.10 CredentialMode schema |
| **Client Bypass Prevention** | No client-side policy evaluation path exists | Medium | Lambda-only credential path; client cannot self-issue |
| **Multi-Factor Authentication Support** | MFA verification before credential vending | Medium | Integrate with existing AWS STS MFA requirements |
| **Per-Request Policy Evaluation** | Fresh policy check on every credential request | Low | Existing server mode (v1.10) already does this |
| **Unified Policy Language** | Same policy syntax for CLI, exec, and TVM modes | Low | CredentialMode conditions handle all three |
| **Attribute-Based Access Control** | Session tags from identity attributes | Medium | AWS STS session tags for ABAC; JWT claims integration |
| **Session Metrics & Analytics** | Track credential usage patterns | Medium | Extend v1.13 session compliance reporting |

## Anti-Features

Features to explicitly NOT build. Common mistakes in credential vending implementations.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Client-Side Policy Evaluation** | Clients can bypass by not calling TVM | Server-only evaluation; no client fallback |
| **Long-Lived Credentials** | Defeats purpose of temporary vending | Cap at 1 hour max; default 15 minutes |
| **Credential Caching on Client** | Client can reuse after revocation | Server-managed sessions only; client gets credentials per-request |
| **Anonymous Credential Requests** | Cannot audit who got what | Require AWS STS GetCallerIdentity on every request |
| **Overly Permissive Scoping** | Credentials with broad permissions | Dynamic policy scoping to least privilege |
| **Synchronous Approval in TVM Path** | Blocks credential requests waiting for approval | Return 403 with request ID; client polls separately |
| **Credential Response in Logs** | AccessKeyId/SecretAccessKey leak | Log credential metadata (session ID, user, profile) not secrets |
| **Implicit Allow** | Credentials issued when policy missing | Explicit deny when no matching allow rule |
| **Cross-Tenant Credential Reuse** | Session from tenant A used for tenant B | Session binding to identity; validate on each request |
| **Unlimited Session Duration** | No upper bound on credential lifetime | Policy-enforced MaxServerDuration (existing v1.10) |
| **Single Point of Trust** | Only one layer validates requests | Defense in depth: TVM policy + IAM policy + SCP |
| **Hard-Coded Policies** | Cannot update rules without deployment | SSM Parameter Store (existing Sentinel pattern) |
| **No Expiration Enforcement** | Server doesn't check session TTL | DynamoDB TTL + explicit expiration checks (existing v1.10) |

## Integration with Existing Sentinel Features

How TVM leverages Sentinel's existing capabilities.

### Already Built (v1.0-v1.13)

| Existing Feature | TVM Integration Point | Implementation Effort |
|------------------|----------------------|----------------------|
| **Policy Engine** | Evaluate with `CredentialMode: server` | Minimal - add TVM mode constant |
| **SSM Policy Loading** | Same `/sentinel/policies/*` paths | Zero - works as-is |
| **AWS Identity Extraction** | STS GetCallerIdentity for TVM clients | Zero - works as-is |
| **SourceIdentity Stamping** | Apply to all AssumeRole calls from TVM | Zero - works as-is |
| **Session Tracking** | Track TVM-vended sessions in DynamoDB | Minimal - add vending_mode field |
| **Session Revocation** | Revoke TVM sessions via `sentinel server-revoke` | Zero - works as-is |
| **Approval Workflows** | Require approval before TVM credential issuance | Medium - async approval check in TVM handler |
| **Break-Glass** | Emergency TVM access with justification | Medium - break-glass state check in TVM handler |
| **Decision Logging** | Log TVM credential decisions | Minimal - add TVM context to logs |
| **CredentialMode Conditions** | Policies target `server` mode specifically | Zero - already exists |
| **require_server_session** | Enforce session tracking for TVM | Zero - policy effect works as-is |
| **MaxServerDuration** | Cap TVM session duration | Zero - works as-is |
| **Profile-Based Policies** | Different TVM rules per profile | Zero - works as-is |
| **Time-Based Conditions** | Allow TVM only during business hours | Zero - works as-is |
| **User Conditions** | Allow TVM only for specific users | Zero - works as-is |

### New Requirements for TVM

| New Feature | Purpose | Why Needed |
|-------------|---------|------------|
| **Lambda Handler** | Entry point for TVM requests | TVMs are serverless; no persistent process |
| **HTTP/API Gateway Integration** | Client-server communication | Standard TVM pattern uses API Gateway + Lambda |
| **Request Authentication** | Verify client identity via AWS SigV4 | Prevent anonymous credential requests |
| **Dynamic Policy Generation** | Scope credentials to tenant/resource | Multi-tenant isolation via IAM policy injection |
| **STS AssumeRole Integration** | Vend scoped credentials | Core TVM pattern; use Sentinel role with inline policy |
| **Credential Response Format** | Return AccessKeyId/SecretAccessKey/SessionToken | Standard AWS credential format |
| **Error Response Format** | Structured errors for client handling | HTTP status codes + JSON error bodies |
| **Health Check Endpoint** | Monitor TVM availability | Operational requirement for production |

## TVM Architecture Patterns

Based on AWS SaaS Factory and IoT CVM reference architectures.

### Standard TVM Flow

1. **Client authenticates** - AWS SigV4 request to API Gateway
2. **Lambda validates identity** - STS GetCallerIdentity extracts ARN
3. **Policy evaluation** - Sentinel policy engine checks allow/deny
4. **Dynamic scoping** - Generate IAM policy for resource isolation
5. **STS AssumeRole** - Vend temporary credentials with inline policy
6. **Response** - Return credentials + session metadata
7. **Session tracking** - Record session in DynamoDB
8. **Audit logging** - Log decision + credential metadata

### Sentinel TVM Enhancements

1. **Client authenticates** - AWS SigV4 request to API Gateway
2. **Lambda validates identity** - STS GetCallerIdentity extracts ARN
3. **Approval check** - Query DynamoDB for pending/approved requests (if approval required)
4. **Break-glass check** - Query DynamoDB for active break-glass sessions (if needed)
5. **Policy evaluation** - Sentinel policy engine with `CredentialMode: server`
6. **Dynamic scoping** - Generate IAM policy + attach SourceIdentity session tag
7. **STS AssumeRole** - Vend credentials with inline policy + session tags
8. **Session tracking** - Record session in DynamoDB with revocation support
9. **Response** - Return credentials + session ID
10. **Audit logging** - Log decision + credential metadata + session correlation

### Session Lifecycle

```
Client Request → Authentication → Policy Evaluation → [Approval/Break-Glass Check] →
Dynamic Scoping → STS AssumeRole → Session Created → Credentials Returned →
[Session Touch on subsequent requests] → Session Expired/Revoked → Credentials Invalid
```

## Feature Dependencies

```
Authentication (STS GetCallerIdentity)
  ↓
Policy Evaluation (existing engine)
  ↓
[Approval Check (v1.2)] ← Optional for sensitive profiles
  ↓
[Break-Glass Check (v1.3)] ← Optional for emergency access
  ↓
Dynamic Policy Generation ← NEW (tenant/resource scoping)
  ↓
STS AssumeRole ← NEW (with inline policy + session tags)
  ↓
Session Tracking (v1.10) ← Records session for revocation
  ↓
Credential Response ← NEW (HTTP response format)
```

## Security Requirements

Based on AWS temporary credential best practices and TVM security patterns.

| Requirement | Implementation | Priority |
|-------------|----------------|----------|
| **No Long-Term Credentials in Client** | TVM vends temporary only | CRITICAL |
| **Fail-Closed on Errors** | Deny credentials on policy/store errors | CRITICAL |
| **Session Duration Caps** | 15min default, 1hr max (policy-enforced) | HIGH |
| **Credential Non-Logging** | Never log AccessKeyId/SecretAccessKey | CRITICAL |
| **Revocation Check** | Query session status before vending | HIGH |
| **STS Token Expiration** | Enforce TTL via STS DurationSeconds | HIGH |
| **Network Isolation** | VPC-only Lambda (optional) | MEDIUM |
| **Rate Limiting** | Per-user request throttling | HIGH |
| **MFA Enforcement** | Optional MFA requirement via policy | MEDIUM |
| **Audit Trail** | All requests logged (success + failure) | HIGH |
| **SourceIdentity Propagation** | All AssumeRole calls tagged | HIGH |
| **IAM Policy Validation** | Validate generated policies before AssumeRole | MEDIUM |
| **Cross-Tenant Isolation** | Session binding to identity | HIGH |
| **DynamoDB Encryption** | Encrypt session table at rest | MEDIUM |
| **API Gateway Authentication** | AWS SigV4 required (no anonymous) | CRITICAL |

## MVP Recommendation

For v1.14 MVP, prioritize core TVM functionality with existing Sentinel integration.

### Phase 1: Foundation
1. Lambda handler skeleton with API Gateway integration
2. AWS SigV4 authentication (IAM authorization)
3. Policy evaluation with `CredentialMode: server`
4. Basic STS AssumeRole with static policy

### Phase 2: Dynamic Scoping
5. Dynamic IAM policy generation (tenant/resource scoping)
6. Session tag propagation (SourceIdentity + custom attributes)
7. Credential response format (AWS SDK compatible)

### Phase 3: Session Integration
8. Session tracking (reuse v1.10 infrastructure)
9. Session revocation support (check before vending)
10. Decision logging (TVM context)

### Phase 4: Sentinel Feature Integration
11. Approval workflow integration (check approval status)
12. Break-glass integration (emergency access bypass)
13. Enhanced audit logging (compliance export)

### Defer to Post-MVP

- **MFA enforcement** - Complex; requires STS GetSessionToken flow
- **Advanced ABAC** - Session tags from SAML/OIDC; requires federation
- **Multi-region deployment** - Operational complexity
- **Credential caching** - Optimization; not security-critical
- **Custom encryption** - Use AWS KMS defaults initially
- **Metrics/Analytics** - Observability enhancement

## Open Questions

1. **Deployment Model** - Single Lambda for all profiles, or per-profile Lambdas?
   - Recommendation: Single Lambda with profile parameter (simpler ops)

2. **API Gateway vs ALB** - Which fronts the Lambda?
   - Recommendation: API Gateway for AWS SigV4 authentication built-in

3. **Session Caching** - Should TVM cache credentials for repeated requests?
   - Recommendation: No caching in MVP; always vend fresh (simpler, more secure)

4. **Approval Timeout** - How long to wait for approval before denying?
   - Recommendation: Return 403 immediately; client polls approval status separately

5. **Break-Glass Bypass** - Does active break-glass session auto-approve TVM requests?
   - Recommendation: Yes; break-glass state checked before policy evaluation

6. **Cross-Account AssumeRole** - Can TVM vend credentials for cross-account roles?
   - Recommendation: Yes; same pattern as CLI exec (two-hop orchestration)

7. **Client SDK** - Should we provide a Sentinel TVM client library?
   - Recommendation: Defer to post-MVP; document standard AWS SDK usage initially

8. **Backward Compatibility** - Should CLI exec fall back to TVM if local policy loading fails?
   - Recommendation: No; keep CLI and TVM as separate modes (explicit, not fallback)

## Sources

### AWS Official Documentation (HIGH Confidence)
- [AWS Prescriptive Guidance: Lambda Token Vending Machine](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/implement-saas-tenant-isolation-for-amazon-s3-by-using-an-aws-lambda-token-vending-machine.html)
- [AWS IAM: Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- [AWS IAM: Pass Session Tags in STS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)

### AWS Reference Implementations (MEDIUM Confidence)
- [IoT Atlas: Device Bootstrap - Certificate Vending Machine](https://iotatlas.net/en/implementations/aws/device_bootstrap/aws-iot-certificate-vending-machine/)
- [AWS Labs: aws-iot-certificate-vending-machine](https://github.com/awslabs/aws-iot-certificate-vending-machine)
- [AWS SaaS Factory: Dynamic Policy Generation](https://github.com/aws-samples/aws-saas-factory-dynamic-policy-generation)

### Security Best Practices (HIGH Confidence)
- [AWS Security Maturity Model: Use Temporary Credentials](https://maturitymodel.security.aws.dev/en/2.-foundational/temporary-credentials/)
- [The Hidden Port: Securing Temporary Credentials in AWS](https://thehiddenport.dev/posts/aws-temporary-credentials-security/)
- [NIST Token Security Guidelines](https://www.biometricupdate.com/202601/nist-warns-token-security-remains-a-critical-weakness-in-cloud-federal-systems)

### Technical Articles (MEDIUM Confidence)
- [AWS Mobile Blog: Simplifying Token Vending Machine Deployment](https://aws.amazon.com/blogs/mobile/simplifying-token-vending-machine-deployment-with-aws-cloudformation/)
- [Picus Security: Isolate Tenant Data via Lambda TVM](https://medium.com/picus-security-engineering/isolate-your-tenant-data-on-aws-s3-via-aws-lambda-token-vending-machine-e5c7f4254ed4)
- [HashiCorp Blog: SaaS Data Isolation with Dynamic Credentials](https://aws.amazon.com/blogs/apn/saas-data-isolation-with-dynamic-credentials-using-hashicorp-vault-in-amazon-eks/)
