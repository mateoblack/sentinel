# Enforcement Patterns

Sentinel enforcement is optional and progressive. This guide documents IAM trust policy and Service Control Policy (SCP) patterns that allow teams to require Sentinel-issued credentials for sensitive roles.

## Overview

Sentinel enforcement operates at three levels:

| Level | Mode | Description |
|-------|------|-------------|
| 1 | Advisory | Sentinel logs decisions but doesn't enforce - AWS accepts any valid credentials |
| 2 | Trust Policy | Individual roles require Sentinel SourceIdentity - non-Sentinel credentials are rejected |
| 3 | Organization SCP | Organization-wide policies require Sentinel for all or selected roles |

Most teams start at Level 1 (advisory) during rollout, then progressively enable enforcement as confidence grows.

## How Enforcement Works

Sentinel stamps every issued session with a `SourceIdentity` value:

```
sentinel:<user>:<request-id>
```

Example: `sentinel:alice:a1b2c3d4`

This value is:
- **Immutable** - Set once on AssumeRole, cannot be changed for session lifetime
- **Propagating** - Follows through role chaining automatically
- **Auditable** - Appears in every CloudTrail event from that session

IAM trust policies can require this prefix using the `sts:SourceIdentity` condition key. Without a valid Sentinel SourceIdentity, AssumeRole fails with AccessDenied.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User Request   │────>│  Sentinel        │────>│  AWS STS        │
│                 │     │                  │     │                 │
│ "I need prod    │     │ Policy: allow    │     │ AssumeRole +    │
│  access"        │     │ SourceIdentity:  │     │ SourceIdentity  │
│                 │     │ sentinel:alice:  │     │ validated by    │
│                 │     │ a1b2c3d4         │     │ trust policy    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Enforcement CLI Commands

Sentinel provides CLI commands to analyze and generate trust policies for enforcement.

### sentinel enforce plan

Analyze role trust policies for Sentinel enforcement status.

**Usage:**

```bash
sentinel enforce plan --role=ROLE_ARN [--role=ROLE_ARN...] [--region=REGION] [--json]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--role` | Role ARN to analyze (repeatable) | Yes |
| `--region` | AWS region for IAM operations | No |
| `--json` | Output in JSON format | No |

**Example:**

```bash
sentinel enforce plan --role=arn:aws:iam::123456789012:role/ProductionAdmin
```

**Output:**

```
Sentinel Enforcement Analysis
=============================

Role: arn:aws:iam::123456789012:role/ProductionAdmin
Status: FULL ✓
Level: trust-policy
Recommendations:
  - Role is fully enforced for Sentinel access

Summary
-------
Full enforcement:    1 role(s)
Partial enforcement: 0 role(s)
No enforcement:      0 role(s)
```

**Status Levels:**

| Status | Symbol | Meaning |
|--------|--------|---------|
| FULL | ✓ | Role requires Sentinel SourceIdentity for all access |
| PARTIAL | ⚠ | Some statements require Sentinel, others don't |
| NONE | ✗ | Role has no Sentinel enforcement |
| ERROR | - | Failed to analyze (check permissions) |

### sentinel enforce generate trust-policy

Generate IAM trust policy JSON with Sentinel conditions.

**Usage:**

```bash
sentinel enforce generate trust-policy --pattern=PATTERN --principal=ARN [--users=USER...] [--legacy-principal=ARN]
```

**Flags:**

| Flag | Description | Required |
|------|-------------|----------|
| `--pattern` | Pattern: `any-sentinel`, `specific-users`, or `migration` | Yes |
| `--principal` | AWS principal ARN (e.g., `arn:aws:iam::123456789012:root`) | Yes |
| `--users` | Username for `specific-users` pattern (repeatable) | For `specific-users` |
| `--legacy-principal` | Legacy principal ARN for `migration` pattern | For `migration` |

**Pattern A: Any Sentinel Credentials**

Allow any credentials issued by Sentinel:

```bash
sentinel enforce generate trust-policy \
  --pattern=any-sentinel \
  --principal=arn:aws:iam::123456789012:root
```

Output:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSentinelAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

**Pattern B: Specific Users via Sentinel**

Allow only specific users (via Sentinel):

```bash
sentinel enforce generate trust-policy \
  --pattern=specific-users \
  --principal=arn:aws:iam::123456789012:root \
  --users=alice \
  --users=bob
```

Output:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSentinelUsers",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": ["sentinel:alice:*", "sentinel:bob:*"]
        }
      }
    }
  ]
}
```

**Pattern C: Migration (Sentinel OR Legacy)**

Allow both Sentinel and legacy access during migration:

```bash
sentinel enforce generate trust-policy \
  --pattern=migration \
  --principal=arn:aws:iam::123456789012:root \
  --legacy-principal=arn:aws:iam::123456789012:role/LegacyServiceRole
```

Output:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSentinelAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    },
    {
      "Sid": "AllowLegacyAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/LegacyServiceRole"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Trust Policy Patterns

Trust policies define who can assume a role. Adding `sts:SourceIdentity` conditions makes Sentinel enforcement mandatory for that role.

### Pattern A: Require ANY Sentinel-Issued Credentials

Allow any credentials issued by Sentinel, regardless of which user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

**Use case**: Basic enforcement - ensure all access goes through Sentinel policy evaluation.

### Pattern B: Require Sentinel AND Specific Users

Allow only specific users (via Sentinel) to assume the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": ["sentinel:alice:*", "sentinel:bob:*"]
        }
      }
    }
  ]
}
```

**Use case**: Sensitive roles where both Sentinel policy AND IAM trust policy must agree on allowed users.

### Pattern C: Allow Sentinel OR Legacy (Migration Period)

During migration, allow both Sentinel-issued credentials and legacy access paths:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSentinelAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    },
    {
      "Sid": "AllowLegacyAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/LegacyServiceRole"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Use case**: Gradual rollout - allow legacy paths while teams migrate to Sentinel.

## Important Notes

### Condition Key

The correct condition key is `sts:SourceIdentity` (not `aws:SourceIdentity`). Using the wrong key will silently fail to enforce.

### StringLike vs StringEquals

Use `StringLike` for wildcard matching. `StringEquals` requires exact match and won't work with the `sentinel:*` pattern.

### Propagation Delay

Trust policy changes take effect immediately - there is no propagation delay like IAM policy changes.

### Cross-Account Roles

For cross-account roles, the principal must match the account making the AssumeRole call:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

## SCP Patterns

Service Control Policies (SCPs) provide organization-wide enforcement. Unlike trust policies (which are per-role), SCPs apply across all accounts in an OU or organization.

### Pattern A: Deny AssumeRole Without Sentinel (Strict)

Block all role assumptions that don't have a Sentinel SourceIdentity:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireSentinelSourceIdentity",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

**Use case**: Full enforcement - all human access must go through Sentinel.

### Pattern B: Deny Only for Sensitive Roles (Targeted)

Require Sentinel only for production and admin roles:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireSentinelForProductionRoles",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::*:role/Production*",
        "arn:aws:iam::*:role/*Admin*"
      ],
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

**Use case**: Targeted enforcement - protect sensitive roles while allowing unrestricted access to development roles.

### Pattern C: Deny with Exceptions for Service Roles

Require Sentinel but allow AWS service-linked roles to operate normally:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireSentinelExceptServiceRoles",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/aws-service-role/*",
            "arn:aws:iam::*:role/AWSServiceRole*"
          ]
        }
      }
    }
  ]
}
```

**Use case**: Full enforcement with service exceptions - Sentinel required for human access, AWS services can operate normally.

## SCP Considerations

### SCPs Cannot Grant Permissions

SCPs only restrict - they cannot grant permissions. The SCP patterns above deny access when conditions aren't met, but you still need appropriate trust policies for the Allow.

### SCP Evaluation Order

SCP evaluation happens BEFORE IAM policies:

```
Request → SCP evaluation → IAM Policy evaluation → Resource Policy evaluation
```

If an SCP denies, IAM policies are never evaluated.

### Apply to OU or Account Level

SCPs are attached via AWS Organizations:

```bash
# Attach SCP to an OU
aws organizations attach-policy \
  --policy-id p-xxxxxx \
  --target-id ou-xxxx-xxxxxxxx

# Attach SCP to a specific account
aws organizations attach-policy \
  --policy-id p-xxxxxx \
  --target-id 123456789012
```

### Service-Linked Role Exceptions

AWS service-linked roles (used by services like Auto Scaling, RDS, etc.) don't set SourceIdentity. Always include exceptions for:

- `arn:aws:iam::*:role/aws-service-role/*`
- `arn:aws:iam::*:role/AWSServiceRole*`

### Test in Non-Production First

SCPs can break critical services if misconfigured. Always:

1. Test in a sandbox OU first
2. Verify service-linked roles still work
3. Monitor CloudTrail for access denied events
4. Have a rollback plan ready

## Deployment Guide

A progressive rollout strategy for enabling Sentinel enforcement.

### Phase 1: Audit Mode (1-2 weeks)

Deploy Sentinel in advisory mode without any enforcement policies.

**Goals:**
- Verify Sentinel is issuing credentials correctly
- Review decision logs to identify access patterns
- Confirm SourceIdentity appears in CloudTrail

**Steps:**
1. Configure Sentinel with your policy rules
2. Update `~/.aws/config` to use `credential_process = sentinel credentials --profile X`
3. Monitor `/var/log/sentinel/decisions.log` for allow/deny decisions
4. Query CloudTrail to verify SourceIdentity stamping:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="sentinel:*" \
  --start-time "$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ)" | jq '.Events | length'
```

**Success criteria:**
- All user access flows through Sentinel
- Decision logs show expected allow/deny patterns
- CloudTrail events include Sentinel SourceIdentity

### Phase 2: Pilot Enforcement (1-2 weeks)

Enable enforcement on a low-risk role to validate the mechanism.

**Goals:**
- Confirm trust policy enforcement works correctly
- Identify any edge cases or integration issues
- Build confidence before expanding

**Steps:**
1. Select a low-risk role (e.g., development environment read-only)
2. Check current enforcement status:

```bash
sentinel enforce plan --role=arn:aws:iam::123456789012:role/DevReadOnly
```

3. Generate a trust policy with Sentinel enforcement:

```bash
sentinel enforce generate trust-policy \
  --pattern=any-sentinel \
  --principal=arn:aws:iam::123456789012:root > trust-policy.json
```

4. Update the role's trust policy:

```bash
aws iam update-assume-role-policy \
  --role-name DevReadOnly \
  --policy-document file://trust-policy.json
```

5. Verify enforcement is active:

```bash
sentinel enforce plan --role=arn:aws:iam::123456789012:role/DevReadOnly
# Should show: Status: FULL
```

6. Test access through Sentinel (should succeed)
7. Test access without Sentinel (should fail with AccessDenied)
8. Verify with CloudTrail audit:

```bash
sentinel audit verify \
  --start=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ) \
  --end=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --role=arn:aws:iam::123456789012:role/DevReadOnly
```

**Success criteria:**
- Sentinel-issued credentials can assume the role
- Non-Sentinel credentials are rejected
- No unexpected disruptions

### Phase 3: Expand to Sensitive Roles

Enable enforcement on production and admin roles.

**Goals:**
- Protect sensitive access paths
- Maintain migration period for legacy access if needed

**Steps:**
1. Identify sensitive roles requiring protection:
   - Production access roles
   - Admin/privileged roles
   - Cross-account roles

2. For each role, choose the appropriate pattern:
   - Pattern A: Require any Sentinel credentials
   - Pattern B: Require Sentinel + specific users (for highly sensitive roles)
   - Pattern C: Migration mode (if legacy access must continue temporarily)

3. Update trust policies incrementally
4. Monitor CloudTrail for access denied events:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)" | \
  jq '.Events[].CloudTrailEvent | fromjson | select(.errorCode == "AccessDenied")'
```

**Success criteria:**
- All sensitive roles require Sentinel
- Legacy migration paths documented and time-boxed
- No critical workflows disrupted

### Phase 4: Organization-Wide SCP (Optional)

Apply SCP-level enforcement across the organization.

**Goals:**
- Defense in depth beyond individual trust policies
- Catch roles that weren't updated with trust policy enforcement
- Organizational-level audit and compliance

**Steps:**
1. Create the SCP in AWS Organizations:

```bash
aws organizations create-policy \
  --name "RequireSentinelSourceIdentity" \
  --description "Require Sentinel SourceIdentity for role assumptions" \
  --type SERVICE_CONTROL_POLICY \
  --content file://sentinel-scp.json
```

2. Attach to a test OU first:

```bash
aws organizations attach-policy \
  --policy-id p-xxxxxx \
  --target-id ou-xxxx-sandbox
```

3. Verify all workflows in the test OU continue working
4. Expand to production OUs
5. Optionally attach to organization root for full enforcement

**Success criteria:**
- SCP active across target OUs/accounts
- Service-linked roles exempted and functioning
- Clear audit trail of enforcement

## Drift Detection

Sentinel can detect when roles lack proper trust policy enforcement at credential issuance time. This provides early warning that credentials may work even without Sentinel, indicating incomplete enforcement.

### Enabling Drift Detection

Add the `--require-sentinel` flag to the credentials command:

```bash
sentinel credentials --profile prod --require-sentinel
```

Or configure in your AWS config:

```ini
[profile prod]
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/default --require-sentinel
```

### Drift Status Values

| Status | Meaning |
|--------|---------|
| `ok` | Role has full Sentinel enforcement |
| `partial` | Role has partial enforcement (some statements missing condition) |
| `none` | Role has no Sentinel enforcement |
| `unknown` | Check failed (IAM permissions, role doesn't exist) |

### Warning Output

When drift is detected, warnings are written to stderr (credentials still issued):

**Partial enforcement:**
```
Warning: Role arn:aws:iam::123456789012:role/MyRole has partial Sentinel enforcement (Some statements allow access without Sentinel SourceIdentity)
```

**No enforcement:**
```
Warning: Role arn:aws:iam::123456789012:role/MyRole has no Sentinel enforcement (Add sts:SourceIdentity condition to trust policy)
```

**Unknown status:**
```
Warning: Could not verify Sentinel enforcement for arn:aws:iam::123456789012:role/MyRole: access denied
```

### Decision Log Fields

When `--require-sentinel` is enabled, drift status is recorded in decision logs:

```json
{
  "timestamp": "2026-01-16T10:30:00Z",
  "user": "alice",
  "profile": "production",
  "effect": "allow",
  "drift_status": "partial",
  "drift_message": "Some statements allow access without Sentinel SourceIdentity"
}
```

| Field | Description | Present |
|-------|-------------|---------|
| `drift_status` | Status value (`ok`, `partial`, `none`, `unknown`) | When --require-sentinel |
| `drift_message` | Human-readable explanation | When --require-sentinel |

### Advisory Mode

Drift detection is **advisory only** - credentials are always issued regardless of drift status. This allows teams to:

1. Deploy Sentinel without breaking existing workflows
2. Monitor drift status via decision logs
3. Progressively remediate trust policies
4. Avoid credential failures during migration

To enforce Sentinel, use trust policy conditions as documented above.

## Troubleshooting

### AccessDenied When Assuming Role

**Symptom:** AssumeRole fails with AccessDenied even though the user is authorized.

**Checks:**

1. **Is Sentinel being used?**
   ```bash
   # Verify credential_process is configured
   grep -A5 "profile production" ~/.aws/config
   # Should show: credential_process = sentinel credentials --profile production
   ```

2. **Is the condition key correct?**
   ```bash
   # Get the trust policy
   aws iam get-role --role-name MyRole --query 'Role.AssumeRolePolicyDocument'
   # Verify it uses sts:SourceIdentity (not aws:SourceIdentity)
   ```

3. **Is StringLike used for wildcards?**
   ```bash
   # Check for StringLike vs StringEquals
   # StringEquals won't match sentinel:alice:a1b2c3d4 against sentinel:*
   ```

4. **Does the Sentinel log show allow?**
   ```bash
   # Check recent decision logs
   tail -10 /var/log/sentinel/decisions.log | jq 'select(.effect == "deny")'
   ```

### SCP Blocking Service Roles

**Symptom:** AWS services fail with permission errors after enabling SCP enforcement.

**Checks:**

1. **Identify the failing service:**
   ```bash
   # Find access denied events in CloudTrail
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
     --start-time "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)" | \
     jq '.Events[].CloudTrailEvent | fromjson | select(.errorCode != null) | {principal: .userIdentity.arn, error: .errorCode}'
   ```

2. **Add service role exceptions to SCP:**
   - Include `ArnNotLike` condition for `aws-service-role/*` patterns
   - See Pattern C in SCP Patterns section

3. **Common service roles to exempt:**
   - `arn:aws:iam::*:role/aws-service-role/*`
   - `arn:aws:iam::*:role/AWSServiceRole*`
   - CI/CD pipeline roles (if not using Sentinel)

### SourceIdentity Not Appearing in CloudTrail

**Symptom:** CloudTrail events don't show the Sentinel SourceIdentity.

**Checks:**

1. **Did AssumeRole succeed?**
   ```bash
   # SourceIdentity is only stamped on successful AssumeRole
   # Check for errors in Sentinel logs
   tail -20 /var/log/sentinel/decisions.log | jq 'select(.effect == "allow")'
   ```

2. **Are you looking at the right events?**
   ```bash
   # SourceIdentity appears in userIdentity.sourceIdentity field
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue="sentinel:alice:a1b2c3d4" \
     --start-time "2024-01-15T00:00:00Z"
   ```

3. **Is CloudTrail configured correctly?**
   - Management events are logged by default
   - Data events (S3 object-level, Lambda) require explicit configuration
   - Check trail configuration for event selectors

4. **Is there CloudTrail delivery delay?**
   - CloudTrail events can take up to 15 minutes to appear
   - Use `lookup-events` for recent events (last 90 days)
   - Use Athena for historical queries

## Security Considerations

### Credential Process Control

Sentinel's effectiveness depends on controlling the `credential_process` path. If users can bypass Sentinel:

- **Direct IAM user credentials** - Users with IAM access keys can call AssumeRole directly without Sentinel
- **Other credential providers** - Environment variables, instance profiles, or other credential sources

**Mitigations:**
- Remove IAM user access keys where possible
- Use IAM policies to restrict who can call AssumeRole directly
- SCPs provide defense-in-depth by enforcing at the organization level

### Trust Policy vs SCP Enforcement

| Aspect | Trust Policy | SCP |
|--------|--------------|-----|
| Scope | Per-role | Per-OU or organization |
| Management | IAM (decentralized) | Organizations (centralized) |
| Bypass | Another statement can allow | Cannot be bypassed by IAM |
| Service roles | Handled automatically | Need explicit exceptions |

**Recommendation:** Use both for defense-in-depth:
- Trust policies for per-role user restrictions
- SCPs for organization-wide enforcement baseline

### SourceIdentity Spoofing

Can someone spoof a Sentinel SourceIdentity to bypass enforcement?

**No**, because:
1. SourceIdentity can only be set by the caller of AssumeRole
2. The caller must have valid credentials to call AssumeRole
3. Trust policies control who can assume the role in the first place

The only way to set `sentinel:alice:*` as SourceIdentity is to call AssumeRole with credentials that the trust policy accepts. If the trust policy requires `sentinel:*` SourceIdentity, the caller must already have gone through Sentinel.

### Audit Trail Integrity

Sentinel logs (`/var/log/sentinel/decisions.log`) and CloudTrail provide complementary audit trails:

| Log Source | Contains | Integrity |
|------------|----------|-----------|
| Sentinel logs | Access decisions (allow/deny), policy rule matched | Local file - protect with file permissions |
| CloudTrail | AWS API calls with SourceIdentity | AWS-managed - tamper-evident |

**Recommendation:**
- Ship Sentinel logs to a centralized log aggregator (CloudWatch Logs, Splunk, etc.)
- Enable CloudTrail log file integrity validation
- Correlate both sources using request_id/source_identity
