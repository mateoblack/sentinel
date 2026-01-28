# SCP Reference Guide for Sentinel

This guide provides Service Control Policy (SCP) templates for enforcing Sentinel-only access to protected AWS roles.

## Table of Contents

1. [Introduction](#introduction)
2. [SCP Templates](#scp-templates)
3. [Deployment Guidance](#deployment-guidance)
4. [Troubleshooting](#troubleshooting)

---

## Introduction

### What are SCPs?

Service Control Policies (SCPs) are AWS Organizations policies that define the maximum available permissions for member accounts. SCPs don't grant permissions; they set guardrails that restrict what actions can be performed, even if IAM policies would otherwise allow them.

### Why SCPs Matter for Sentinel Security

Sentinel provides policy enforcement BEFORE credential issuance. However, Sentinel security is only effective if clients **cannot bypass it**. Without SCPs:

- Users with direct `sts:AssumeRole` permissions could bypass Sentinel entirely
- Protected roles could be assumed without Sentinel policy evaluation
- SourceIdentity stamping would be optional, breaking audit trails

SCPs enforce Sentinel-only access at the AWS control plane level, making bypass architecturally impossible.

### When to Use SCPs vs. IAM Trust Policies

| Approach | Scope | Use When |
|----------|-------|----------|
| **SCPs** | Organization-wide | You want to enforce Sentinel across all accounts in an OU |
| **IAM Trust Policies** | Per-role | You want selective enforcement on specific roles |
| **Both** | Defense in depth | Maximum security for production environments |

**Recommendation:** Use both SCPs and trust policies for defense in depth. SCPs prevent bypass at the organization level, while trust policies enforce constraints at the role level.

---

## SCP Templates

### Basic Pattern: Deny Direct AssumeRole

Deny `sts:AssumeRole` to protected roles except when called by the Sentinel TVM Lambda:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectAssumeRole",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
        }
      }
    }
  ]
}
```

**Key points:**
- `Resource` uses wildcard to match all protected roles (customize prefix as needed)
- `aws:PrincipalArn` condition allows ONLY the TVM execution role
- Replace `ACCOUNT` with your AWS account ID

### Advanced Pattern: Lambda Service Principal

For stricter enforcement, combine principal ARN with Lambda service conditions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectAssumeRoleStrict",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
        },
        "StringNotEqualsIfExists": {
          "aws:PrincipalServiceName": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

This ensures the call originates from Lambda, not from compromised credentials.

### Multi-Account Pattern: Organization-Wide SCP

For AWS Organizations with a centralized TVM in a security account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectAssumeRoleOrgWide",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::SECURITY_ACCOUNT:role/SentinelTVMExecutionRole"
        }
      }
    }
  ]
}
```

**Cross-account setup:**
1. Deploy TVM in security account
2. Protected roles in workload accounts trust security account's execution role
3. Attach SCP to organization root or target OUs

### SourceIdentity Enforcement SCP

Require that all AssumeRole calls include a Sentinel-formatted SourceIdentity:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireSentinelSourceIdentity",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    }
  ]
}
```

This pattern blocks any AssumeRole that doesn't have a SourceIdentity starting with `sentinel:`, ensuring all sessions go through Sentinel.

### Time-Bound Access SCP (Business Hours Only)

Restrict credential issuance to business hours for additional security:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideBusinessHours",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-Production-*",
      "Condition": {
        "DateGreaterThan": {
          "aws:CurrentTime": "2026-01-01T18:00:00Z"
        },
        "DateLessThan": {
          "aws:CurrentTime": "2026-01-02T06:00:00Z"
        }
      }
    }
  ]
}
```

**Note:** Time-based SCPs are complex due to UTC handling. Consider using Sentinel's built-in time window policy conditions instead for more flexible time-based access control.

### Emergency Break-Glass Pattern

Allow break-glass access to bypass SCPs in emergencies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDirectAssumeRoleWithBreakGlass",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole",
            "arn:aws:iam::ACCOUNT:role/BreakGlassRole"
          ]
        }
      }
    }
  ]
}
```

**Important:** Break-glass roles should:
- Require MFA
- Have CloudTrail alerting
- Be audited regularly
- Use separate physical access controls (hardware tokens)

---

## Deployment Guidance

### Using `sentinel scp template`

Generate SCP templates for your environment:

```bash
# Generate basic SCP template
sentinel scp template \
  --tvm-role-arn arn:aws:iam::123456789012:role/SentinelTVMExecutionRole \
  --protected-prefix "SentinelProtected-" \
  --output scp-policy.json

# Generate with SourceIdentity enforcement
sentinel scp template \
  --tvm-role-arn arn:aws:iam::123456789012:role/SentinelTVMExecutionRole \
  --require-source-identity \
  --output scp-policy.json

# Include break-glass role exception
sentinel scp template \
  --tvm-role-arn arn:aws:iam::123456789012:role/SentinelTVMExecutionRole \
  --break-glass-arn arn:aws:iam::123456789012:role/BreakGlassRole \
  --output scp-policy.json
```

### Testing SCPs in Isolated OUs

**Always test SCPs before applying organization-wide:**

1. **Create Test OU:**
   ```bash
   aws organizations create-organizational-unit \
     --parent-id r-xxxx \
     --name "SCP-Testing"
   ```

2. **Move Test Account:**
   ```bash
   aws organizations move-account \
     --account-id 111111111111 \
     --source-parent-id r-xxxx \
     --destination-parent-id ou-xxxx-testou
   ```

3. **Create and Attach SCP:**
   ```bash
   aws organizations create-policy \
     --name "SentinelEnforcement-Test" \
     --description "Test Sentinel-only access enforcement" \
     --type SERVICE_CONTROL_POLICY \
     --content file://scp-policy.json

   aws organizations attach-policy \
     --policy-id p-xxxxxxxxxx \
     --target-id ou-xxxx-testou
   ```

4. **Verify TVM Still Works:**
   ```bash
   # Request credentials through Sentinel
   sentinel credentials --profile test-profile
   # Should succeed
   ```

5. **Verify Direct Access Blocked:**
   ```bash
   # Try direct AssumeRole (should fail)
   aws sts assume-role \
     --role-arn arn:aws:iam::111111111111:role/SentinelProtected-Test \
     --role-session-name test
   # Should return AccessDenied
   ```

### Deprecated: `sentinel scp deploy`

**Warning:** The `sentinel scp deploy` command has been deprecated and removed in v1.21.

**Reason:** Direct SCP deployment from CLI poses risks:
- SCPs have immediate, organization-wide impact
- Mistakes can lock out entire accounts
- No approval workflow for such impactful changes

**Recommended Approach:**
1. Use `sentinel scp template` to generate policy JSON
2. Review the policy in version control
3. Apply through your organization's change management process
4. Test in isolated OU first
5. Gradually roll out to production OUs

---

## Troubleshooting

### Common SCP Evaluation Errors

#### Error: "User: arn:aws:... is not authorized to perform: sts:AssumeRole"

**Possible Causes:**
1. SCP is blocking the request
2. Trust policy doesn't allow the caller
3. IAM policy doesn't grant AssumeRole

**Diagnosis:**
```bash
# Check if SCP is the cause - SCPs show as "Explicit deny" in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query "Events[?contains(CloudTrailEvent, 'AccessDenied')]" \
  | jq '.[] | .CloudTrailEvent | fromjson | {errorCode, errorMessage}'
```

#### Error: TVM Can't Assume Protected Roles

**Diagnosis:**
```bash
# Verify TVM execution role ARN matches SCP exception
aws lambda get-function-configuration \
  --function-name SentinelTVM \
  --query "Role"

# Should match exactly what's in the SCP condition
```

**Fix:** Ensure the TVM execution role ARN in the SCP exactly matches the deployed Lambda's role ARN, including account ID.

### How to Verify SCP is Working

#### 1. Verify TVM Access (Should Succeed)

```bash
# From TVM Lambda or with TVM execution role credentials
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
  --role-session-name test \
  --source-identity "sentinel:test:direct:test123"

# Should succeed and return credentials
```

#### 2. Verify Direct Access Blocked (Should Fail)

```bash
# From user credentials (not TVM)
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
  --role-session-name test

# Should fail with: AccessDenied
```

#### 3. Check CloudTrail for SCP Violations

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query "Events[?contains(CloudTrailEvent, 'SentinelProtected') && contains(CloudTrailEvent, 'AccessDenied')]"
```

### Common Mistakes to Avoid

#### Mistake 1: Forgetting to Allow the TVM

```json
// WRONG - blocks everyone including TVM
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/SentinelProtected-*"
}
```

**Fix:** Always include the `StringNotEquals` condition for the TVM execution role.

#### Mistake 2: Wrong Principal ARN Format

```json
// WRONG - using role name instead of full ARN
"aws:PrincipalArn": "SentinelTVMExecutionRole"

// CORRECT - full ARN
"aws:PrincipalArn": "arn:aws:iam::123456789012:role/SentinelTVMExecutionRole"
```

#### Mistake 3: Not Testing Before Applying

Always test SCPs in a sandbox account or isolated OU before applying organization-wide. SCP mistakes can lock out entire accounts.

---

## See Also

- [ENFORCEMENT.md](ENFORCEMENT.md) - IAM trust policy enforcement patterns
- [LAMBDA_TVM_DEPLOYMENT.md](LAMBDA_TVM_DEPLOYMENT.md) - Full TVM deployment guide
- [SECURITY.md](SECURITY.md) - Security advisories and hardening guide
- [AWS SCP Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)

---

*Last updated: 2026-01-27*
*Supersedes: docs/LAMBDA_TVM_SCP.md (consolidated into this reference)*
