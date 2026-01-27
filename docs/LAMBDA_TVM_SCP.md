# Lambda TVM Service Control Policy (SCP) Patterns

> **Note:** This document has been superseded by [SCP_REFERENCE.md](SCP_REFERENCE.md), which provides a comprehensive, consolidated reference for all SCP patterns, deployment guidance, and troubleshooting.

This guide covers AWS Service Control Policies (SCPs) for enforcing TVM-only access to protected roles.

## Why SCPs Matter for TVM Security

The TVM provides policy enforcement BEFORE credential issuance. However, TVM security is only effective if clients **cannot bypass it**. Without SCPs:

- Users with direct AssumeRole permissions could bypass the TVM entirely
- Protected roles could be assumed without Sentinel policy evaluation
- SourceIdentity stamping would be optional, breaking audit trails

SCPs enforce TVM-only access at the AWS control plane level, making bypass architecturally impossible.

## Basic Pattern: Deny Direct AssumeRole

Deny AssumeRole to protected roles except when called by the TVM Lambda:

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
- `Resource` uses wildcard to match all protected roles
- `aws:PrincipalArn` condition allows ONLY the TVM execution role
- Replace `ACCOUNT` with your AWS account ID

## Advanced Pattern: Lambda Service Principal

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

## Multi-Account Pattern: Organization-Wide SCP

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

## Approval-Required Pattern

Enforce that credentials only come through approved requests:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireApprovedAccess",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelApprovalRequired-*",
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*:????????:*"
        }
      }
    }
  ]
}
```

This pattern requires the SourceIdentity to contain an approval marker (8-char hex), blocking direct access that bypasses approval workflows.

## Testing Your SCP

### 1. Verify SCP allows TVM

```bash
# From TVM Lambda or with TVM execution role credentials
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
  --role-session-name test \
  --source-identity "sentinel:test:direct:test123"

# Should succeed
```

### 2. Verify SCP blocks direct access

```bash
# From user credentials (not TVM)
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/SentinelProtected-Production \
  --role-session-name test

# Should fail with: AccessDenied
```

### 3. Check CloudTrail for violations

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query "Events[?contains(CloudTrailEvent, 'SentinelProtected') && contains(CloudTrailEvent, 'AccessDenied')]"
```

## Common Mistakes

### Mistake 1: Forgetting to allow the TVM itself

```json
// WRONG - blocks everyone including TVM
{
  "Effect": "Deny",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/SentinelProtected-*"
}
```

Always include the `StringNotEquals` condition for the TVM execution role.

### Mistake 2: Wrong principal ARN format

```json
// WRONG - using role name instead of full ARN
"aws:PrincipalArn": "SentinelTVMExecutionRole"

// CORRECT - full ARN
"aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
```

### Mistake 3: Not testing before applying

Always test SCPs in a sandbox account or with a single test role before applying organization-wide.

## Gradual Rollout Strategy

### Phase 1: Audit Mode (No Deny)

Monitor who's calling AssumeRole without blocking:

```bash
# Create CloudTrail metric filter for direct AssumeRole
aws logs put-metric-filter \
  --log-group-name CloudTrail/logs \
  --filter-name DirectAssumeRole \
  --filter-pattern '{ $.eventName = "AssumeRole" && $.userIdentity.arn != "*SentinelTVMExecutionRole*" }' \
  --metric-transformations metricName=DirectAssumeRoleCount,metricNamespace=Sentinel,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name DirectAssumeRoleAlert \
  --metric-name DirectAssumeRoleCount \
  --namespace Sentinel \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold
```

### Phase 2: Identify Violators

Review CloudTrail for direct AssumeRole calls:

```bash
# Find users calling AssumeRole directly
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -d '7 days ago' --iso-8601) \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .userIdentity.arn | contains("SentinelTVM") | not)'
```

### Phase 3: Apply Deny SCP

After confirming all legitimate access goes through TVM:

1. Create SCP with deny statement
2. Attach to test OU first
3. Validate TVM still works
4. Attach to production OUs

## See Also

- [LAMBDA_TVM_DEPLOYMENT.md](LAMBDA_TVM_DEPLOYMENT.md) - Full deployment guide
- [AWS SCP Documentation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
