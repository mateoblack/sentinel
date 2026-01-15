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
