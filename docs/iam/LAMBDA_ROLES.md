# Lambda TVM IAM Roles

IAM role templates for deploying Sentinel Lambda Token Vending Machine (TVM).

## Overview

The Lambda TVM architecture uses two types of IAM roles:

1. **Lambda Execution Role** - The role Lambda assumes to run the TVM function
2. **Protected Roles** - The roles that Lambda assumes on behalf of users

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Client         │────>│  Lambda TVM      │────>│  Protected Role │
│                 │     │                  │     │                 │
│ Authenticated   │     │ Lambda Execution │     │ Trust: Lambda   │
│ request         │     │ Role             │     │ execution role  │
│                 │     │                  │     │ ONLY            │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

**Critical security principle:** Protected roles must ONLY trust the Lambda execution role. This ensures:

- Clients cannot call AssumeRole directly to bypass policy enforcement
- All credential requests flow through Lambda's policy evaluation
- SourceIdentity stamping is mandatory (Lambda sets it)
- Audit trail is complete (every credential traced to Lambda request)

If protected roles trust other principals (users, other roles), clients can bypass the TVM entirely and obtain credentials without policy checks.

## Lambda Execution Role

The Lambda TVM needs an execution role with permissions to:
- Assume protected roles (sts:AssumeRole)
- Write logs (CloudWatch Logs)

### Minimum IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeProtectedRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sentinel-tvm*"
    }
  ]
}
```

**Notes:**
- The `AssumeProtectedRoles` statement uses a wildcard on `SentinelProtected-*` to allow assuming any protected role following the naming convention
- For tighter security, list specific role ARNs instead of wildcards
- Cross-account: If protected roles are in different accounts, include those account IDs in the resource ARN

### Trust Policy (for Lambda Service)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

This allows the AWS Lambda service to assume this role when executing the TVM function.

## Protected Role Trust Policies

Protected roles MUST only trust the Lambda execution role. This is the key security control that prevents clients from calling AssumeRole directly.

### Trust Policy Template

Replace `LAMBDA_ROLE_ARN` with your Lambda execution role ARN.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "LAMBDA_ROLE_ARN"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*:*:*"
        }
      }
    }
  ]
}
```

**Example with specific Lambda role:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SentinelTVMLambda"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*:*:*"
        }
      }
    }
  ]
}
```

### SourceIdentity Condition

The `sts:SourceIdentity` condition ensures only Sentinel-stamped credentials work. Lambda TVM sets this value when calling AssumeRole.

**Format:** `sentinel:<user>:<approval-marker>:<request-id>`

| Component | Description | Example |
|-----------|-------------|---------|
| `sentinel` | Fixed prefix | `sentinel` |
| `user` | Authenticated username | `alice` |
| `approval-marker` | `direct` or 8-char hex approval ID | `direct`, `abcd1234` |
| `request-id` | Unique request identifier | `f7e8d9c0` |

**Condition patterns:**

| Pattern | Matches | Use Case |
|---------|---------|----------|
| `sentinel:*:*:*` | All Sentinel credentials | Basic enforcement |
| `sentinel:alice:*:*` | Specific user only | User-restricted role |
| `sentinel:*:????????:*` | Approved access only | Require approval workflow |

**Approved-only access:**

For roles that should only be accessible via approved requests (not direct access):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SentinelTVMLambda"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        },
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*:direct:*"
        }
      }
    }
  ]
}
```

## Naming Conventions

Recommended naming for TVM-protected roles:

| Pattern | Example | Use Case |
|---------|---------|----------|
| `SentinelProtected-<profile>` | `SentinelProtected-prod` | Standard protected role |
| `SentinelProtected-<env>-<level>` | `SentinelProtected-prod-admin` | Environment + access level |
| `SentinelProtected-<team>-<env>` | `SentinelProtected-platform-staging` | Team-scoped role |

**Benefits:**
- Clearly identifies Sentinel-managed roles
- Enables wildcard policies on the Lambda execution role (`SentinelProtected-*`)
- Supports resource-based filtering in CloudTrail queries
- Easy to distinguish from other IAM roles

**Lambda execution role naming:**
- `SentinelTVMLambda` - Single TVM deployment
- `SentinelTVMLambda-<env>` - Per-environment TVM (e.g., `SentinelTVMLambda-prod`)

## Security Considerations

### Why Protected Roles Must NOT Allow Direct AssumeRole

If a protected role trusts users directly:

```
BAD: User can bypass Lambda TVM
┌─────────────────┐                    ┌─────────────────┐
│  User           │───────────────────>│  Protected Role │
│                 │  Direct AssumeRole │                 │
│ (No policy      │  (No SourceIdentity│ Trust: User     │
│  enforcement)   │   No audit trail)  │                 │
└─────────────────┘                    └─────────────────┘
```

This defeats the purpose of the TVM:
- No policy evaluation
- No SourceIdentity stamping
- No centralized audit
- No approval workflow enforcement

### Auditing Existing Trust Policies

Check if roles allow principals other than Lambda:

```bash
# List trust policy for a role
aws iam get-role --role-name SentinelProtected-prod \
  --query 'Role.AssumeRolePolicyDocument' \
  --output json | jq .

# Check for non-Lambda principals
aws iam get-role --role-name SentinelProtected-prod \
  --query 'Role.AssumeRolePolicyDocument.Statement[].Principal' \
  --output json
```

**Red flags in trust policies:**
- `Principal.AWS` pointing to users or non-Lambda roles
- Missing `sts:SourceIdentity` condition
- `Principal.AWS: "*"` (allows anyone)

### SCPs to Block Direct AssumeRole

For defense-in-depth, use SCPs to prevent direct AssumeRole to protected roles. This catches misconfigured trust policies.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireLambdaTVMForProtectedRoles",
      "Effect": "Deny",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SentinelProtected-*",
      "Condition": {
        "StringNotLike": {
          "sts:SourceIdentity": "sentinel:*"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/SentinelTVMLambda*"
        }
      }
    }
  ]
}
```

This SCP:
- Denies AssumeRole to `SentinelProtected-*` roles
- Unless the caller has a `sentinel:*` SourceIdentity
- Or the caller is the Lambda TVM role itself

See [ENFORCEMENT.md](../ENFORCEMENT.md) for comprehensive SCP patterns.

## Terraform Example

A brief example for reference. Full Terraform module in Phase 102 (Infrastructure as Code).

```hcl
# Lambda execution role
resource "aws_iam_role" "sentinel_tvm" {
  name = "SentinelTVMLambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

# Lambda execution policy
resource "aws_iam_role_policy" "sentinel_tvm" {
  name = "SentinelTVMPolicy"
  role = aws_iam_role.sentinel_tvm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeProtectedRoles"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/SentinelProtected-*"
      },
      {
        Sid      = "CloudWatchLogs"
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/sentinel-tvm*"
      }
    ]
  })
}

# Protected role (example)
resource "aws_iam_role" "protected" {
  name = "SentinelProtected-prod-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = aws_iam_role.sentinel_tvm.arn }
      Action = "sts:AssumeRole"
      Condition = {
        StringLike = { "sts:SourceIdentity" = "sentinel:*:*:*" }
      }
    }]
  })
}

# Attach permissions to protected role (example: admin)
resource "aws_iam_role_policy_attachment" "protected_admin" {
  role       = aws_iam_role.protected.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

## Cross-Account Setup

For cross-account deployments where Lambda TVM is in one account and protected roles are in another:

### Lambda Execution Role (Account A)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeProtectedRolesInAccountB",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::ACCOUNT_B_ID:role/SentinelProtected-*"
    }
  ]
}
```

### Protected Role Trust Policy (Account B)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_A_ID:role/SentinelTVMLambda"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*:*:*"
        }
      }
    }
  ]
}
```

## Verification Checklist

Before deploying Lambda TVM:

- [ ] Lambda execution role created with correct trust policy (Lambda service)
- [ ] Lambda execution role has AssumeRole permission for protected roles
- [ ] Lambda execution role has CloudWatch Logs permissions
- [ ] Protected roles trust ONLY the Lambda execution role
- [ ] Protected roles have SourceIdentity condition
- [ ] No protected roles trust users or other principals directly
- [ ] Naming convention followed consistently
- [ ] Cross-account roles configured (if applicable)
- [ ] SCP defense-in-depth applied (optional)

## Related Documentation

- [ENFORCEMENT.md](../ENFORCEMENT.md) - Trust policies and SCPs for mandatory Sentinel usage
- [ASSURANCE.md](../ASSURANCE.md) - Verifying Sentinel enforcement in your environment
- [CLOUDTRAIL.md](../CLOUDTRAIL.md) - Correlating Sentinel logs with AWS activity
