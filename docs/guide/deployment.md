# Deployment Guide

Production setup for Sentinel including SSM, IAM, and multi-profile configuration.

## Overview

A production Sentinel deployment involves:

1. **SSM Parameter Store** - Policy storage
2. **IAM Policies** - Access control for Sentinel operations
3. **DynamoDB Tables** - Request and break-glass storage (optional)
4. **Trust Policies** - Enforcement (optional)
5. **Monitoring** - Logs and alerts

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Account                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │  SSM Parameter  │    │   DynamoDB      │                 │
│  │  Store          │    │   Tables        │                 │
│  │                 │    │                 │                 │
│  │ /sentinel/      │    │ sentinel-       │                 │
│  │   policies/     │    │   requests      │                 │
│  │     dev         │    │ sentinel-       │                 │
│  │     staging     │    │   breakglass    │                 │
│  │     prod        │    │                 │                 │
│  └────────┬────────┘    └────────┬────────┘                 │
│           │                      │                           │
│           v                      v                           │
│  ┌─────────────────────────────────────────────┐            │
│  │              Sentinel CLI                    │            │
│  │                                              │            │
│  │  credentials | exec | request | breakglass  │            │
│  └─────────────────────────────────────────────┘            │
│                         │                                    │
│                         v                                    │
│  ┌─────────────────────────────────────────────┐            │
│  │              AWS STS                         │            │
│  │                                              │            │
│  │  AssumeRole with SourceIdentity             │            │
│  └─────────────────────────────────────────────┘            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## SSM Parameter Store Setup

### Bootstrap Command

Create SSM parameters for your profiles:

```bash
# Preview changes
sentinel init bootstrap \
  --profile dev \
  --profile staging \
  --profile prod \
  --plan

# Apply changes
sentinel init bootstrap \
  --profile dev \
  --profile staging \
  --profile prod \
  --yes

# Verify status
sentinel init status
```

### Parameter Structure

Bootstrap creates one SSM parameter per profile:

| Parameter Path | Content |
|---------------|---------|
| `/sentinel/policies/dev` | Access policy YAML for dev |
| `/sentinel/policies/staging` | Access policy YAML for staging |
| `/sentinel/policies/prod` | Access policy YAML for prod |

### Custom Policy Root

For multi-tenant or environment separation:

```bash
sentinel init bootstrap \
  --profile myapp \
  --policy-root /myorg/sentinel/policies
```

This creates `/myorg/sentinel/policies/myapp`.

### Updating Policies

Edit policies via AWS CLI, Console, or Infrastructure as Code:

```bash
# Download
aws ssm get-parameter \
  --name /sentinel/policies/prod \
  --query 'Parameter.Value' \
  --output text > policy.yaml

# Edit policy.yaml

# Upload
aws ssm put-parameter \
  --name /sentinel/policies/prod \
  --value file://policy.yaml \
  --type String \
  --overwrite
```

## IAM Policies

### SentinelPolicyReader

Attach to roles that read policies (Sentinel CLI users):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyRead",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
      ]
    }
  ]
}
```

### SentinelPolicyAdmin

Attach to roles that manage policies (CI/CD, admins):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelPolicyAdmin",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "ssm:DeleteParameter",
        "ssm:AddTagsToResource",
        "ssm:RemoveTagsFromResource"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
      ]
    }
  ]
}
```

### SentinelRequestsAccess

For approval workflow features:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelRequestTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-requests",
        "arn:aws:dynamodb:*:*:table/sentinel-requests/index/*"
      ]
    }
  ]
}
```

### SentinelBreakGlassAccess

For break-glass features:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SentinelBreakGlassTable",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass",
        "arn:aws:dynamodb:*:*:table/sentinel-breakglass/index/*"
      ]
    }
  ]
}
```

### Restricting ARN Scope

For tighter security, specify region and account:

```json
"Resource": [
  "arn:aws:ssm:us-west-2:123456789012:parameter/sentinel/policies/*"
]
```

## DynamoDB Tables

### Requests Table

```bash
aws dynamodb create-table \
  --table-name sentinel-requests \
  --attribute-definitions \
    AttributeName=pk,AttributeType=S \
    AttributeName=sk,AttributeType=S \
    AttributeName=gsi1pk,AttributeType=S \
    AttributeName=gsi1sk,AttributeType=S \
  --key-schema \
    AttributeName=pk,KeyType=HASH \
    AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "gsi1",
        "KeySchema": [
          {"AttributeName": "gsi1pk", "KeyType": "HASH"},
          {"AttributeName": "gsi1sk", "KeyType": "RANGE"}
        ],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]' \
  --billing-mode PAY_PER_REQUEST
```

### Break-Glass Table

```bash
aws dynamodb create-table \
  --table-name sentinel-breakglass \
  --attribute-definitions \
    AttributeName=pk,AttributeType=S \
    AttributeName=sk,AttributeType=S \
    AttributeName=gsi1pk,AttributeType=S \
    AttributeName=gsi1sk,AttributeType=S \
  --key-schema \
    AttributeName=pk,KeyType=HASH \
    AttributeName=sk,KeyType=RANGE \
  --global-secondary-indexes \
    '[
      {
        "IndexName": "gsi1",
        "KeySchema": [
          {"AttributeName": "gsi1pk", "KeyType": "HASH"},
          {"AttributeName": "gsi1sk", "KeyType": "RANGE"}
        ],
        "Projection": {"ProjectionType": "ALL"}
      }
    ]' \
  --billing-mode PAY_PER_REQUEST
```

## Multi-Profile Configuration

### AWS Config

Configure each profile in `~/.aws/config`:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/dev

[profile staging]
credential_process = sentinel credentials --profile staging --policy-parameter /sentinel/policies/staging

[profile prod]
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod --log-file /var/log/sentinel/decisions.log
```

### Shared Parameters

Use a shared policy parameter for multiple profiles:

```ini
[profile dev]
credential_process = sentinel credentials --profile dev --policy-parameter /sentinel/policies/default

[profile staging]
credential_process = sentinel credentials --profile staging --policy-parameter /sentinel/policies/default

[profile prod]
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/default
```

The policy can contain rules for all profiles:

```yaml
version: "1"
rules:
  - name: dev-access
    effect: allow
    conditions:
      profiles: [dev]
      users: [alice, bob, charlie]

  - name: staging-access
    effect: allow
    conditions:
      profiles: [staging]
      users: [alice, bob]

  - name: prod-requires-approval
    effect: require_approval
    conditions:
      profiles: [prod]

  - name: default-deny
    effect: deny
    conditions: {}
```

## Trust Policy Enforcement

To make Sentinel mandatory (not just advisory), configure IAM trust policies.

### Generate Trust Policy

```bash
sentinel enforce generate trust-policy \
  --pattern=any-sentinel \
  --principal=arn:aws:iam::123456789012:root
```

### Apply to Role

```bash
aws iam update-assume-role-policy \
  --role-name ProductionRole \
  --policy-document file://trust-policy.json
```

### Verify Enforcement

```bash
sentinel enforce plan --role=arn:aws:iam::123456789012:role/ProductionRole
```

See [Enforcement Patterns](../ENFORCEMENT.md) for complete documentation.

## Production Checklist

### Infrastructure

- [ ] SSM parameters created for all profiles
- [ ] IAM policies attached to appropriate roles
- [ ] DynamoDB tables created (if using approval/break-glass)
- [ ] Logging directory exists and is writable

### Policies

- [ ] Access policies reviewed and tested
- [ ] Default deny rule present in all policies
- [ ] Approval policy configured (if using approval workflow)
- [ ] Break-glass policy configured (if using break-glass)
- [ ] Rate limit policy configured (if using break-glass)

### Security

- [ ] Trust policies enforced on sensitive roles
- [ ] SSM parameter access restricted to necessary roles
- [ ] DynamoDB access restricted to Sentinel operations
- [ ] Decision logs shipped to centralized logging

### Monitoring

- [ ] CloudWatch alarms on Sentinel errors
- [ ] Alert on break-glass invocations
- [ ] Dashboard for access request metrics
- [ ] Periodic audit of policy changes

### Documentation

- [ ] User guide distributed to team
- [ ] On-call runbook includes break-glass procedures
- [ ] Approver list documented and accessible

## Terraform Example

### SSM Parameters

```hcl
resource "aws_ssm_parameter" "sentinel_policy_dev" {
  name  = "/sentinel/policies/dev"
  type  = "String"
  value = file("${path.module}/policies/dev.yaml")
}

resource "aws_ssm_parameter" "sentinel_policy_prod" {
  name  = "/sentinel/policies/prod"
  type  = "String"
  value = file("${path.module}/policies/prod.yaml")
}
```

### IAM Policy

```hcl
resource "aws_iam_policy" "sentinel_reader" {
  name        = "SentinelPolicyReader"
  description = "Read access to Sentinel policies"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SentinelPolicyRead"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/sentinel/policies/*"
        ]
      }
    ]
  })
}
```

### DynamoDB Table

```hcl
resource "aws_dynamodb_table" "sentinel_requests" {
  name         = "sentinel-requests"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "S"
  }

  global_secondary_index {
    name            = "gsi1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }
}
```

## Logging Setup

### File Logging

```bash
# Create log directory
sudo mkdir -p /var/log/sentinel
sudo chown $USER /var/log/sentinel

# Configure in credential_process
credential_process = sentinel credentials --profile prod --policy-parameter /sentinel/policies/prod --log-file /var/log/sentinel/decisions.log
```

### Log Rotation

```
# /etc/logrotate.d/sentinel
/var/log/sentinel/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 $USER $USER
}
```

### CloudWatch Logs

Ship logs to CloudWatch for centralized analysis:

```bash
# Install CloudWatch agent
# Configure to watch /var/log/sentinel/decisions.log
```

## Related Documentation

- [Bootstrap Guide](../BOOTSTRAP.md) - Detailed SSM bootstrap documentation
- [Enforcement Patterns](../ENFORCEMENT.md) - Trust policies and SCPs
- [CloudTrail Correlation](../CLOUDTRAIL.md) - Audit log integration
- [Assurance Guide](../ASSURANCE.md) - Verification and monitoring
