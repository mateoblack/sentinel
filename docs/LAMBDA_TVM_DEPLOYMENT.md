# Lambda TVM Deployment Guide

This guide covers deploying the Sentinel Lambda Token Vending Machine (TVM) with AWS API Gateway HTTP API.

## Overview

The Lambda TVM moves credential vending to server-side infrastructure. Protected roles trust ONLY the Lambda execution role, preventing clients from bypassing policy enforcement.

**Architecture:**
```
+--------------+     SigV4      +--------------+     AssumeRole    +--------------+
|   Client     | -------------> |  API Gateway | ----------------> |  Lambda TVM  |
|  (SDK/CLI)   |                |  (IAM Auth)  |                   |              |
+--------------+                +--------------+                   +------+-------+
                                                                          |
                                                                          | AssumeRole
                                                                          | w/ SourceIdentity
                                                                          v
                                                                   +------+-------+
                                                                   |  Protected   |
                                                                   |    Role      |
                                                                   +--------------+
```

## Prerequisites

- AWS account with permissions to create Lambda, API Gateway, and IAM resources
- Sentinel Lambda binary (`make lambda-tvm`)
- SSM parameters for Sentinel policies (from `sentinel bootstrap`)

## Step 1: Create Lambda Function

### Build the Lambda binary

```bash
# From sentinel source directory
make lambda-tvm

# Creates: bin/lambda-tvm-linux-amd64.zip
```

### Create Lambda function

```bash
# Create execution role first (see IAM section below)
aws lambda create-function \
  --function-name sentinel-tvm \
  --runtime provided.al2023 \
  --handler bootstrap \
  --architecture x86_64 \
  --role arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole \
  --zip-file fileb://bin/lambda-tvm-linux-amd64.zip \
  --timeout 30 \
  --memory-size 256 \
  --environment "Variables={
    SENTINEL_POLICY_PARAMETER=/sentinel/policies/production,
    SENTINEL_SESSION_TABLE=sentinel-sessions,
    SENTINEL_APPROVAL_TABLE=sentinel-approvals,
    SENTINEL_BREAKGLASS_TABLE=sentinel-breakglass
  }"
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SENTINEL_POLICY_PARAMETER` | Yes | SSM parameter path for the profile policy |
| `SENTINEL_POLICY_ROOT` | No | SSM path root for profile discovery (auto-derived if not set) |
| `SENTINEL_SESSION_TABLE` | No | DynamoDB table for session tracking |
| `SENTINEL_APPROVAL_TABLE` | No | DynamoDB table for approval workflows |
| `SENTINEL_BREAKGLASS_TABLE` | No | DynamoDB table for break-glass events |

## Step 2: Create API Gateway HTTP API

### Create HTTP API with IAM authorization

```bash
# Create API
aws apigatewayv2 create-api \
  --name sentinel-tvm \
  --protocol-type HTTP \
  --description "Sentinel Token Vending Machine"

# Note the ApiId from response
API_ID=<api-id>

# Create integration with Lambda
aws apigatewayv2 create-integration \
  --api-id $API_ID \
  --integration-type AWS_PROXY \
  --integration-uri arn:aws:lambda:REGION:ACCOUNT:function:sentinel-tvm \
  --payload-format-version 2.0

# Note the IntegrationId
INTEGRATION_ID=<integration-id>

# Create root route for credential vending (IAM auth)
aws apigatewayv2 create-route \
  --api-id $API_ID \
  --route-key "GET /" \
  --authorization-type AWS_IAM \
  --target integrations/$INTEGRATION_ID

# Create POST route for credential vending
aws apigatewayv2 create-route \
  --api-id $API_ID \
  --route-key "POST /" \
  --authorization-type AWS_IAM \
  --target integrations/$INTEGRATION_ID

# Create profiles route for discovery
aws apigatewayv2 create-route \
  --api-id $API_ID \
  --route-key "GET /profiles" \
  --authorization-type AWS_IAM \
  --target integrations/$INTEGRATION_ID

# Create default stage
aws apigatewayv2 create-stage \
  --api-id $API_ID \
  --stage-name '$default' \
  --auto-deploy
```

### Grant API Gateway permission to invoke Lambda

```bash
aws lambda add-permission \
  --function-name sentinel-tvm \
  --statement-id apigateway-invoke \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:REGION:ACCOUNT:$API_ID/*"
```

## Step 3: IAM Configuration

### Lambda Execution Role

The Lambda execution role needs permission to:
- Assume protected roles (with SourceIdentity)
- Read policies from SSM
- Access DynamoDB tables (if configured)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeProtectedRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::ACCOUNT:role/SentinelProtected-*"
      ],
      "Condition": {
        "StringLike": {
          "sts:SourceIdentity": "sentinel:*"
        }
      }
    },
    {
      "Sid": "ReadPolicies",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParametersByPath"
      ],
      "Resource": "arn:aws:ssm:REGION:ACCOUNT:parameter/sentinel/policies/*"
    },
    {
      "Sid": "SessionTracking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/sentinel-sessions",
        "arn:aws:dynamodb:REGION:ACCOUNT:table/sentinel-sessions/index/*"
      ]
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:REGION:ACCOUNT:*"
    }
  ]
}
```

### Protected Role Trust Policy

Protected roles MUST trust ONLY the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/SentinelTVMExecutionRole"
      },
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

**Critical:** Do NOT trust other principals. This ensures clients cannot bypass TVM.

### Client IAM Policy

Clients need permission to invoke the API Gateway endpoint:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeTVM",
      "Effect": "Allow",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:REGION:ACCOUNT:API_ID/*"
    }
  ]
}
```

## Step 4: Resource Policy (Optional)

Restrict API Gateway access to specific VPC or IP ranges:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:REGION:ACCOUNT:API_ID/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]
        }
      }
    }
  ]
}
```

For VPC-only access, use VPC endpoint:

```bash
# Create VPC endpoint for API Gateway
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxx \
  --service-name com.amazonaws.REGION.execute-api \
  --vpc-endpoint-type Interface \
  --subnet-ids subnet-xxx \
  --security-group-ids sg-xxx
```

## Step 5: Lambda Authorizer for Instant Revocation

For sensitive downstream APIs that need instant session revocation:

### Deploy the authorizer Lambda

```bash
# Build authorizer (same binary, different entry point)
# Or use the TVM binary with authorizer mode

aws lambda create-function \
  --function-name sentinel-authorizer \
  --runtime provided.al2023 \
  --handler bootstrap \
  --architecture x86_64 \
  --role arn:aws:iam::ACCOUNT:role/SentinelAuthorizerRole \
  --zip-file fileb://bin/lambda-authorizer-linux-amd64.zip \
  --timeout 5 \
  --memory-size 128 \
  --environment "Variables={SENTINEL_SESSION_TABLE=sentinel-sessions}"
```

### Attach authorizer to downstream API

```bash
# Create authorizer
aws apigatewayv2 create-authorizer \
  --api-id $DOWNSTREAM_API_ID \
  --authorizer-type REQUEST \
  --authorizer-uri arn:aws:lambda:REGION:ACCOUNT:function:sentinel-authorizer \
  --identity-source '$request.header.X-Sentinel-Session-ID' \
  --name sentinel-session-authorizer

# Attach to route
aws apigatewayv2 update-route \
  --api-id $DOWNSTREAM_API_ID \
  --route-id $ROUTE_ID \
  --authorizer-id $AUTHORIZER_ID \
  --authorization-type CUSTOM
```

### Client usage

Clients pass the session ID in requests:

```bash
# With header
curl -H "X-Sentinel-Session-ID: session-xxx" https://api.example.com/sensitive

# With query parameter
curl "https://api.example.com/sensitive?sentinel_session_id=session-xxx"
```

## API Endpoints

### GET / - Credential Vending

Request credentials for a profile:

```bash
# Using AWS CLI with SigV4
aws lambda invoke \
  --function-name sentinel-tvm \
  --payload '{"profile":"production"}' \
  response.json

# Using curl with AWS credentials
curl -X GET \
  -H "X-Amz-Security-Token: $AWS_SESSION_TOKEN" \
  "https://API_ID.execute-api.REGION.amazonaws.com/?profile=production"
```

**Parameters:**
- `profile` (required): Target profile name
- `duration` (optional): Session duration in seconds (900-43200)

**Response:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-01-25T14:30:00Z"
}
```

### GET /profiles - Profile Discovery

List available profiles:

```bash
curl -X GET \
  "https://API_ID.execute-api.REGION.amazonaws.com/profiles"
```

**Response:**
```json
{
  "profiles": [
    {"name": "dev", "policy_path": "/sentinel/policies/dev"},
    {"name": "production", "policy_path": "/sentinel/policies/production"}
  ],
  "root": "/sentinel/policies"
}
```

## Error Responses

| Code | Error | Description |
|------|-------|-------------|
| 400 | MISSING_PROFILE | Profile parameter not provided |
| 400 | INVALID_DURATION | Duration outside valid range |
| 403 | IAM_AUTH_REQUIRED | Request not signed with SigV4 |
| 403 | POLICY_DENY | Sentinel policy denied access |
| 403 | SESSION_REVOKED | Session has been revoked |
| 404 | NOT_FOUND | Unknown API path |
| 500 | CREDENTIAL_ERROR | Failed to assume role |

## Monitoring

### CloudWatch Logs

Lambda logs decision entries in JSON Lines format:

```json
{"timestamp":"2026-01-25T12:00:00Z","user":"alice","profile":"production","effect":"allow","source_identity":"sentinel:alice:abc123"}
```

### CloudWatch Metrics

Monitor these metrics:
- `Invocations` - Total requests
- `Errors` - Failed requests
- `Duration` - Latency (target: <200ms p99)
- `ConcurrentExecutions` - Concurrent Lambda instances

### Alarms

Set up alarms for:
- Error rate > 1%
- P99 latency > 500ms
- Concurrent executions near limit

## Security Best Practices

1. **Trust boundary**: Protected roles trust ONLY Lambda execution role
2. **Resource policy**: Restrict API Gateway to VPC/IP ranges
3. **Minimal permissions**: Lambda execution role has least privilege
4. **Session tracking**: Enable for audit trail and revocation
5. **CloudWatch logging**: Enable for security monitoring
6. **VPC deployment**: Consider VPC Lambda for network isolation

## Troubleshooting

### "IAM_AUTH_REQUIRED" error

Ensure request is signed with SigV4:
```bash
# Use AWS CLI for automatic signing
aws apigatewayv2 invoke-api ...
```

### "POLICY_DENY" error

Check Sentinel policy allows the user/time/conditions:
```bash
sentinel credentials --profile production --verbose
```

### "CREDENTIAL_ERROR" error

Verify Lambda execution role can assume the target role:
```bash
aws iam get-role --role-name TargetRole
# Check trust policy includes Lambda execution role
```
