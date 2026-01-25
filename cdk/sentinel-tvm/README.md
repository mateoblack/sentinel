# Sentinel TVM CDK Stack

AWS CDK TypeScript stack for deploying Sentinel Lambda Token Vending Machine with API Gateway.

## Overview

This stack deploys:
- **Lambda Function**: Sentinel TVM binary (PROVIDED_AL2023 runtime, ARM64)
- **HTTP API Gateway**: IAM-authenticated endpoints for credential vending
- **IAM Execution Role**: Least-privilege permissions for Lambda

## Prerequisites

1. **Node.js** 18+ and npm
2. **AWS CDK CLI**: `npm install -g aws-cdk`
3. **Lambda ZIP**: Built Sentinel TVM binary (`make build-lambda`)
4. **SSM Policies**: Sentinel policies stored in SSM Parameter Store

## Installation

```bash
cd cdk/sentinel-tvm
npm install
```

## Configuration

Configure via CDK context or environment variables:

| Property | Context | Environment | Required | Default |
|----------|---------|-------------|----------|---------|
| Policy parameter | `policyParameter` | `SENTINEL_POLICY_PARAMETER` | Yes | `/sentinel/policies/default` |
| Lambda ZIP path | `lambdaZipPath` | `LAMBDA_ZIP_PATH` | Yes | `../dist/lambda-tvm.zip` |
| Policy root | `policyRoot` | `SENTINEL_POLICY_ROOT` | No | - |
| Session table | `sessionTable` | `SENTINEL_SESSION_TABLE` | No | - |
| Approval table | `approvalTable` | `SENTINEL_APPROVAL_TABLE` | No | - |
| Break-glass table | `breakglassTable` | `SENTINEL_BREAKGLASS_TABLE` | No | - |
| Memory size (MB) | `memorySize` | `LAMBDA_MEMORY_SIZE` | No | 256 |
| Timeout (seconds) | `timeout` | `LAMBDA_TIMEOUT` | No | 30 |

## Deployment

```bash
# Bootstrap CDK (first time only)
cdk bootstrap

# Deploy with context
cdk deploy \
  --context policyParameter=/sentinel/policies/production \
  --context lambdaZipPath=../../dist/lambda-tvm.zip

# Or use environment variables
export SENTINEL_POLICY_PARAMETER=/sentinel/policies/production
export LAMBDA_ZIP_PATH=../../dist/lambda-tvm.zip
cdk deploy
```

## Stack Outputs

After deployment:

| Output | Description |
|--------|-------------|
| `ApiEndpoint` | HTTP API URL for credential requests |
| `ExecutionRoleArn` | Lambda execution role ARN |
| `LambdaFunctionArn` | Lambda function ARN |

## API Routes

All routes require IAM authentication (SigV4 signed requests):

- `GET /` - Request credentials for a profile
- `POST /` - Request credentials (alternative)
- `GET /profiles` - List available profiles

## IAM Permissions

The execution role includes:
- **CloudWatch Logs**: Lambda logging
- **SSM GetParameter**: Policy retrieval from `/sentinel/policies/*`
- **AssumeRole**: Only `SentinelProtected-*` roles with SourceIdentity
- **DynamoDB** (conditional): Session/approval/break-glass tables

## Customization

For production deployments, consider:

1. **VPC Integration**: Add VPC config for private networking
2. **Custom Domain**: Add API Gateway custom domain
3. **Monitoring**: Add CloudWatch alarms and dashboards
4. **Tracing**: Enable X-Ray tracing

```typescript
// Example: Add VPC
const tvmFunction = new lambda.Function(this, 'SentinelTvmFunction', {
  // ... existing config
  vpc: myVpc,
  vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
});
```
