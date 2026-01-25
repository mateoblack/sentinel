# Sentinel TVM Terraform Module

Terraform module for deploying the Sentinel Token Vending Machine (TVM) with AWS Lambda and API Gateway HTTP API.

## Overview

This module deploys:
- Lambda function running the Sentinel TVM binary
- API Gateway HTTP API with IAM authorization
- Least-privilege IAM execution role
- Routes for credential vending and profile discovery

## Prerequisites

1. **Lambda deployment package**: Build the Lambda binary using `make lambda-tvm`
2. **SSM policies**: Configure Sentinel policies in SSM Parameter Store (use `sentinel bootstrap`)
3. **Protected roles**: Create roles with trust policies for the Lambda execution role

## Usage

### Basic Example

```hcl
module "sentinel_tvm" {
  source = "./terraform/sentinel-tvm"

  lambda_zip_path  = "bin/lambda-tvm-linux-amd64.zip"
  policy_parameter = "/sentinel/policies/production"
}

output "api_endpoint" {
  value = module.sentinel_tvm.api_endpoint
}
```

### Full Configuration

```hcl
module "sentinel_tvm" {
  source = "./terraform/sentinel-tvm"

  function_name    = "sentinel-tvm"
  lambda_zip_path  = "bin/lambda-tvm-linux-amd64.zip"
  policy_parameter = "/sentinel/policies/production"
  policy_root      = "/sentinel/policies"

  # DynamoDB tables for optional features
  session_table    = "sentinel-sessions"
  approval_table   = "sentinel-approvals"
  breakglass_table = "sentinel-breakglass"

  # Lambda configuration
  memory_size = 256
  timeout     = 30

  tags = {
    Environment = "production"
    Service     = "sentinel"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `function_name` | Name of the Lambda function | `string` | `"sentinel-tvm"` | no |
| `lambda_zip_path` | Path to the Lambda deployment package | `string` | n/a | yes |
| `policy_parameter` | SSM parameter path for the Sentinel policy | `string` | n/a | yes |
| `policy_root` | SSM path root for profile discovery | `string` | `""` | no |
| `session_table` | DynamoDB table name for session tracking | `string` | `""` | no |
| `approval_table` | DynamoDB table name for approval workflows | `string` | `""` | no |
| `breakglass_table` | DynamoDB table name for break-glass events | `string` | `""` | no |
| `memory_size` | Lambda memory in MB | `number` | `256` | no |
| `timeout` | Lambda timeout in seconds | `number` | `30` | no |
| `tags` | Tags to apply to all resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `api_endpoint` | API Gateway invoke URL |
| `function_arn` | Lambda function ARN |
| `function_name` | Lambda function name |
| `execution_role_arn` | IAM execution role ARN |
| `api_id` | API Gateway HTTP API ID |
| `api_execution_arn` | API execution ARN (for IAM policies) |

## IAM Permissions

The execution role grants least-privilege access:

| Permission | Purpose |
|------------|---------|
| `sts:AssumeRole` on `SentinelProtected-*` | Assume protected roles with SourceIdentity |
| `ssm:GetParameter`, `ssm:GetParametersByPath` | Read Sentinel policies |
| `dynamodb:PutItem`, `GetItem`, `UpdateItem`, `Query` | Session/approval/breakglass tracking (conditional) |
| `logs:CreateLogGroup`, `CreateLogStream`, `PutLogEvents` | CloudWatch logging |

## Protected Role Setup

Protected roles must trust ONLY the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::ACCOUNT:role/sentinel-tvm-execution-role"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringLike": {
        "sts:SourceIdentity": "sentinel:*"
      }
    }
  }]
}
```

For detailed setup, see [LAMBDA_TVM_DEPLOYMENT.md](../../docs/LAMBDA_TVM_DEPLOYMENT.md).
