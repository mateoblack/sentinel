# Sentinel Protected Role Terraform Module

Creates IAM roles that trust **only** the Sentinel TVM Lambda execution role. This ensures that protected roles cannot be assumed directly by users, forcing all credential access through the TVM's policy evaluation.

## Overview

The trust policy on protected roles requires:
1. The principal is the TVM execution role
2. SourceIdentity starts with `sentinel:*` (proves the TVM stamped it)

This creates a cryptographically-enforced trust boundary - users cannot bypass Sentinel policy by calling `sts:AssumeRole` directly.

## Usage

### Basic Protected Role

```hcl
module "protected_role" {
  source = "./terraform/sentinel-protected-role"

  role_name              = "SentinelProtected-Production"
  tvm_execution_role_arn = module.sentinel_tvm.execution_role_arn

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/ReadOnlyAccess"
  ]

  tags = {
    Environment = "production"
  }
}
```

### With Inline Policies

```hcl
module "protected_role" {
  source = "./terraform/sentinel-protected-role"

  role_name              = "SentinelProtected-DeploymentRole"
  tvm_execution_role_arn = module.sentinel_tvm.execution_role_arn

  inline_policies = {
    deploy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["ecs:UpdateService", "ecs:DescribeServices"]
          Resource = ["arn:aws:ecs:*:*:service/production/*"]
        }
      ]
    })
  }
}
```

### With Additional Trust Policy Statements

```hcl
module "protected_role" {
  source = "./terraform/sentinel-protected-role"

  role_name              = "SentinelProtected-CrossAccount"
  tvm_execution_role_arn = module.sentinel_tvm.execution_role_arn

  # Also allow a secondary TVM in another region
  assume_role_policy_additions = [
    {
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::123456789012:role/sentinel-tvm-us-west-2"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringLike = {
          "sts:SourceIdentity" = "sentinel:*"
        }
      }
    }
  ]
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `role_name` | Name of the protected role (must start with `SentinelProtected-`) | `string` | - | Yes |
| `tvm_execution_role_arn` | ARN of the TVM Lambda execution role | `string` | - | Yes |
| `assume_role_policy_additions` | Additional trust policy statements | `list(object)` | `[]` | No |
| `managed_policy_arns` | Managed policy ARNs to attach | `list(string)` | `[]` | No |
| `inline_policies` | Map of inline policy names to JSON documents | `map(string)` | `{}` | No |
| `tags` | Tags to apply to the role | `map(string)` | `{}` | No |
| `max_session_duration` | Max session duration (3600-43200 seconds) | `number` | `3600` | No |
| `description` | Role description | `string` | Auto-generated | No |

## Outputs

| Name | Description |
|------|-------------|
| `role_arn` | ARN of the protected IAM role |
| `role_name` | Name of the protected IAM role |
| `role_id` | Unique ID of the protected IAM role |

## Security Notes

**Why TVM-only trust?**

Protected roles trust ONLY the Lambda TVM execution role. This creates a hard boundary:

- Users cannot call `sts:AssumeRole` directly for these roles
- The TVM evaluates Sentinel policy before issuing credentials
- SourceIdentity condition ensures credentials came from the TVM
- Combined with SCPs, this creates defense-in-depth

**SourceIdentity enforcement:**

The trust policy requires `sts:SourceIdentity` to match `sentinel:*`. The TVM stamps this identity on every AssumeRole call, containing:
- Username extracted from the caller's AWS identity
- Approval marker (direct access or approval ID)
- Unique request ID for CloudTrail correlation

**Naming convention:**

Role names must start with `SentinelProtected-` to match the TVM's IAM policy. The TVM can only assume roles matching this pattern, preventing misconfiguration.

## Related Modules

- [sentinel-tvm](../sentinel-tvm) - The Lambda TVM that assumes protected roles
