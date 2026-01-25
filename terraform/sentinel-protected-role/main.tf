# Sentinel Protected Role Terraform Module
# Creates IAM roles that trust ONLY the Sentinel TVM execution role
#
# This ensures that protected roles cannot be assumed directly by users,
# forcing all credential access through the TVM's policy evaluation.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Protected IAM Role
# Trust policy requires:
# 1. Principal is the TVM execution role
# 2. SourceIdentity starts with "sentinel:" (proves TVM stamped it)
resource "aws_iam_role" "protected" {
  name        = var.role_name
  description = var.description

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "AllowTVMAssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.tvm_execution_role_arn
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringLike = {
            "sts:SourceIdentity" = "sentinel:*"
          }
        }
      }
    ], var.assume_role_policy_additions)
  })

  max_session_duration = var.max_session_duration

  tags = merge(var.tags, {
    ManagedBy       = "terraform"
    SentinelManaged = "true"
  })
}

# Attach managed policies
resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.protected.name
  policy_arn = each.value
}

# Create inline policies
resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies

  name   = each.key
  role   = aws_iam_role.protected.name
  policy = each.value
}
