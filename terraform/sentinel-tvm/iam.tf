# Sentinel TVM Terraform Module - IAM Configuration
# Least-privilege execution role for Lambda TVM

# Lambda Execution Role
resource "aws_iam_role" "tvm_execution" {
  name = "${var.function_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# Policy: Assume Protected Roles
# Allows Lambda to assume roles following SentinelProtected-* naming convention
resource "aws_iam_role_policy" "assume_protected_roles" {
  name = "${var.function_name}-assume-protected-roles"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeProtectedRoles"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = [
          "arn:aws:iam::*:role/SentinelProtected-*"
        ]
        Condition = {
          StringLike = {
            "sts:SourceIdentity" = "sentinel:*"
          }
        }
      }
    ]
  })
}

# Policy: Read Sentinel Policies from SSM
resource "aws_iam_role_policy" "read_policies" {
  name = "${var.function_name}-read-policies"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadPolicies"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${local.region}:${local.account_id}:parameter/sentinel/policies/*"
        ]
      }
    ]
  })
}

# Policy: Session Tracking (conditional - only if session_table is specified)
resource "aws_iam_role_policy" "session_tracking" {
  count = var.session_table != "" ? 1 : 0

  name = "${var.function_name}-session-tracking"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SessionTracking"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.session_table}",
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.session_table}/index/*"
        ]
      }
    ]
  })
}

# Policy: Approval Workflows (conditional - only if approval_table is specified)
resource "aws_iam_role_policy" "approval_workflows" {
  count = var.approval_table != "" ? 1 : 0

  name = "${var.function_name}-approval-workflows"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ApprovalWorkflows"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.approval_table}",
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.approval_table}/index/*"
        ]
      }
    ]
  })
}

# Policy: Break-Glass Events (conditional - only if breakglass_table is specified)
resource "aws_iam_role_policy" "breakglass_events" {
  count = var.breakglass_table != "" ? 1 : 0

  name = "${var.function_name}-breakglass-events"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BreakGlassEvents"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.breakglass_table}",
          "arn:aws:dynamodb:${local.region}:${local.account_id}:table/${var.breakglass_table}/index/*"
        ]
      }
    ]
  })
}

# Policy: CloudWatch Logs
resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "${var.function_name}-cloudwatch-logs"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.function_name}",
          "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.function_name}:*"
        ]
      }
    ]
  })
}

# Policy: Secrets Manager Access (conditional - only if mdm_api_secret_arn is specified)
# Required for loading MDM API token from Secrets Manager with caching
resource "aws_iam_role_policy" "secrets_manager" {
  count = var.mdm_api_secret_arn != "" ? 1 : 0

  name = "${var.function_name}-secrets-manager"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = var.mdm_api_secret_arn
      }
    ]
  })
}

# Policy: Policy Signature Verification (conditional - only if policy_signing_key_arn is specified)
# Required for verifying KMS signatures on policies
resource "aws_iam_role_policy" "policy_signing" {
  count = var.policy_signing_key_arn != "" ? 1 : 0

  name = "${var.function_name}-policy-signing"
  role = aws_iam_role.tvm_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPolicySignatureVerification"
        Effect = "Allow"
        Action = [
          "kms:Verify",
          "kms:DescribeKey"
        ]
        Resource = var.policy_signing_key_arn
      }
    ]
  })
}
