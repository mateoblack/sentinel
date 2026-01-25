# Sentinel TVM Terraform Module - Main Resources
# Lambda function and API Gateway HTTP API for Token Vending Machine

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Data sources for ARN construction
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Environment variables for Lambda
  environment_variables = merge(
    {
      SENTINEL_POLICY_PARAMETER = var.policy_parameter
    },
    var.policy_root != "" ? {
      SENTINEL_POLICY_ROOT = var.policy_root
    } : {},
    var.session_table != "" ? {
      SENTINEL_SESSION_TABLE = var.session_table
    } : {},
    var.approval_table != "" ? {
      SENTINEL_APPROVAL_TABLE = var.approval_table
    } : {},
    var.breakglass_table != "" ? {
      SENTINEL_BREAKGLASS_TABLE = var.breakglass_table
    } : {},
    # MDM Provider Configuration
    var.mdm_provider != "" ? {
      SENTINEL_MDM_PROVIDER = var.mdm_provider
    } : {},
    var.mdm_base_url != "" ? {
      SENTINEL_MDM_BASE_URL = var.mdm_base_url
    } : {},
    # Use Secrets Manager (preferred) or env var (deprecated) for MDM API token
    var.mdm_api_secret_arn != "" ? {
      SENTINEL_MDM_API_SECRET_ID = var.mdm_api_secret_arn
    } : var.mdm_api_token != "" ? {
      SENTINEL_MDM_API_TOKEN = var.mdm_api_token
    } : {},
    var.require_device_posture ? {
      SENTINEL_REQUIRE_DEVICE = "true"
    } : {}
  )
}

# Lambda Function
resource "aws_lambda_function" "tvm" {
  function_name = var.function_name
  description   = "Sentinel Token Vending Machine - server-side credential vending with policy evaluation"

  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["x86_64"]

  role        = aws_iam_role.tvm_execution.arn
  memory_size = var.memory_size
  timeout     = var.timeout

  environment {
    variables = local.environment_variables
  }

  tags = var.tags
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "tvm" {
  name          = var.function_name
  protocol_type = "HTTP"
  description   = "Sentinel Token Vending Machine HTTP API"

  tags = var.tags
}

# Lambda Integration
resource "aws_apigatewayv2_integration" "tvm" {
  api_id             = aws_apigatewayv2_api.tvm.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.tvm.invoke_arn
  integration_method = "POST"

  payload_format_version = "2.0"
}

# Route: GET / - Credential vending
resource "aws_apigatewayv2_route" "root_get" {
  api_id    = aws_apigatewayv2_api.tvm.id
  route_key = "GET /"

  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.tvm.id}"
}

# Route: POST / - Credential vending
resource "aws_apigatewayv2_route" "root_post" {
  api_id    = aws_apigatewayv2_api.tvm.id
  route_key = "POST /"

  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.tvm.id}"
}

# Route: GET /profiles - Profile discovery
resource "aws_apigatewayv2_route" "profiles" {
  api_id    = aws_apigatewayv2_api.tvm.id
  route_key = "GET /profiles"

  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.tvm.id}"
}

# Default Stage with auto-deploy
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.tvm.id
  name        = "$default"
  auto_deploy = true

  tags = var.tags
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tvm.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.tvm.execution_arn}/*/*"
}
